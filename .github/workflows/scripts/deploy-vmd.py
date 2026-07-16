#!/usr/bin/env python3
"""Deploy the vmd, boxd, and template-builder binaries to every compute
instance tagged with the configured label, in parallel.

Env vars:
  GCP_PROJECT          required — project containing vmd hosts
  GCP_REGION           optional — only deploy to instances whose zone is in
                       this region (e.g. us-central1). The prod project holds
                       hosts for more than one cell (us-central1 primary +
                       the us-west2 cell), and the workflow deploys them
                       sequentially, so an unscoped label filter would fold
                       the cell host into the primary fan-out. Empty = no
                       region scoping (previous behavior).
  VMD_LABEL            required — gcloud instances list label filter (e.g. component=vmd)
  VMD_SERVICE          required — systemd unit name for vmd (e.g. superserve-vmd)
  VMD_INSTALL_DIR      required — bin install dir on the host (e.g. /usr/local/bin)
  SHA                  required — commit SHA (only first 8 chars used)

All deploy artifacts (binaries + systemd units + scripts) are packed
into a single tarball and SCP'd once per host. Each gcloud SCP/SSH
opens a fresh IAP tunnel (~10-15s setup), so bundling cuts per-host
deploy time roughly in half.

Binaries are always uploaded. The remote script hash-compares boxd
against the currently-installed copy and only installs + rebuilds the
rootfs when the hash differs, keeping no-op redeploys cheap and
preserving vmd's template cache.
"""

import os
import subprocess
import sys
import textwrap
from concurrent.futures import ThreadPoolExecutor, as_completed


def run_or_die(cmd, context):
    """Run a subprocess, surface stderr on failure. Logs reach the
    GitHub Actions UI directly — no need to inspect the runner.
    GH redacts repo secrets automatically; nothing in our command
    args is sensitive beyond what's already in the workflow YAML.
    """
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        stderr = (r.stderr or "").strip()
        stdout = (r.stdout or "").strip()
        raise RuntimeError(
            f"{context} failed (exit={r.returncode}): {' '.join(cmd[:4])}…\n"
            f"--- stderr ---\n{stderr or '(empty)'}\n"
            f"--- stdout ---\n{stdout or '(empty)'}"
        )
    return r


# Files included in the deploy bundle. Paths are relative to the repo
# root; they're preserved inside the tarball and reused on the host
# after extraction.
BUNDLE_FILES = [
    "bin/vmd",
    "bin/boxd",
    "bin/template-builder",
    "bin/secretsproxy",
    "deploy/superserve-vmd.service",
    "deploy/superserve-vmd.socket",
    "deploy/superserve-secretsproxy.service",
    "deploy/firecracker@.service",
    "deploy/firecracker-netns@.service",
    "deploy/sandboxes.slice",
    "scripts/fc-cleanup",
]


def main() -> int:
    project = os.environ["GCP_PROJECT"]
    region = os.environ.get("GCP_REGION", "")
    label = os.environ.get("VMD_LABEL", "component=vmd")
    service = os.environ.get("VMD_SERVICE", "superserve-vmd")
    install_dir = os.environ.get("VMD_INSTALL_DIR", "/usr/local/bin")
    sha = os.environ["SHA"][:8]
    sentry_dsn = os.environ.get("SENTRY_DSN", "")

    # Build the deploy bundle once. Same artifact ships to every host;
    # building per-host would waste CI runner CPU.
    bundle_local = f"deploy-bundle-{sha}.tar.gz"
    run_or_die(["tar", "czf", bundle_local] + BUNDLE_FILES, "bundle build")
    print(f"Built {bundle_local} ({os.path.getsize(bundle_local)} bytes)")

    result = subprocess.run(
        [
            "gcloud", "compute", "instances", "list",
            f"--project={project}",
            f"--filter=labels.{label} AND status=RUNNING",
            "--format=csv[no-heading](name,zone)",
        ],
        capture_output=True, text=True, check=True,
    )

    instances = [
        {"name": r[0], "zone": r[1]}
        for line in result.stdout.strip().splitlines()
        if line.strip()
        for r in [line.strip().split(",")]
    ]

    # Region scoping is done here rather than in the gcloud filter: matching
    # on the zone basename is unambiguous, while gcloud filter matching
    # against zone URIs is easy to get subtly wrong. Zero matches is a hard
    # failure either way — a deploy that silently skips a host is exactly
    # the drift this script exists to prevent.
    if region:
        instances = [
            inst for inst in instances
            if inst["zone"].split("/")[-1].startswith(f"{region}-")
        ]

    where = f"{project} ({region})" if region else project
    if not instances:
        print(f"No instances with label {label} found in {where}", file=sys.stderr)
        return 1

    print(f"Deploying VMD to {len(instances)} instance(s) in {where}")

    bundle_remote = f"/tmp/deploy-bundle-{sha}.tar.gz"
    extract_dir = f"/tmp/deploy-{sha}"

    def deploy(inst):
        name, zone = inst["name"], inst["zone"]
        tag = f"{name}/{zone}"

        # Single SCP — one IAP tunnel for the whole bundle.
        run_or_die(
            [
                "gcloud", "compute", "scp", bundle_local, f"{name}:{bundle_remote}",
                f"--zone={zone}", f"--project={project}",
                "--quiet", "--tunnel-through-iap",
            ],
            f"[{tag}] scp bundle",
        )
        print(f"[{tag}] bundle uploaded")

        inject_script = textwrap.dedent(f"""
            set -euo pipefail

            # Extract the deploy bundle into a sha-scoped staging dir so
            # parallel deploys (or aborted retries) don't collide.
            sudo rm -rf {extract_dir}
            mkdir -p {extract_dir}
            tar xzf {bundle_remote} -C {extract_dir}

            # Install vmd + template-builder binaries.
            sudo install -m 0755 {extract_dir}/bin/vmd {install_dir}/vmd
            sudo install -m 0755 {extract_dir}/bin/template-builder {install_dir}/template-builder

            # Install systemd units. A running socket unit keeps its
            # originally-bound fds across daemon-reload + start (start is a
            # no-op when active), so a changed ListenStream/socket option
            # only takes effect if the socket is rebound — flagged here,
            # acted on in the restart block below.
            if sudo cmp -s {extract_dir}/deploy/superserve-vmd.socket /etc/systemd/system/superserve-vmd.socket; then
                SOCKET_CHANGED=0
            else
                SOCKET_CHANGED=1
            fi
            sudo install -m 0644 {extract_dir}/deploy/superserve-vmd.service /etc/systemd/system/superserve-vmd.service
            sudo install -m 0644 {extract_dir}/deploy/superserve-vmd.socket /etc/systemd/system/superserve-vmd.socket
            sudo install -m 0644 {extract_dir}/deploy/firecracker@.service /etc/systemd/system/firecracker@.service
            sudo install -m 0644 {extract_dir}/deploy/firecracker-netns@.service /etc/systemd/system/firecracker-netns@.service
            sudo install -m 0644 {extract_dir}/deploy/sandboxes.slice /etc/systemd/system/sandboxes.slice
            sudo systemctl daemon-reload
            sudo systemctl enable --quiet superserve-vmd.socket

            sudo install -m 0755 {extract_dir}/scripts/fc-cleanup {install_dir}/fc-cleanup

            # Inject boxd + rebuild rootfs only when the new binary differs
            # from what's already installed. `-trimpath -ldflags '-s -w'`
            # makes Go builds reproducible, so hashes only differ when
            # source actually changed. Skipping preserves the rootfs hash,
            # which keeps vmd's template cache valid.
            NEW_HASH=$(sha256sum {extract_dir}/bin/boxd | awk '{{print $1}}')
            CUR_HASH=$(sha256sum {install_dir}/boxd 2>/dev/null | awk '{{print $1}}' || echo none)

            if [ "$NEW_HASH" != "$CUR_HASH" ]; then
                echo "boxd changed ($CUR_HASH -> $NEW_HASH) — installing + rebuilding rootfs"
                sudo install -m 0755 {extract_dir}/bin/boxd {install_dir}/boxd

                ROOTFS=""
                for env_file in /etc/sandbox/vmd.env; do
                    if [ -f "$env_file" ]; then
                        candidate=$(grep "^BASE_ROOTFS_PATH=" "$env_file" | head -1 | cut -d= -f2) || true
                        if [ -n "$candidate" ]; then
                            ROOTFS="$candidate"
                            break
                        fi
                    fi
                done

                if [ -n "$ROOTFS" ] && [ -f "$ROOTFS" ]; then
                    STAGING="$ROOTFS.new.$$"
                    MNT=$(mktemp -d)
                    trap '\''if mountpoint -q "$MNT" 2>/dev/null; then sudo umount "$MNT" || true; fi; rmdir "$MNT" 2>/dev/null || true; sudo rm -f "$STAGING" 2>/dev/null || true'\'' EXIT

                    sudo cp --reflink=auto "$ROOTFS" "$STAGING"
                    sudo mount -o loop "$STAGING" "$MNT"
                    sudo cp {install_dir}/boxd "$MNT/usr/local/bin/boxd"
                    sudo chmod +x "$MNT/usr/local/bin/boxd"
                    sudo umount "$MNT"
                    rmdir "$MNT"
                    sudo mv "$STAGING" "$ROOTFS"
                    trap - EXIT
                    echo "boxd injected into rootfs"
                else
                    echo "WARNING: BASE_ROOTFS_PATH not found; skipping rootfs inject"
                fi
            else
                echo "boxd unchanged ($CUR_HASH) — skipping install + rootfs rebuild"
            fi

            # secretsproxy daemon: hash-compare for idempotent install.
            NEW_SP_HASH=$(sha256sum {extract_dir}/bin/secretsproxy | awk '{{print $1}}')
            CUR_SP_HASH=$(sha256sum {install_dir}/secretsproxy 2>/dev/null | awk '{{print $1}}' || echo none)
            if [ "$NEW_SP_HASH" != "$CUR_SP_HASH" ]; then
                echo "secretsproxy changed ($CUR_SP_HASH -> $NEW_SP_HASH) — installing"
                sudo install -m 0755 {extract_dir}/bin/secretsproxy {install_dir}/secretsproxy
            else
                echo "secretsproxy unchanged ($CUR_SP_HASH) — skipping binary install"
            fi
            sudo install -m 0644 {extract_dir}/deploy/superserve-secretsproxy.service /etc/systemd/system/superserve-secretsproxy.service
            sudo systemctl daemon-reload
            sudo systemctl enable --quiet superserve-secretsproxy.service

            sudo rm -rf {extract_dir}
            rm -f {bundle_remote}

            # Upsert SENTRY_DSN in the vmd env file without touching other vars.
            # Only update when a non-empty value is provided; skip silently otherwise.
            if [ -n '{sentry_dsn}' ]; then
                sudo sed -i '/^SENTRY_DSN=/d' /etc/sandbox/vmd.env
                echo 'SENTRY_DSN={sentry_dsn}' | sudo tee -a /etc/sandbox/vmd.env > /dev/null
            fi

            # Upsert SECRETSPROXY_SOCKET on both env files. The daemon writes
            # its control socket into RuntimeDirectory=/run/secretsproxy under
            # DynamicUser; vmd connects to the same path.
            for env_file in /etc/sandbox/vmd.env /etc/sandbox/secretsproxy.env; do
                if [ -f "$env_file" ]; then
                    sudo sed -i '/^SECRETSPROXY_SOCKET=/d' "$env_file"
                    echo 'SECRETSPROXY_SOCKET=/run/secretsproxy/control.sock' | sudo tee -a "$env_file" > /dev/null
                fi
            done

            # Stop before starting the socket unit: on the first deploy of
            # socket activation the old direct-bound vmd still holds the
            # ports, and a plain restart can bind the socket unit before the
            # old process has released them. Idempotent in steady state.
            sudo systemctl stop {service}
            if [ "$SOCKET_CHANGED" = 1 ]; then
                # Socket unit changed: rebind so the new ListenStream/options
                # apply. Brief refused window, but only on the rare deploy that
                # edits the socket file. Steady state keeps the socket up so
                # connections backlog across the vmd swap instead of refusing.
                sudo systemctl restart superserve-vmd.socket
            else
                sudo systemctl start superserve-vmd.socket
            fi
            sudo systemctl start {service}
            sleep 3
            sudo systemctl is-active --quiet {service} || (
                echo "ERROR: {service} failed to become active after restart" >&2
                sudo systemctl status --no-pager {service} >&2 || true
                sudo journalctl -u {service} --no-pager -n 40 >&2 || true
                exit 1
            )

            # Restart secretsproxy; tolerate missing env file on hosts not
            # yet provisioned (is-active check below is gated on the file).
            sudo systemctl restart superserve-secretsproxy.service || true
            if [ -f /etc/sandbox/secretsproxy.env ]; then
                sleep 2
                sudo systemctl is-active --quiet superserve-secretsproxy.service || (
                    echo "ERROR: superserve-secretsproxy failed to become active after restart" >&2
                    sudo systemctl status --no-pager superserve-secretsproxy.service >&2 || true
                    sudo journalctl -u superserve-secretsproxy.service --no-pager -n 40 >&2 || true
                    exit 1
                )
            else
                echo "/etc/sandbox/secretsproxy.env not present; daemon not started (provision env file to enable)"
            fi
        """)

        r = subprocess.run(
            [
                "gcloud", "compute", "ssh", name,
                f"--zone={zone}", f"--project={project}",
                "--quiet", "--tunnel-through-iap",
                "--command", inject_script,
            ],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            raise RuntimeError(
                f"service not healthy\n"
                f"--- stdout ---\n{r.stdout}\n"
                f"--- stderr ---\n{r.stderr}"
            )
        print(f"[{tag}] active")
        if r.stdout.strip():
            print(f"[{tag}] {r.stdout.strip()}")

    failed = []
    with ThreadPoolExecutor(max_workers=len(instances)) as ex:
        futures = {ex.submit(deploy, inst): inst for inst in instances}
        for f in as_completed(futures):
            inst = futures[f]
            try:
                f.result()
            except Exception as e:
                tag = f"{inst['name']}/{inst['zone']}"
                print(f"[{tag}] FAILED: {e}", file=sys.stderr)
                failed.append(tag)

    if failed:
        print(f'Deploy failed on: {", ".join(failed)}', file=sys.stderr)
        return 1

    print(f"Deployed VMD to {len(instances)} instance(s). sha={sha}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
