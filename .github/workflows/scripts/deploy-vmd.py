#!/usr/bin/env python3
"""Deploy the vmd binary (and optionally boxd + rootfs) to every compute
instance tagged with the configured label, in parallel.

Env vars:
  GCP_PROJECT          required — project containing vmd hosts
  VMD_LABEL            required — gcloud instances list label filter (e.g. component=vmd)
  VMD_SERVICE          required — systemd unit name for vmd (e.g. superserve-vmd)
  VMD_INSTALL_DIR      required — bin install dir on the host (e.g. /usr/local/bin)
  SHA                  required — commit SHA (only first 8 chars used)
  BOXD_CHANGED         optional — "true" to rebuild rootfs with new boxd; anything else skips
"""

import os
import subprocess
import sys
import textwrap
from concurrent.futures import ThreadPoolExecutor, as_completed


def main() -> int:
    project = os.environ["GCP_PROJECT"]
    label = os.environ.get("VMD_LABEL", "component=vmd")
    service = os.environ.get("VMD_SERVICE", "superserve-vmd")
    install_dir = os.environ.get("VMD_INSTALL_DIR", "/usr/local/bin")
    sha = os.environ["SHA"][:8]
    boxd_changed = os.environ.get("BOXD_CHANGED", "true") == "true"

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

    if not instances:
        print(f"No instances with label {label} found in {project}", file=sys.stderr)
        return 1

    print(f"Deploying VMD to {len(instances)} instance(s)")

    def deploy(inst):
        name, zone = inst["name"], inst["zone"]
        tag = f"{name}/{zone}"

        def scp(src, dst):
            subprocess.run(
                [
                    "gcloud", "compute", "scp", src, f"{name}:{dst}",
                    f"--zone={zone}", f"--project={project}",
                    "--quiet", "--tunnel-through-iap",
                ],
                check=True, capture_output=True,
            )

        scp("bin/vmd", f"/tmp/vmd-{sha}")
        if boxd_changed:
            scp("bin/boxd", f"/tmp/boxd-{sha}")

        scp("deploy/superserve-vmd.service", "/tmp/superserve-vmd.service")
        scp("deploy/firecracker@.service", "/tmp/firecracker@.service")
        scp("deploy/firecracker-netns@.service", "/tmp/firecracker-netns@.service")
        scp("deploy/sandboxes.slice", "/tmp/sandboxes.slice")
        scp("scripts/fc-cleanup", "/tmp/fc-cleanup")
        print(f"[{tag}] files uploaded")

        inject_script = textwrap.dedent(f"""
            set -euo pipefail

            sudo mv /tmp/vmd-{sha} {install_dir}/vmd
            sudo chmod +x {install_dir}/vmd

            sudo mv /tmp/superserve-vmd.service /etc/systemd/system/superserve-vmd.service
            sudo mv /tmp/firecracker@.service /etc/systemd/system/firecracker@.service
            sudo mv /tmp/firecracker-netns@.service /etc/systemd/system/firecracker-netns@.service
            sudo mv /tmp/sandboxes.slice /etc/systemd/system/sandboxes.slice
            sudo systemctl daemon-reload

            sudo mv /tmp/fc-cleanup {install_dir}/fc-cleanup
            sudo chmod +x {install_dir}/fc-cleanup

            # Only inject boxd + rebuild rootfs when boxd source changed.
            # Skipping preserves the rootfs hash so vmd's template cache is
            # valid — no cold boot on vmd-only deploys.
            BOXD_SRC_CHANGED={'true' if boxd_changed else 'false'}
            if [ "$BOXD_SRC_CHANGED" = "true" ]; then
                sudo mv /tmp/boxd-{sha} {install_dir}/boxd
                sudo chmod +x {install_dir}/boxd

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
                echo "boxd source unchanged — skipping build and rootfs inject"
            fi

            sudo systemctl restart {service}
            sleep 3
            sudo systemctl is-active --quiet {service} || (
                echo "ERROR: {service} failed to become active after restart" >&2
                sudo systemctl status --no-pager {service} >&2 || true
                sudo journalctl -u {service} --no-pager -n 40 >&2 || true
                exit 1
            )
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
