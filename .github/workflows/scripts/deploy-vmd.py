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
  SENTRY_DSN           optional — upserted into /etc/sandbox/vmd.env when set
  BACKUP_BUCKET        optional — the cell's artifact backup bucket. Upserted
                       into vmd.env when set; empty = skip, leaving the
                       host's backup uploader disabled. Staged rollout:
                       staging first, production after the staging soak.
  OTEL_ENVIRONMENT     optional — enables vmd's OTLP backup-metrics exporter
                       by upserting OTEL_METRICS_ENABLED=true and this value
                       as OTEL_ENVIRONMENT into vmd.env. Empty = skip,
                       leaving the host's existing setting alone. The
                       endpoint stays vmd's compiled default
                       (http://localhost:4318, the host-local collector), so
                       only the enable flag and environment ship. The backup
                       alert policies key on these series, including the
                       backup-disabled alert, which cannot fire on absent
                       data — so metrics must be on wherever those alerts
                       are instantiated.
  CONTROL_PLANE_URL    optional — control-plane base URL (e.g.
                       https://api.superserve.ai). Upserted into vmd.env when
                       set. vmd reads it via os.Getenv("CONTROL_PLANE_URL").
  INTERNAL_API_TOKEN   optional — shared control-plane/host auth token, sourced
                       from CI secrets / Secret Manager (never hardcode). When
                       set it is upserted into vmd.env as INTERNAL_API_TOKEN and
                       into /etc/sandbox/secretsproxy.env as DAEMON_AUTH_TOKEN
                       (secretsproxy authenticates callers with the same token
                       the control plane presents). Hosts previously had these
                       provisioned out-of-band via Packer/manual staging.
  DATABASE_URL         optional — this host's Postgres connection string,
                       sourced from CI secrets / Secret Manager (never
                       hardcode). Upserted into vmd.env when set; empty = skip
                       (same convention as CONTROL_PLANE_URL). Without it the
                       reconciler silently falls back to BoltDB-only drift
                       detection and never writes its audit trail — no error,
                       just quiet degradation, so this is easy to miss if the
                       value is ever lost from a host's env file.
  VMD_DNS_REDIRECT_PORT optional — local resolver port vmd REDIRECTs guest :53
                       to via its SANDBOX_DNS_REDIRECT nat chain. Empty = skip
                       (like CONTROL_PLANE_URL). Do NOT default this fleet-wide:
                       this script deploys to every selected host, and a host
                       without an unbound listener on the port would blackhole
                       guest DNS. Set it per host/region to match that host's
                       unbound local_dns_port; upserted into vmd.env so a rebuilt
                       host wires the redirect (unbound answers there but vmd
                       owns the redirect rules).
  VMD_PAUSED_NETWORK_RECLAIM optional — enables pressure-driven release of
                       paused-network inventory. When set, upserted into
                       vmd.env.
  VMD_PAUSED_NETWORK_SLOT_HEADROOM_PERCENT optional — free-slot pressure
                       percentage. When set, upserted into vmd.env.
  VMD_PAUSED_NETWORK_SLOT_HEADROOM_RESERVE optional — free-slot absolute
                       reserve. When set, upserted into vmd.env.
  VMD_PAUSED_NETWORK_SLOT_HEADROOM_HYSTERESIS optional — free-slot release
                       band. When set, upserted into vmd.env.
  VMD_PAUSED_NETWORK_NETNS_THRESHOLD optional — kernel netns pressure
                       threshold. When set, upserted into vmd.env.
  VMD_PAUSED_NETWORK_NETNS_HYSTERESIS optional — kernel netns recovery band.
                       When set, upserted into vmd.env.
  VMD_PAUSED_NETWORK_MOUNT_THRESHOLD optional — kernel mount pressure
                       threshold. When set, upserted into vmd.env.
  VMD_PAUSED_NETWORK_MOUNT_HYSTERESIS optional — kernel mount recovery band.
                       When set, upserted into vmd.env.
  VMD_PAUSED_NETWORK_MIN_WARM_AGE optional — minimum paused age before
                       slot-pressure recycle. When set, upserted into vmd.env.
  VMD_PAUSED_NETWORK_MAX_RECLAIMS optional — controller work budget per pass.
                       When set, upserted into vmd.env.
  VMD_PAUSED_NETWORK_RECLAIM_COOLDOWN optional — minimum time between
                       reclamation passes. When set, upserted into vmd.env.

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
import shlex
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
    "deploy/superserve-vms.service",
    "deploy/vmd-rollback-guard",
    "deploy/superserve-vmd-rollback-guard.conf",
    "deploy/superserve-secretsproxy.service",
    "deploy/firecracker@.service",
    "deploy/firecracker-netns@.service",
    "deploy/sandboxes.slice",
    "deploy/needrestart-superserve.conf",
    "deploy/apt-no-auto-upgrades.conf",
    "deploy/maintenance-watch.sh",
    "deploy/superserve-maintenance-watch.service",
    "deploy/superserve-maintenance-watch.timer",
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
    backup_bucket = os.environ.get("BACKUP_BUCKET", "")
    otel_environment = os.environ.get("OTEL_ENVIRONMENT", "")
    control_plane_url = os.environ.get("CONTROL_PLANE_URL", "")
    internal_api_token = os.environ.get("INTERNAL_API_TOKEN", "")
    database_url = os.environ.get("DATABASE_URL", "")
    # Empty = skip, so a fleet-wide deploy never writes a redirect to a host
    # whose resolver isn't on this port. Set per host/region to match unbound.
    dns_redirect_port = os.environ.get("VMD_DNS_REDIRECT_PORT", "")

    # Pre-quote every value injected into the remote shell script. These come
    # from CI secrets / Secret Manager and must be treated as arbitrary text:
    # shlex.quote makes each safe both as a shell `[ -n ... ]` operand and, as a
    # full "KEY=value" token, as a literal env-file line via `echo`.
    q_sentry = shlex.quote(sentry_dsn)
    q_sentry_line = shlex.quote(f"SENTRY_DSN={sentry_dsn}")
    q_backup = shlex.quote(backup_bucket)
    q_backup_line = shlex.quote(f"BACKUP_BUCKET={backup_bucket}")
    q_otel = shlex.quote(otel_environment)
    q_otel_enabled_line = shlex.quote("OTEL_METRICS_ENABLED=true")
    q_otel_env_line = shlex.quote(f"OTEL_ENVIRONMENT={otel_environment}")
    q_cpu = shlex.quote(control_plane_url)
    q_cpu_line = shlex.quote(f"CONTROL_PLANE_URL={control_plane_url}")
    q_dns = shlex.quote(dns_redirect_port)
    q_dns_line = shlex.quote(f"VMD_DNS_REDIRECT_PORT={dns_redirect_port}")
    q_paused_reclaim = shlex.quote(os.environ.get("VMD_PAUSED_NETWORK_RECLAIM", ""))
    q_paused_reclaim_line = shlex.quote(
        f"VMD_PAUSED_NETWORK_RECLAIM={os.environ.get('VMD_PAUSED_NETWORK_RECLAIM', '')}"
    )
    q_paused_slot_percent = shlex.quote(os.environ.get("VMD_PAUSED_NETWORK_SLOT_HEADROOM_PERCENT", ""))
    q_paused_slot_percent_line = shlex.quote(
        f"VMD_PAUSED_NETWORK_SLOT_HEADROOM_PERCENT={os.environ.get('VMD_PAUSED_NETWORK_SLOT_HEADROOM_PERCENT', '')}"
    )
    q_paused_slot_reserve = shlex.quote(os.environ.get("VMD_PAUSED_NETWORK_SLOT_HEADROOM_RESERVE", ""))
    q_paused_slot_reserve_line = shlex.quote(
        f"VMD_PAUSED_NETWORK_SLOT_HEADROOM_RESERVE={os.environ.get('VMD_PAUSED_NETWORK_SLOT_HEADROOM_RESERVE', '')}"
    )
    q_paused_slot_hysteresis = shlex.quote(os.environ.get("VMD_PAUSED_NETWORK_SLOT_HEADROOM_HYSTERESIS", ""))
    q_paused_slot_hysteresis_line = shlex.quote(
        f"VMD_PAUSED_NETWORK_SLOT_HEADROOM_HYSTERESIS={os.environ.get('VMD_PAUSED_NETWORK_SLOT_HEADROOM_HYSTERESIS', '')}"
    )
    q_paused_netns_threshold = shlex.quote(os.environ.get("VMD_PAUSED_NETWORK_NETNS_THRESHOLD", ""))
    q_paused_netns_threshold_line = shlex.quote(
        f"VMD_PAUSED_NETWORK_NETNS_THRESHOLD={os.environ.get('VMD_PAUSED_NETWORK_NETNS_THRESHOLD', '')}"
    )
    q_paused_netns_hysteresis = shlex.quote(os.environ.get("VMD_PAUSED_NETWORK_NETNS_HYSTERESIS", ""))
    q_paused_netns_hysteresis_line = shlex.quote(
        f"VMD_PAUSED_NETWORK_NETNS_HYSTERESIS={os.environ.get('VMD_PAUSED_NETWORK_NETNS_HYSTERESIS', '')}"
    )
    q_paused_mount_threshold = shlex.quote(os.environ.get("VMD_PAUSED_NETWORK_MOUNT_THRESHOLD", ""))
    q_paused_mount_threshold_line = shlex.quote(
        f"VMD_PAUSED_NETWORK_MOUNT_THRESHOLD={os.environ.get('VMD_PAUSED_NETWORK_MOUNT_THRESHOLD', '')}"
    )
    q_paused_mount_hysteresis = shlex.quote(os.environ.get("VMD_PAUSED_NETWORK_MOUNT_HYSTERESIS", ""))
    q_paused_mount_hysteresis_line = shlex.quote(
        f"VMD_PAUSED_NETWORK_MOUNT_HYSTERESIS={os.environ.get('VMD_PAUSED_NETWORK_MOUNT_HYSTERESIS', '')}"
    )
    q_paused_min_warm_age = shlex.quote(os.environ.get("VMD_PAUSED_NETWORK_MIN_WARM_AGE", ""))
    q_paused_min_warm_age_line = shlex.quote(
        f"VMD_PAUSED_NETWORK_MIN_WARM_AGE={os.environ.get('VMD_PAUSED_NETWORK_MIN_WARM_AGE', '')}"
    )
    q_paused_max_reclaims = shlex.quote(os.environ.get("VMD_PAUSED_NETWORK_MAX_RECLAIMS", ""))
    q_paused_max_reclaims_line = shlex.quote(
        f"VMD_PAUSED_NETWORK_MAX_RECLAIMS={os.environ.get('VMD_PAUSED_NETWORK_MAX_RECLAIMS', '')}"
    )
    q_paused_cooldown = shlex.quote(os.environ.get("VMD_PAUSED_NETWORK_RECLAIM_COOLDOWN", ""))
    q_paused_cooldown_line = shlex.quote(
        f"VMD_PAUSED_NETWORK_RECLAIM_COOLDOWN={os.environ.get('VMD_PAUSED_NETWORK_RECLAIM_COOLDOWN', '')}"
    )
    q_token = shlex.quote(internal_api_token)
    q_iat_line = shlex.quote(f"INTERNAL_API_TOKEN={internal_api_token}")
    q_dat_line = shlex.quote(f"DAEMON_AUTH_TOKEN={internal_api_token}")
    q_db = shlex.quote(database_url)
    q_db_line = shlex.quote(f"DATABASE_URL={database_url}")
    maintenance_webhook = os.environ.get("MAINTENANCE_ALERT_WEBHOOK", "")
    q_webhook = shlex.quote(maintenance_webhook)
    q_webhook_line = shlex.quote(f"MAINTENANCE_ALERT_WEBHOOK={maintenance_webhook}")

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
        q_host_id_line = shlex.quote(f"HOST_ID={name}")

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

            # Rollback safety gate. If the incoming vmd lacks cgroup supervision
            # (a downgrade past direct-spawn), an old binary would mishandle any
            # live or PAUSED cgroup VMs on this host — deleting records/networking
            # under them. Detect the downgrade by grepping the incoming binary for
            # its capability marker (never execute an unknown old binary — it would
            # start the daemon), then certify the host is drained USING THE CURRENT
            # cgroup-aware binary before it is replaced. Gate on the CURRENT binary
            # ALSO having the marker: on a retried downgrade the installed binary is
            # already pre-direct-spawn, and running it as `vmd drain-check` would
            # start the daemon (it doesn't know the subcommand) and hang the deploy
            # — and there is nothing left to drain. Skipped for normal upgrades too.
            if grep -qa cgroup-supervision {install_dir}/vmd 2>/dev/null && ! grep -qa cgroup-supervision {extract_dir}/bin/vmd; then
                echo "incoming vmd lacks cgroup-supervision — verifying host is drained before downgrade"
                sudo systemctl stop superserve-vmd.socket superserve-vmd.service 2>/dev/null || true
                # The capable vmd records its resolved state path in the
                # breadcrumb (arming requires the write), so read that instead
                # of re-parsing env files with systemd's grammar. Empty (a
                # capable host that never armed) = drain-check's own defaults
                # apply; the host-resident start guard backstops either way.
                DC_STATE=$(sudo head -n 1 /var/lib/sandbox/vmd-state-path 2>/dev/null || true)
                set +e
                sudo env VMD_STATE_PATH="$DC_STATE" {install_dir}/vmd drain-check
                DRAIN_RC=$?
                set -e
                if [ "$DRAIN_RC" -ne 0 ]; then
                    echo "ERROR: host is NOT drained of direct-spawn state (drain-check rc=$DRAIN_RC); refusing to downgrade vmd. Drain cgroup VMs first, then retry." >&2
                    sudo systemctl start superserve-vmd.socket || true
                    exit 1
                fi
                echo "host drained — proceeding with downgrade"
            fi

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
            # Upsert the maintenance-watch webhook into its own env file so the
            # watcher never sources vmd's tokens. Empty = skip: the watcher
            # still runs and logs notices to the journal, it just can't page.
            # Written BEFORE the timer is enabled below: an elapsed OnBootSec
            # fires the watcher the moment `enable --now` runs.
            if [ -n {q_webhook} ]; then
                sudo install -d -m 0755 /etc/sandbox
                sudo touch /etc/sandbox/maintenance-watch.env
                sudo chmod 0600 /etc/sandbox/maintenance-watch.env
                sudo sed -i '/^MAINTENANCE_ALERT_WEBHOOK=/d' /etc/sandbox/maintenance-watch.env
                echo {q_webhook_line} | sudo tee -a /etc/sandbox/maintenance-watch.env > /dev/null
            fi
            sudo install -m 0755 {extract_dir}/deploy/maintenance-watch.sh {install_dir}/maintenance-watch
            sudo install -m 0644 {extract_dir}/deploy/superserve-maintenance-watch.service /etc/systemd/system/superserve-maintenance-watch.service
            sudo install -m 0644 {extract_dir}/deploy/superserve-maintenance-watch.timer /etc/systemd/system/superserve-maintenance-watch.timer
            sudo install -m 0644 {extract_dir}/deploy/superserve-vms.service /etc/systemd/system/superserve-vms.service
            # Host-resident rollback guard: survives deploys of older revisions
            # (their scripts predate the drain gate above and never remove
            # drop-ins), so a guard-less script cannot install a pre-cgroup
            # binary over live direct-spawn VMs unnoticed.
            sudo install -m 0755 {extract_dir}/deploy/vmd-rollback-guard {install_dir}/vmd-rollback-guard
            sudo install -d -m 0755 /etc/systemd/system/superserve-vmd.service.d
            sudo install -m 0644 {extract_dir}/deploy/superserve-vmd-rollback-guard.conf /etc/systemd/system/superserve-vmd.service.d/10-rollback-guard.conf
            sudo systemctl daemon-reload
            sudo systemctl enable --quiet superserve-vmd.socket
            sudo systemctl enable --now --quiet superserve-maintenance-watch.timer
            # Delegated cgroup subtree for direct-spawn VMs. Enable for boot, but
            # START only when the delegated root has no child cgroups yet (fresh /
            # first deploy). Once vmd has bootstrapped it, the root is an inner
            # cgroup (keeper/ + VM children, controllers enabled), so systemd
            # cannot place ExecStart back there (cgroup v2 no-internal-process) —
            # a start would either be a redundant no-op (keeper alive) or FAIL and
            # abort the deploy (keeper died with VMs still live). In both cases vmd
            # re-adopts the existing scope; boot-time start is covered by WantedBy.
            sudo systemctl enable --quiet superserve-vms.service
            # A bootstrapped keeper is never restarted (below), so the unit
            # file's TasksMax cannot reach a running service via daemon-reload
            # alone. Apply it to the live unit; the unit file covers boot. The
            # CPU/IO weight is deliberately NOT set here — the reconciler owns
            # it dynamically (100 per live direct VM); a static value here
            # would fight that and, at 10000 on a near-empty population, starve
            # legacy VMs under contention.
            sudo systemctl set-property --runtime superserve-vms.service TasksMax=infinity 2>/dev/null || true
            VMS_CG=$(systemctl show -p ControlGroup --value superserve-vms.service 2>/dev/null || true)
            # -print -quit (find exits itself after the first hit) instead of
            # piping to grep -q: under set -o pipefail, grep closing the pipe
            # early SIGPIPEs find and the pipeline reads non-zero even on a
            # match, which would wrongly try to start a populated keeper.
            VMS_CHILD=""
            if [ -n "$VMS_CG" ]; then
                VMS_CHILD=$(sudo find "/sys/fs/cgroup$VMS_CG" -mindepth 1 -maxdepth 1 -type d -print -quit 2>/dev/null || true)
            fi
            if [ -n "$VMS_CHILD" ]; then
                echo "delegated VM scope already established — not (re)starting the keeper; vmd will adopt it"
            else
                sudo systemctl start superserve-vms.service
            fi

            sudo install -m 0755 {extract_dir}/scripts/fc-cleanup {install_dir}/fc-cleanup

            # Host patching policy: OS packages install only in deliberate
            # maintenance windows, and library-upgrade tooling must never
            # restart the VM or platform units. Re-asserted every deploy so a
            # reimaged or hand-edited host converges back to the policy.
            sudo install -D -m 0644 {extract_dir}/deploy/needrestart-superserve.conf /etc/needrestart/conf.d/50-superserve.conf
            sudo install -D -m 0644 {extract_dir}/deploy/apt-no-auto-upgrades.conf /etc/apt/apt.conf.d/99superserve-no-auto-upgrades
            sudo systemctl disable --now apt-daily-upgrade.timer 2>/dev/null || true

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
                        candidate=$(sudo grep "^BASE_ROOTFS_PATH=" "$env_file" | head -1 | cut -d= -f2) || true
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
            if [ -n {q_sentry} ]; then
                sudo sed -i '/^SENTRY_DSN=/d' /etc/sandbox/vmd.env
                echo {q_sentry_line} | sudo tee -a /etc/sandbox/vmd.env > /dev/null
            fi

            # Upsert BACKUP_BUCKET (the cell's artifact backup bucket).
            # Empty = skip, leaving the uploader disabled on this host.
            if [ -n {q_backup} ]; then
                sudo sed -i '/^BACKUP_BUCKET=/d' /etc/sandbox/vmd.env
                echo {q_backup_line} | sudo tee -a /etc/sandbox/vmd.env > /dev/null
            fi

            # Upsert the OTLP backup-metrics contract: enable flag plus
            # environment label. Empty = skip. The exporter endpoint stays
            # vmd's compiled default (the host-local collector on
            # localhost:4318). The backup alert policies read these series,
            # so hosts they watch must have this set.
            if [ -n {q_otel} ]; then
                sudo sed -i '/^OTEL_METRICS_ENABLED=/d' /etc/sandbox/vmd.env
                sudo sed -i '/^OTEL_ENVIRONMENT=/d' /etc/sandbox/vmd.env
                echo {q_otel_enabled_line} | sudo tee -a /etc/sandbox/vmd.env > /dev/null
                echo {q_otel_env_line} | sudo tee -a /etc/sandbox/vmd.env > /dev/null
            fi

            # Upsert HOST_ID with the instance name. vmd falls back to
            # "default" without it, which breaks reconciler DB scoping,
            # heartbeat identity, and the host_id metric label the backup
            # alert policies filter on. The instance name is the host's
            # identity in the host table and in those filters; on hosts
            # where it was seeded by hand this rewrites the same value.
            sudo sed -i '/^HOST_ID=/d' /etc/sandbox/vmd.env
            echo {q_host_id_line} | sudo tee -a /etc/sandbox/vmd.env > /dev/null

            # Upsert SECRETSPROXY_SOCKET on both env files. The daemon writes
            # its control socket into RuntimeDirectory=/run/secretsproxy under
            # DynamicUser; vmd connects to the same path.
            for env_file in /etc/sandbox/vmd.env /etc/sandbox/secretsproxy.env; do
                if [ -f "$env_file" ]; then
                    sudo sed -i '/^SECRETSPROXY_SOCKET=/d' "$env_file"
                    echo 'SECRETSPROXY_SOCKET=/run/secretsproxy/control.sock' | sudo tee -a "$env_file" > /dev/null
                fi
            done

            # Upsert the control-plane URL. Empty = skip. vmd.env is safe to
            # create; secretsproxy.env is only UPSERTED when it ALREADY exists —
            # never create it here, because a partial file (missing
            # DAEMON_AUTH_TOKEN/DATABASE_URL) makes the daemon exit and fails the
            # health check below. The host bootstrap owns creating that file.
            if [ -n {q_cpu} ]; then
                sudo install -d -m 0755 /etc/sandbox
                sudo touch /etc/sandbox/vmd.env
                sudo sed -i '/^CONTROL_PLANE_URL=/d' /etc/sandbox/vmd.env
                echo {q_cpu_line} | sudo tee -a /etc/sandbox/vmd.env > /dev/null
                if [ -f /etc/sandbox/secretsproxy.env ]; then
                    sudo sed -i '/^CONTROL_PLANE_URL=/d' /etc/sandbox/secretsproxy.env
                    echo {q_cpu_line} | sudo tee -a /etc/sandbox/secretsproxy.env > /dev/null
                fi
            fi

            # Upsert the guest DNS redirect port so vmd rebuilds its
            # SANDBOX_DNS_REDIRECT nat chain on a fresh host. unbound answers on
            # this port; without the env var vmd never redirects guest :53 there
            # and guests bypass the Cloudflare Gateway resolver.
            if [ -n {q_dns} ]; then
                sudo install -d -m 0755 /etc/sandbox
                sudo touch /etc/sandbox/vmd.env
                sudo sed -i '/^VMD_DNS_REDIRECT_PORT=/d' /etc/sandbox/vmd.env
                echo {q_dns_line} | sudo tee -a /etc/sandbox/vmd.env > /dev/null
            fi

            # Upsert the paused-network reclaim policy. These values are
            # supplied by deployment config so the daemon never bakes in host
            # defaults.
            if [ -n {q_paused_reclaim} ]; then
                sudo install -d -m 0755 /etc/sandbox
                sudo touch /etc/sandbox/vmd.env
                sudo sed -i '/^VMD_PAUSED_NETWORK_RECLAIM=/d' /etc/sandbox/vmd.env
                echo {q_paused_reclaim_line} | sudo tee -a /etc/sandbox/vmd.env > /dev/null
            fi
            if [ -n {q_paused_slot_percent} ]; then
                sudo install -d -m 0755 /etc/sandbox
                sudo touch /etc/sandbox/vmd.env
                sudo sed -i '/^VMD_PAUSED_NETWORK_SLOT_HEADROOM_PERCENT=/d' /etc/sandbox/vmd.env
                echo {q_paused_slot_percent_line} | sudo tee -a /etc/sandbox/vmd.env > /dev/null
            fi
            if [ -n {q_paused_slot_reserve} ]; then
                sudo install -d -m 0755 /etc/sandbox
                sudo touch /etc/sandbox/vmd.env
                sudo sed -i '/^VMD_PAUSED_NETWORK_SLOT_HEADROOM_RESERVE=/d' /etc/sandbox/vmd.env
                echo {q_paused_slot_reserve_line} | sudo tee -a /etc/sandbox/vmd.env > /dev/null
            fi
            if [ -n {q_paused_slot_hysteresis} ]; then
                sudo install -d -m 0755 /etc/sandbox
                sudo touch /etc/sandbox/vmd.env
                sudo sed -i '/^VMD_PAUSED_NETWORK_SLOT_HEADROOM_HYSTERESIS=/d' /etc/sandbox/vmd.env
                echo {q_paused_slot_hysteresis_line} | sudo tee -a /etc/sandbox/vmd.env > /dev/null
            fi
            if [ -n {q_paused_netns_threshold} ]; then
                sudo install -d -m 0755 /etc/sandbox
                sudo touch /etc/sandbox/vmd.env
                sudo sed -i '/^VMD_PAUSED_NETWORK_NETNS_THRESHOLD=/d' /etc/sandbox/vmd.env
                echo {q_paused_netns_threshold_line} | sudo tee -a /etc/sandbox/vmd.env > /dev/null
            fi
            if [ -n {q_paused_netns_hysteresis} ]; then
                sudo install -d -m 0755 /etc/sandbox
                sudo touch /etc/sandbox/vmd.env
                sudo sed -i '/^VMD_PAUSED_NETWORK_NETNS_HYSTERESIS=/d' /etc/sandbox/vmd.env
                echo {q_paused_netns_hysteresis_line} | sudo tee -a /etc/sandbox/vmd.env > /dev/null
            fi
            if [ -n {q_paused_mount_threshold} ]; then
                sudo install -d -m 0755 /etc/sandbox
                sudo touch /etc/sandbox/vmd.env
                sudo sed -i '/^VMD_PAUSED_NETWORK_MOUNT_THRESHOLD=/d' /etc/sandbox/vmd.env
                echo {q_paused_mount_threshold_line} | sudo tee -a /etc/sandbox/vmd.env > /dev/null
            fi
            if [ -n {q_paused_mount_hysteresis} ]; then
                sudo install -d -m 0755 /etc/sandbox
                sudo touch /etc/sandbox/vmd.env
                sudo sed -i '/^VMD_PAUSED_NETWORK_MOUNT_HYSTERESIS=/d' /etc/sandbox/vmd.env
                echo {q_paused_mount_hysteresis_line} | sudo tee -a /etc/sandbox/vmd.env > /dev/null
            fi
            if [ -n {q_paused_min_warm_age} ]; then
                sudo install -d -m 0755 /etc/sandbox
                sudo touch /etc/sandbox/vmd.env
                sudo sed -i '/^VMD_PAUSED_NETWORK_MIN_WARM_AGE=/d' /etc/sandbox/vmd.env
                echo {q_paused_min_warm_age_line} | sudo tee -a /etc/sandbox/vmd.env > /dev/null
            fi
            if [ -n {q_paused_max_reclaims} ]; then
                sudo install -d -m 0755 /etc/sandbox
                sudo touch /etc/sandbox/vmd.env
                sudo sed -i '/^VMD_PAUSED_NETWORK_MAX_RECLAIMS=/d' /etc/sandbox/vmd.env
                echo {q_paused_max_reclaims_line} | sudo tee -a /etc/sandbox/vmd.env > /dev/null
            fi
            if [ -n {q_paused_cooldown} ]; then
                sudo install -d -m 0755 /etc/sandbox
                sudo touch /etc/sandbox/vmd.env
                sudo sed -i '/^VMD_PAUSED_NETWORK_RECLAIM_COOLDOWN=/d' /etc/sandbox/vmd.env
                echo {q_paused_cooldown_line} | sudo tee -a /etc/sandbox/vmd.env > /dev/null
            fi

            # Upsert the shared control-plane auth token. vmd reads it as
            # INTERNAL_API_TOKEN; secretsproxy authenticates callers with the
            # same value as DAEMON_AUTH_TOKEN. Sourced from CI secrets / Secret
            # Manager — never hardcoded. Empty = leave existing values alone.
            if [ -n {q_token} ]; then
                sudo install -d -m 0755 /etc/sandbox
                sudo touch /etc/sandbox/vmd.env
                # vmd.env holds the bearer token — keep it root-only.
                sudo chmod 0600 /etc/sandbox/vmd.env
                sudo sed -i '/^INTERNAL_API_TOKEN=/d' /etc/sandbox/vmd.env
                echo {q_iat_line} | sudo tee -a /etc/sandbox/vmd.env > /dev/null
                # Upsert DAEMON_AUTH_TOKEN only into an EXISTING secretsproxy.env;
                # never create it here (same reason as CONTROL_PLANE_URL above).
                if [ -f /etc/sandbox/secretsproxy.env ]; then
                    sudo chmod 0600 /etc/sandbox/secretsproxy.env
                    sudo sed -i '/^DAEMON_AUTH_TOKEN=/d' /etc/sandbox/secretsproxy.env
                    echo {q_dat_line} | sudo tee -a /etc/sandbox/secretsproxy.env > /dev/null
                fi
            fi

            # Upsert this host's DB connection string. Sourced from CI secrets /
            # Secret Manager — never hardcoded. Empty = leave existing value
            # alone: losing this silently degrades the reconciler to
            # BoltDB-only mode (no error, just a quiet fallback), so an empty
            # value here must never overwrite a working one.
            if [ -n {q_db} ]; then
                sudo install -d -m 0755 /etc/sandbox
                sudo touch /etc/sandbox/vmd.env
                sudo chmod 0600 /etc/sandbox/vmd.env
                sudo sed -i '/^DATABASE_URL=/d' /etc/sandbox/vmd.env
                echo {q_db_line} | sudo tee -a /etc/sandbox/vmd.env > /dev/null
                # secretsproxy reads its own DATABASE_URL from its own env file
                # (buildAuditSink fails startup without it, unless
                # SECRETSPROXY_AUDIT_DISABLED=true) — only upsert into an
                # EXISTING file, same reason as CONTROL_PLANE_URL/DAEMON_AUTH_TOKEN
                # above: never create a partial secretsproxy.env here.
                if [ -f /etc/sandbox/secretsproxy.env ]; then
                    sudo chmod 0600 /etc/sandbox/secretsproxy.env
                    sudo sed -i '/^DATABASE_URL=/d' /etc/sandbox/secretsproxy.env
                    echo {q_db_line} | sudo tee -a /etc/sandbox/secretsproxy.env > /dev/null
                fi
            fi

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
