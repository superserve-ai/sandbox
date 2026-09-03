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
  BACKUP_BACKFILL      optional — "1" enables the paused-sandbox backup
                       backfill sweep (startup + six-hourly re-sweeps).
                       Reconciled, not merely upserted: unset in the
                       workflow removes the line on the next deploy, which
                       is the rollout's documented off switch.
  BACKUP_JOURNAL_PATH  optional — path for the backup uploader's BoltDB
                       journal. Upserted into vmd.env when set; empty = skip,
                       leaving vmd's default (next to RUN_DIR, i.e. on the
                       host's root disk) in place. Set this to a path on
                       /mnt/localssd: the journal is written to continuously
                       while backups drain, and the root disk is small
                       enough that it can fill and stall the uploader.
  BACKUP_STAGING_DIR   optional — path for the backup uploader's staging
                       tree (vmd's default lives inside SNAPSHOT_DIR).
                       Upserted into vmd.env when set; empty = skip. Set
                       this to a path on a dedicated background-data disk
                       (not the local-SSD array): every staged file is
                       read twice before it leaves the host (digest
                       pre-check, then the upload stream), and on the
                       array also serving live VM disk I/O that read
                       traffic contends directly with tenant workloads.
                       Same real-mount precondition as BACKUP_JOURNAL_PATH
                       below — refuses to deploy rather than silently
                       staging onto the root disk.
  BACKUP_UPLOAD_CONCURRENCY
                       optional — number of parallel drain workers in the
                       backup uploader. Upserted into vmd.env when set;
                       empty = skip, leaving vmd's default of one worker.
                       Workers share a single bandwidth limiter, so this
                       raises task throughput (per-task overhead is the
                       bottleneck at high pause rates), never total egress.
                       Staged rollout: staging first, production after the
                       staging soak.
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
import re
import pathlib
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
    "deploy/vmd-wake-floor-guard",
    "deploy/superserve-vmd-wake-floor-guard.conf",
    "deploy/superserve-vmd-start-generation.conf",
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


def check_bundle_parity() -> None:
    """Every deploy/ file the remote script installs must ride in the bundle,
    or the install fails on the host after the binaries were already copied.
    Checked before any host is touched."""
    src = pathlib.Path(__file__).read_text()
    referenced = set(re.findall(r"\{extract_dir\}/(deploy/[A-Za-z0-9_.@-]+)", src))
    missing = sorted(referenced - set(BUNDLE_FILES))
    if missing:
        sys.exit(f"deploy-vmd.py: installed by the remote script but not bundled: {missing}")


def main() -> int:
    check_bundle_parity()
    project = os.environ["GCP_PROJECT"]
    region = os.environ.get("GCP_REGION", "")
    label = os.environ.get("VMD_LABEL", "component=vmd")
    service = os.environ.get("VMD_SERVICE", "superserve-vmd")
    install_dir = os.environ.get("VMD_INSTALL_DIR", "/usr/local/bin")
    sha = os.environ["SHA"][:8]
    sentry_dsn = os.environ.get("SENTRY_DSN", "")
    backup_bucket = os.environ.get("BACKUP_BUCKET", "")
    backup_upload_concurrency = os.environ.get("BACKUP_UPLOAD_CONCURRENCY", "")
    backup_journal_path = os.environ.get("BACKUP_JOURNAL_PATH", "")
    backup_staging_dir = os.environ.get("BACKUP_STAGING_DIR", "")
    backup_backfill = os.environ.get("BACKUP_BACKFILL", "")
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
    q_backup_backfill = shlex.quote(backup_backfill)
    q_backup_backfill_line = shlex.quote(f"BACKUP_BACKFILL={backup_backfill}")
    q_backup_workers = shlex.quote(backup_upload_concurrency)
    q_backup_workers_line = shlex.quote(f"BACKUP_UPLOAD_CONCURRENCY={backup_upload_concurrency}")
    q_backup_journal = shlex.quote(backup_journal_path)
    q_backup_journal_line = shlex.quote(f"BACKUP_JOURNAL_PATH={backup_journal_path}")
    q_backup_staging = shlex.quote(backup_staging_dir)
    q_backup_staging_line = shlex.quote(f"BACKUP_STAGING_DIR={backup_staging_dir}")
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

            # Precondition, checked before any host mutation: if
            # BACKUP_JOURNAL_PATH names a path outside a real mount (the
            # local-SSD array being transiently unmounted, most likely),
            # fail here instead of partway through the stop/restart
            # sequence below. superserve-vmd.socket stays active across the
            # whole deploy by design (zero-downtime — see
            # deploy/superserve-vmd.socket), so aborting mid-sequence would
            # leave {service} stopped with the socket still live: the next
            # connection would socket-activate it against the *persisted*
            # (already-correct) path while the mount is absent, silently
            # opening a root-disk BoltDB there — exactly what this check
            # exists to prevent, just via a path this script doesn't
            # control. Failing before touching the service at all leaves
            # the host exactly as it was (old binary, old config, still
            # serving) instead of stopped and exposed.
            if [ -n {q_backup_journal} ]; then
                # A path below the mount (e.g. /mnt/localssd/journals/backup.db)
                # is valid but its immediate parent may not exist yet on a
                # fresh host and, even once created, is never itself the
                # mountpoint — mountpoint(1) would reject it regardless of
                # whether the array is actually mounted. Walk up to the
                # nearest existing ancestor and compare devices with / instead:
                # same device means nothing real is mounted there yet.
                BJ_ANCESTOR="$(dirname {q_backup_journal})"
                while [ ! -d "$BJ_ANCESTOR" ] && [ "$BJ_ANCESTOR" != "/" ]; do
                    BJ_ANCESTOR="$(dirname "$BJ_ANCESTOR")"
                done
                if [ "$(sudo stat -c %d "$BJ_ANCESTOR")" = "$(sudo stat -c %d /)" ]; then
                    echo "ERROR: $BJ_ANCESTOR is on the root filesystem, not a separate mount; refusing to deploy" >&2
                    exit 1
                fi
                # $BJ_ANCESTOR is confirmed on a real mount, so it's now safe
                # to create the rest of the path down to the parent — vmd
                # opens the journal directly with no mkdir of its own
                # (cmd/vmd/main.go), so a nested path like
                # /mnt/localssd/journals/backup.db needs this directory to
                # exist before vmd (or the migration copy below) can open a
                # file in it. Only set the 0700 mode (vs. the more common
                # 0755 -- only vmd, as root, ever needs to reach this
                # directory) when actually CREATING it: for the common
                # configured value, /mnt/localssd/backup.db, dirname is
                # /mnt/localssd itself -- the shared mount root RUN_DIR and
                # SNAPSHOT_DIR also live under -- and install -d re-chmods
                # existing directories too, so applying it unconditionally
                # would narrow that shared mountpoint's permissions on
                # every single deploy.
                BJ_JOURNAL_DIR="$(dirname {q_backup_journal})"
                if [ ! -d "$BJ_JOURNAL_DIR" ]; then
                    sudo install -d -m 0700 "$BJ_JOURNAL_DIR"
                fi
            fi

            # Same precondition as BACKUP_JOURNAL_PATH above, for the same
            # reason: a transiently unmounted background-data disk must
            # fail the deploy here, not silently stage backup uploads onto
            # the root disk. Unlike the journal (a file path, whose parent
            # is what can be a mountpoint), this setting names a
            # directory that can itself BE the mountpoint — the walk
            # starts at the configured path itself, not its parent, so a
            # value like /mnt/backup-staging is checked directly instead
            # of incorrectly evaluating /mnt. vmd creates the staging
            # directory itself (os.MkdirAll in cmd/vmd/main.go) on every
            # startup regardless of what backs it, so on a fresh host
            # before vmd's first run this still falls back to the nearest
            # existing ancestor, same as the journal check.
            if [ -n {q_backup_staging} ]; then
                BS_ANCESTOR={q_backup_staging}
                while [ ! -d "$BS_ANCESTOR" ] && [ "$BS_ANCESTOR" != "/" ]; do
                    BS_ANCESTOR="$(dirname "$BS_ANCESTOR")"
                done
                if [ "$(sudo stat -c %d "$BS_ANCESTOR")" = "$(sudo stat -c %d /)" ]; then
                    echo "ERROR: $BS_ANCESTOR is on the root filesystem, not a separate mount; refusing to deploy" >&2
                    exit 1
                fi
            fi

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

            # Wake-protocol floor: the daemon writes this evidence the first
            # time it sees an image that owes a wake (restored, paused, or
            # seeded among the templates), and from then on a vmd without the
            # protocol would leave such images stopped. Same check as the
            # host-resident start guard, applied before the binary lands.
            if ! grep -qa wake-protocol-1 {extract_dir}/bin/vmd; then
                SNAPSHOTS=$(sed -n 's/^SNAPSHOT_DIR=//p' /etc/sandbox/vmd.env 2>/dev/null | tail -n 1 | tr -d '"')
                SNAPSHOTS="${{SNAPSHOTS:-/var/lib/sandbox/snapshots}}"
                if [ -e /var/lib/sandbox/wake-protocol-evidence ] || grep -lqs '"workload_frozen":true' "$SNAPSHOTS"/templates/*/*/*.wallclock "$SNAPSHOTS"/templates/*/*.wallclock "$SNAPSHOTS"/*/*.wallclock 2>/dev/null; then
                    echo "ERROR: this host holds images that owe a wake; refusing a vmd without the wake protocol" >&2
                    exit 1
                fi
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
            # Wake-protocol floor: its own executable and drop-in, at paths no
            # earlier deploy script knows, so a rollback that reinstalls that
            # script's guard leaves this one in place. See vmd-wake-floor-guard.
            sudo install -m 0755 {extract_dir}/deploy/vmd-wake-floor-guard {install_dir}/vmd-wake-floor-guard
            sudo install -m 0644 {extract_dir}/deploy/superserve-vmd-wake-floor-guard.conf /etc/systemd/system/superserve-vmd.service.d/30-wake-floor-guard.conf
            # Start-generation stamp: proves receipt succession (see the
            # drop-in's header). A drop-in for the same reason as the guard
            # above — it must survive deploys of revisions that predate it.
            sudo install -m 0644 {extract_dir}/deploy/superserve-vmd-start-generation.conf /etc/systemd/system/superserve-vmd.service.d/20-start-generation.conf
            sudo systemctl daemon-reload
            # daemon-reload alone does not apply [Slice] resource values to
            # an already-active cgroup (same systemd behavior the TasksMax
            # block below works around), and sandboxes.slice is active on
            # any host with VMs. Apply the weights to the live slice;
            # --runtime keeps the unit file the durable source for boot.
            # Keep the values in lockstep with deploy/sandboxes.slice.
            #
            # WARNING: this runtime override survives a rollback to an
            # older script revision (which cannot know to clear it) and
            # lasts until reboot. To clear it by hand:
            #   systemctl set-property --runtime sandboxes.slice CPUWeight=100 IOWeight=100
            sudo systemctl set-property --runtime sandboxes.slice CPUWeight=400 IOWeight=400 2>/dev/null || true
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

            # Upsert BACKUP_UPLOAD_CONCURRENCY (parallel drain workers over
            # one shared bandwidth cap). Empty = skip, leaving vmd's default
            # of a single worker.
            if [ -n {q_backup_workers} ]; then
                sudo sed -i '/^BACKUP_UPLOAD_CONCURRENCY=/d' /etc/sandbox/vmd.env
                echo {q_backup_workers_line} | sudo tee -a /etc/sandbox/vmd.env > /dev/null
            fi

            # Upsert BACKUP_STAGING_DIR (moves the backup uploader's staging
            # tree off whatever disk serves live VM I/O). Empty = leave it
            # unset, on vmd's SNAPSHOT_DIR-based default. Unlike
            # BACKUP_JOURNAL_PATH below, this needs no stop-and-migrate
            # step: vmd creates the new tree itself on startup, staged
            # files already on disk stay reachable through the journal's
            # absolute paths regardless of this value, and vmd's own
            # legacy-staging sweep drains whatever tree was previously
            # live once the config change takes effect.
            #
            # The delete runs unconditionally, outside the empty-value
            # guard: pre-this-var vmd binaries treat BACKUP_STAGING_DIR as
            # the SINGLE staging root (this deploy's split into an
            # always-local pause-path tree plus a configurable
            # uploader-visible tree is new). A rollback that drops this
            # workflow var but leaves a stale line in vmd.env from an
            # earlier deploy would silently move pause-hot-path staging
            # onto the dedicated disk on the old binary — the exact
            # latency regression this split exists to avoid. Unset must
            # actively clear host state, not just skip writing new state.
            #
            # This protects the common rollback shape: the current script
            # redeploys with the workflow var dropped. It does NOT protect
            # a rollback that also reverts deploy-vmd.py itself to a
            # revision before this line existed — that restores the old
            # skip-on-empty behavior along with it, by construction (the
            # fix lives in the file being reverted). No change to this
            # script can close that gap; treat "revert deploy-vmd.py past
            # this commit" as carrying the known cost of a manual
            # `sed -i '/^BACKUP_STAGING_DIR=/d' /etc/sandbox/vmd.env`
            # sweep across affected hosts first.
            sudo sed -i '/^BACKUP_STAGING_DIR=/d' /etc/sandbox/vmd.env
            if [ -n {q_backup_staging} ]; then
                echo {q_backup_staging_line} | sudo tee -a /etc/sandbox/vmd.env > /dev/null
            fi

            # BACKUP_JOURNAL_PATH (moves the backup uploader's BoltDB journal
            # off the root disk onto the local-SSD array) is upserted below,
            # after vmd is stopped, together with migrating any existing
            # journal file to the new location. See that block for why the
            # env write must not happen until the migration is done.

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

            # Set HOST_ID to the instance name only when the env has no
            # value yet. HOST_ID is the host's identity in the host table,
            # so it must never change across deploys: heartbeats and
            # reconciler scoping key on the existing row, and rewriting it
            # to the instance name orphans any host whose row predates the
            # name-matching convention. New hosts get the instance name,
            # which is the convention for every row created since.
            if ! sudo grep -q '^HOST_ID=' /etc/sandbox/vmd.env; then
                echo {q_host_id_line} | sudo tee -a /etc/sandbox/vmd.env > /dev/null
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

            # Reconcile the backfill flag: unlike the skip-when-empty vars,
            # the stale line is ALWAYS removed and re-added only when the
            # workflow sets it. This is a rollout flag with an explicit off
            # step (coverage verified, flag removed), and unsetting it in the
            # workflow must actually disable the sweep on the next deploy
            # rather than requiring a manual host edit.
            sudo touch /etc/sandbox/vmd.env
            sudo sed -i '/^BACKUP_BACKFILL=/d' /etc/sandbox/vmd.env
            if [ -n {q_backup_backfill} ]; then
                echo {q_backup_backfill_line} | sudo tee -a /etc/sandbox/vmd.env > /dev/null
            fi

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

            # Stop here ONLY in the exceptional cases that need the ports
            # released before the socket unit (re)binds: the one-time migration
            # from a direct-bound vmd to socket activation (the socket unit is
            # not yet the active listener, so the old process still owns the
            # ports), or a socket-definition change that forces a rebind. In
            # steady state the socket unit already owns the ports and stays up
            # across the swap — stopping vmd here instead would leave it down
            # for the whole config window with the socket still listening, so a
            # connection arriving in that gap socket-activates a throwaway vmd
            # that the restart below then kills. A normal binary deploy never
            # reaches this stop; the single restart further down does its
            # cutover with connections backlogging on the socket.
            #
            # Stop BOTH units, not just vmd: on a socket-definition change the
            # old socket is still active, so leaving it listening would let a
            # connection socket-activate an interim vmd during the rebind
            # window — the very race this gating exists to remove. Stopping an
            # inactive socket (the migration case) is a harmless no-op. The
            # socket comes back with its new definition at the rebind block
            # below; that rare deploy accepts a brief refused window.
            if ! systemctl is-active --quiet superserve-vmd.socket || [ "$SOCKET_CHANGED" = 1 ]; then
                sudo systemctl stop superserve-vmd.socket {service}
            fi

            # Migrate the backup journal to its new path now that vmd is
            # stopped (the file is closed, safe to move), then upsert
            # BACKUP_JOURNAL_PATH. The env write happens LAST, only after a
            # successful migration: if it happened earlier and the deploy
            # were interrupted before this point, vmd.env would already
            # name the new path while the real journal was still at the
            # old one, so a retry would read old==new, skip the migration
            # as "already done", and the eventual restart would open an
            # empty database. Skip entirely when there's nothing to migrate
            # (old path unchanged, no old file, or a destination already
            # migrated by an earlier deploy) so this is a no-op in steady
            # state.
            if [ -n {q_backup_journal} ]; then
                # This block stops superserve-vmd.socket and {service} itself
                # when the journal path changes (below), and the gated stop
                # above may already have stopped {service} on a socket
                # migration. Either way, arm recovery up front for the whole
                # section so any failure exit between here and the
                # restart/health-check block — the mount recheck just below, or
                # the fallible env write later — cannot leave a unit down with
                # nothing to bring it back. A start on units that were never
                # stopped is a harmless no-op. Disarmed only once {service} is
                # confirmed active again, near the end of this script.
                #
                # Re-verifies the mount at fire time rather than blindly
                # restarting: $BJ_ANCESTOR is set below and stays valid for
                # the rest of this block, so a failure well after the mount
                # check (the env write, say) could still be firing this
                # handler while the mount is fine and a restart is exactly
                # right — but if it's the mount check itself that's failing,
                # or the mount vanished in the meantime, restarting would
                # recreate the very root-backed journal this section exists
                # to prevent. Stop both units instead and leave them down in
                # that case: down but honest beats up and silently wrong.
                # Empty $BJ_ANCESTOR (nothing checked yet) falls through to
                # the normal restart, same as before.
                trap '\''if [ -n "$BJ_ANCESTOR" ] && [ "$(sudo stat -c %d "$BJ_ANCESTOR" 2>/dev/null)" = "$(sudo stat -c %d / 2>/dev/null)" ]; then echo "WARNING: $BJ_ANCESTOR is on the root filesystem; leaving superserve-vmd.socket and {service} stopped rather than restarting onto it" >&2; sudo systemctl stop superserve-vmd.socket {service} 2>/dev/null || true; else sudo systemctl start superserve-vmd.socket {service} 2>/dev/null || true; fi'\'' EXIT
                NEW_BACKUP_JOURNAL_PATH={q_backup_journal}
                # EnvironmentFile= (systemd.exec(5), which is what loads
                # vmd.env) accepts quoted values, and vmd itself receives
                # them unquoted either way. This script never writes
                # BACKUP_JOURNAL_PATH or RUN_DIR quoted, but an existing
                # host could have either set that way by hand — grep|cut
                # below would then keep the quote characters as part of the
                # value, so it would never match the real file on disk and
                # the migration would silently skip a journal that does
                # exist. Strip one matching pair of leading/trailing quotes
                # from each before using it as a path.
                BJ_Q1="'"
                BJ_Q2='"'
                OLD_BACKUP_JOURNAL_PATH=$(sudo grep '^BACKUP_JOURNAL_PATH=' /etc/sandbox/vmd.env 2>/dev/null | head -1 | cut -d= -f2-) || true
                case "$OLD_BACKUP_JOURNAL_PATH" in
                    "$BJ_Q2"*"$BJ_Q2") OLD_BACKUP_JOURNAL_PATH="${{OLD_BACKUP_JOURNAL_PATH#$BJ_Q2}}"; OLD_BACKUP_JOURNAL_PATH="${{OLD_BACKUP_JOURNAL_PATH%$BJ_Q2}}" ;;
                    "$BJ_Q1"*"$BJ_Q1") OLD_BACKUP_JOURNAL_PATH="${{OLD_BACKUP_JOURNAL_PATH#$BJ_Q1}}"; OLD_BACKUP_JOURNAL_PATH="${{OLD_BACKUP_JOURNAL_PATH%$BJ_Q1}}" ;;
                esac
                if [ -z "$OLD_BACKUP_JOURNAL_PATH" ]; then
                    # No override recorded yet: mirror vmd's own default
                    # derivation (filepath.Join(filepath.Dir(cfg.RunDir),
                    # "backup.db") in cmd/vmd/main.go) instead of assuming a
                    # fixed path, since RUN_DIR itself is configurable.
                    RUN_DIR_VALUE=$(sudo grep '^RUN_DIR=' /etc/sandbox/vmd.env 2>/dev/null | head -1 | cut -d= -f2-) || true
                    case "$RUN_DIR_VALUE" in
                        "$BJ_Q2"*"$BJ_Q2") RUN_DIR_VALUE="${{RUN_DIR_VALUE#$BJ_Q2}}"; RUN_DIR_VALUE="${{RUN_DIR_VALUE%$BJ_Q2}}" ;;
                        "$BJ_Q1"*"$BJ_Q1") RUN_DIR_VALUE="${{RUN_DIR_VALUE#$BJ_Q1}}"; RUN_DIR_VALUE="${{RUN_DIR_VALUE%$BJ_Q1}}" ;;
                    esac
                    RUN_DIR_VALUE="${{RUN_DIR_VALUE:-/var/lib/sandbox/rundir}}"
                    # filepath.Dir does not walk up a level when the path
                    # already ends in a separator, it only collapses the
                    # trailing slash(es): filepath.Dir("/a/b/") is "/a/b",
                    # not "/a". Shell dirname always walks up regardless, so
                    # stripping the slash and calling dirname unconditionally
                    # derives the wrong ancestor whenever RUN_DIR itself ends
                    # in a separator. Branch on that case instead.
                    case "$RUN_DIR_VALUE" in
                        */) RUN_DIR_PARENT="$(printf '%s' "$RUN_DIR_VALUE" | sed 's:/*$::')" ;;
                        *)  RUN_DIR_PARENT="$(dirname "$RUN_DIR_VALUE")" ;;
                    esac
                    OLD_BACKUP_JOURNAL_PATH="$RUN_DIR_PARENT/backup.db"
                fi

                # The precondition block at the top of this script already
                # confirmed the mount, but that was before extracting the
                # bundle and installing binaries/units — a long enough
                # window that the array could be transiently unmounted by
                # the time we get here. Check again immediately before
                # mutating anything below, and unconditionally (not just
                # when the path is changing): a steady-state host restarts
                # {service} unconditionally further down too, and if the
                # mount vanished in between, vmd would silently open a
                # root-backed journal at the same configured path, hiding
                # the real one until the SSD is remounted.
                BJ_ANCESTOR="$(dirname "$NEW_BACKUP_JOURNAL_PATH")"
                while [ ! -d "$BJ_ANCESTOR" ] && [ "$BJ_ANCESTOR" != "/" ]; do
                    BJ_ANCESTOR="$(dirname "$BJ_ANCESTOR")"
                done
                if [ "$(sudo stat -c %d "$BJ_ANCESTOR")" = "$(sudo stat -c %d /)" ]; then
                    echo "ERROR: $BJ_ANCESTOR is on the root filesystem, not a separate mount; refusing to deploy" >&2
                    # The recovery trap armed above re-checks $BJ_ANCESTOR
                    # itself before deciding whether to restart, so a plain
                    # exit here correctly leaves both units stopped instead
                    # of restarting vmd onto the root-backed path this check
                    # just caught.
                    exit 1
                fi

                if [ "$OLD_BACKUP_JOURNAL_PATH" != "$NEW_BACKUP_JOURNAL_PATH" ]; then
                    # The socket unit stays up across a normal deploy by design
                    # (connections backlog instead of refusing), so a
                    # connection landing here could socket-activate vmd against
                    # the still-current old path — even when
                    # $OLD_BACKUP_JOURNAL_PATH has no file yet (a host's first
                    # deploy of this setting): vmd would then create one there
                    # on activation, and it becomes an orphan the moment
                    # vmd.env is rewritten below to name the new path, with
                    # nothing left to migrate it. Stop BOTH units here,
                    # whenever the path is changing at all, not just when
                    # there's a file to migrate. Re-enabled by the socket
                    # restart/start block and the {service} restart later in
                    # this script, once vmd.env names the new path. The
                    # recovery trap armed at the top of this block covers a
                    # failure here too.
                    sudo systemctl stop superserve-vmd.socket {service}
                    if [ -f "$OLD_BACKUP_JOURNAL_PATH" ]; then
                        # $OLD_BACKUP_JOURNAL_PATH still present under its
                        # original name is the only signal migration hasn't
                        # completed: completion always ends by renaming it
                        # aside, below. So this always redoes the copy while
                        # the source is present, rather than trusting
                        # NEW_BACKUP_JOURNAL_PATH's mere existence — an
                        # earlier attempt may have been interrupted after
                        # making it visible but before it was synced (see
                        # below), leaving a torn file that a plain existence
                        # check would mistake for a completed migration.
                        #
                        # Old and new live on different filesystems (root
                        # disk vs. the local-SSD array), so a plain `mv` is a
                        # copy-then-delete, not an atomic rename: a kill
                        # mid-copy would otherwise leave a torn file directly
                        # at NEW_BACKUP_JOURNAL_PATH. Copy to a
                        # same-filesystem temp path next to the destination,
                        # then rename — same filesystem makes that rename
                        # atomic.
                        TMP_BACKUP_JOURNAL_PATH="${{NEW_BACKUP_JOURNAL_PATH}}.migrating.$$"
                        sudo rm -f "${{NEW_BACKUP_JOURNAL_PATH}}".migrating.*
                        sudo cp --preserve=mode,ownership "$OLD_BACKUP_JOURNAL_PATH" "$TMP_BACKUP_JOURNAL_PATH"
                        sudo mv "$TMP_BACKUP_JOURNAL_PATH" "$NEW_BACKUP_JOURNAL_PATH"
                        # The copy and the rename onto NEW_BACKUP_JOURNAL_PATH
                        # are only cached writes until this point: root disk
                        # and the local-SSD array are separate devices with
                        # independent write-back queues, so a crash here
                        # could leave the destination's data, or even the
                        # rename's own directory entry, unwritten — on reboot
                        # vmd would find a missing or truncated destination.
                        # Flush everything to disk before going any further,
                        # and before the config below can start pointing at
                        # this destination.
                        sudo sync
                        # The source is intentionally NOT retired here. It's
                        # retired below, only once vmd.env durably names
                        # NEW_BACKUP_JOURNAL_PATH — see that block for why.
                    fi
                fi

                # Publish the override as one atomic swap instead of
                # sed -i (delete) + tee -a (append): those are two separate
                # writes, so a failure or interruption between them (full
                # disk, dropped session) can leave vmd.env with no
                # BACKUP_JOURNAL_PATH line at all. vmd would then fall back
                # to its own default — $OLD_BACKUP_JOURNAL_PATH — and if a
                # migration above already ran, that path is empty or gone,
                # so vmd creates a fresh database there. A later deploy
                # would then read that fresh empty file as "the old journal"
                # and copy it over the real one, destroying it. Build the
                # new content in a temp file on the same filesystem as
                # vmd.env and rename it into place: vmd.env is always either
                # fully the old content or fully the new content, never
                # in between, regardless of when a failure happens.
                sudo touch /etc/sandbox/vmd.env
                BJ_ENV_TMP="/etc/sandbox/vmd.env.tmp.$$"
                sudo rm -f /etc/sandbox/vmd.env.tmp.*
                sudo cp --preserve=mode,ownership /etc/sandbox/vmd.env "$BJ_ENV_TMP"
                sudo sed -i '/^BACKUP_JOURNAL_PATH=/d' "$BJ_ENV_TMP"
                echo {q_backup_journal_line} | sudo tee -a "$BJ_ENV_TMP" > /dev/null
                sudo mv "$BJ_ENV_TMP" /etc/sandbox/vmd.env
                # Sync AFTER the rename, not before: a sync before only
                # covers the temp file's content, not the rename's own
                # directory-entry update, which is a separate write that
                # can still be lost on power loss right after `mv` returns
                # — same reasoning as the journal file's own sync above.
                sudo sync

                if [ "$OLD_BACKUP_JOURNAL_PATH" != "$NEW_BACKUP_JOURNAL_PATH" ] \\
                    && [ -f "$OLD_BACKUP_JOURNAL_PATH" ]; then
                    # vmd.env now durably names NEW_BACKUP_JOURNAL_PATH, so
                    # it's safe to retire the source: nothing will fall back
                    # to looking for it at its original name anymore.
                    # Rename rather than remove: if this script is killed
                    # here, a recoverable file survives instead of an
                    # unlinked inode. Not cleaned up afterward — reclaiming
                    # it safely needs the same "nothing still references it"
                    # guarantee that motivates renaming over deleting it
                    # here, for a single-digit-MB file, not the multi-GB
                    # artifacts that actually filled the root disk.
                    sudo mv "$OLD_BACKUP_JOURNAL_PATH" "${{OLD_BACKUP_JOURNAL_PATH}}.migrated"
                    echo "migrated backup journal: $OLD_BACKUP_JOURNAL_PATH -> $NEW_BACKUP_JOURNAL_PATH"
                fi
            fi
            if [ "$SOCKET_CHANGED" = 1 ]; then
                # Socket unit changed: rebind so the new ListenStream/options
                # apply. Brief refused window, but only on the rare deploy that
                # edits the socket file. Steady state keeps the socket up so
                # connections backlog across the vmd swap instead of refusing.
                sudo systemctl restart superserve-vmd.socket
            else
                sudo systemctl start superserve-vmd.socket
            fi
            # `restart`, not `start`: the socket unit stays active through
            # the whole block above by design (zero-downtime — connections
            # backlog instead of refusing), so a connection arriving during
            # the stop window can already have made systemd reactivate
            # {service} against the pre-migration vmd.env. `start` is a
            # no-op against an already-active unit and would leave that
            # reactivated process running on the old path indefinitely;
            # `restart` guarantees the process running once this script
            # exits is always the one reading the final, fully-migrated
            # config, whether or not a reactivation race occurred.
            sudo systemctl restart {service}
            # Wait for APPLICATION readiness, not is-active: the unit is
            # Type=simple, so "active" only proves the process forked, while vmd
            # answers Unavailable until it logs startup-complete — its real gate,
            # which can lag the fork. Scope the scan to the unit's CURRENT
            # systemd invocation so no prior-boot or crashed-and-replaced ready
            # line counts, and re-confirm that invocation is still current+active
            # when the line is seen. Read journalctl into a var (no pipe) so a
            # match can't SIGPIPE it under pipefail (as with the find -print
            # -quit above). Fail with the recovery trap still armed on timeout.
            READY=0
            for i in $(seq 1 90); do
                INVOCATION=$(systemctl show -p InvocationID --value {service} 2>/dev/null || true)
                # journalctl -g exits nonzero on no match (and prints
                # "-- No entries --" to stdout), so drive the check off its exit
                # status — capturing stdout would read that marker as a false
                # positive. No `|| true`: that would swallow the no-match status.
                if [ -n "$INVOCATION" ] \
                   && sudo journalctl "_SYSTEMD_INVOCATION_ID=$INVOCATION" --quiet -g 'gRPC serving requests' --no-pager >/dev/null 2>&1 \
                   && [ "$(systemctl show -p InvocationID --value {service} 2>/dev/null || true)" = "$INVOCATION" ] \
                   && sudo systemctl is-active --quiet {service}; then
                    READY=1
                    break
                fi
                sleep 1
            done
            if [ "$READY" != 1 ]; then
                echo "ERROR: {service} did not reach application readiness (startupReady) within 90s after restart" >&2
                sudo systemctl status --no-pager {service} >&2 || true
                sudo journalctl -u {service} --no-pager -n 80 >&2 || true
                exit 1
            fi
            # {service} is confirmed serving requests on the final config: disarm
            # the journal-migration recovery trap (a no-op if it was never armed
            # this run). Anything past this point is unrelated to the backup
            # journal and shouldn't restart vmd on failure.
            trap - EXIT

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
