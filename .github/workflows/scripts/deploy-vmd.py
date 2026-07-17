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
  VMD_UFFD_ENABLED     optional boolean — upsert into /etc/sandbox/vmd.env
  VMD_RESUME_UFFD      optional boolean — upsert into /etc/sandbox/vmd.env
  VMD_INCREMENTAL_SNAPSHOT
                       optional boolean — upsert into /etc/sandbox/vmd.env
  VMD_SAVED_SNAPSHOT_PREFLIGHT
                       optional boolean — verify mandatory reflinks on the
                       target host before restarting vmd
  SANDBOX_DATA_DISK_DEVICE
                       optional stable /dev/disk/by-id/google-* path. When
                       supplied, prepare persistent XFS storage before the
                       saved-snapshot preflight.
  DATABASE_URL         required for initial data-disk migration/recovery —
                       PostgreSQL URL used to drain and reactivate the host
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
import re
import shutil
import subprocess
import sys
import textwrap
import time
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
    "deploy/sandbox-data-disk.service",
    "scripts/fc-cleanup",
    "scripts/setup-sandbox-data-disk.sh",
]

VMD_BOOLEAN_ENV_VARS = (
    "VMD_UFFD_ENABLED",
    "VMD_RESUME_UFFD",
    "VMD_INCREMENTAL_SNAPSHOT",
)

DATA_DISK_READY = "DATA_DISK_READY"
DATA_DISK_MIGRATION_PREFIX = "DATA_DISK_MIGRATION\t"
DATA_DISK_MIGRATION_PENDING_PREFIX = "DATA_DISK_MIGRATION_PENDING\t"
DATA_DISK_REACTIVATION_PENDING_PREFIX = "DATA_DISK_REACTIVATION_PENDING\t"
HOST_DRAIN_TIMEOUT_SECONDS = 600
HOST_DRAIN_POLL_SECONDS = 2
FIRECRACKER_DRAIN_TIMEOUT_SECONDS = 600
FIRECRACKER_DRAIN_POLL_SECONDS = 2
PG_CONNECT_TIMEOUT_SECONDS = 15
PG_STATEMENT_TIMEOUT_MS = 30000
PSQL_COMMAND_TIMEOUT_SECONDS = 45

HOST_LIFECYCLE_ACTIVITY_SQL = textwrap.dedent("""
    (
        SELECT count(*)::bigint
        FROM sandbox
        WHERE host_id = :'host_id'
          AND destroyed_at IS NULL
          AND (
            status IN ('starting', 'active', 'pausing', 'resuming')
            OR snapshot_operation_id IS NOT NULL
          )
    ) + (
        SELECT count(*)::bigint
        FROM snapshot
        WHERE host_id = :'host_id'
          AND kind = 'saved'
          AND deleted_at IS NULL
          AND status IN ('creating', 'deleting')
    ) + (
        SELECT count(*)::bigint
        FROM template_build
        WHERE vmd_host_id = :'host_id'
          AND status IN ('building', 'snapshotting')
    )
""").strip()

# Read HOST_ID without sourcing the environment file: it is configuration,
# not trusted shell code. A narrow character set also keeps the probe output
# unambiguous; the runner binds the value as a quoted psql variable.
DATA_DISK_MIGRATION_PROBE_SCRIPT = textwrap.dedent(r"""
    set -euo pipefail

    authority_present=0
    pending_reactivation=0
    if sudo test -e /etc/sandbox/data-disk-authoritative; then
        authority_present=1
    fi
    if sudo test -e /etc/sandbox/data-disk-reactivation-pending; then
        pending_reactivation=1
    fi

    if [ "$authority_present" = 1 ] && [ "$pending_reactivation" = 0 ]; then
        printf '%s\n' DATA_DISK_READY
        exit 0
    fi

    host_id=default
    if sudo test -f /etc/sandbox/vmd.env; then
        if ! configured_host_id=$(sudo awk '
            BEGIN { count = 0 }
            {
                line = $0
                sub(/\r$/, "", line)
                if (line !~ /^[[:space:]]*HOST_ID[[:space:]]*=/) next
                count++
                sub(/^[[:space:]]*HOST_ID[[:space:]]*=[[:space:]]*/, "", line)
                sub(/[[:space:]]+$/, "", line)
                if (length(line) >= 2 &&
                    ((substr(line, 1, 1) == "\"" && substr(line, length(line), 1) == "\"") ||
                     (substr(line, 1, 1) == "\047" && substr(line, length(line), 1) == "\047"))) {
                    line = substr(line, 2, length(line) - 2)
                }
                value = line
            }
            END {
                if (count > 1) exit 42
                if (count == 1) print value
            }
        ' /etc/sandbox/vmd.env); then
            echo "ERROR: /etc/sandbox/vmd.env must contain at most one HOST_ID assignment" >&2
            exit 1
        fi
        if [ -n "$configured_host_id" ]; then
            host_id=$configured_host_id
        fi
    fi

    case "$host_id" in
        *[!A-Za-z0-9._:-]*|'')
            echo "ERROR: HOST_ID contains unsupported characters" >&2
            exit 1
            ;;
    esac
    if [ "${#host_id}" -gt 128 ]; then
        echo "ERROR: HOST_ID is longer than 128 characters" >&2
        exit 1
    fi

    if [ "$authority_present" = 1 ]; then
        printf 'DATA_DISK_REACTIVATION_PENDING\t%s\n' "$host_id"
    elif [ "$pending_reactivation" = 1 ]; then
        printf 'DATA_DISK_MIGRATION_PENDING\t%s\n' "$host_id"
    else
        printf 'DATA_DISK_MIGRATION\t%s\n' "$host_id"
    fi
""").strip()

DATA_DISK_SET_PENDING_SCRIPT = textwrap.dedent(r"""
    set -euo pipefail
    sudo install -d -m 0755 /etc/sandbox
    sudo install -m 0600 /dev/null /etc/sandbox/data-disk-reactivation-pending
""").strip()

DATA_DISK_CLEAR_PENDING_SCRIPT = textwrap.dedent(r"""
    set -euo pipefail
    sudo rm -f /etc/sandbox/data-disk-reactivation-pending
""").strip()

FIRECRACKER_DRAIN_PROBE_SCRIPT = textwrap.dedent(f"""
    set -euo pipefail
    deadline=$((SECONDS + {FIRECRACKER_DRAIN_TIMEOUT_SECONDS}))

    while true; do
        if ! units=$(sudo systemctl list-units \\
            --type=service \\
            --state=active,activating,deactivating,reloading \\
            --no-legend \\
            --plain \\
            'firecracker@*.service' | awk '{{print $1}}'); then
            echo "ERROR: failed to inspect Firecracker units" >&2
            exit 1
        fi
        set +e
        processes=$(sudo pgrep -x firecracker)
        pgrep_rc=$?
        set -e
        if [ "$pgrep_rc" -gt 1 ]; then
            echo "ERROR: failed to inspect Firecracker processes" >&2
            exit 1
        fi
        if [ -z "$units" ] && [ -z "$processes" ]; then
            echo "Firecracker runtime is quiescent"
            exit 0
        fi
        if [ "$SECONDS" -ge "$deadline" ]; then
            echo "ERROR: Firecracker runtime did not quiesce" >&2
            if [ -n "$units" ]; then
                echo "Active/transitional systemd units:" >&2
                printf '%s\\n' "$units" | sed 's/^/  /' >&2
            fi
            if [ -n "$processes" ]; then
                echo "Firecracker process IDs:" >&2
                printf '%s\\n' "$processes" | sed 's/^/  /' >&2
            fi
            exit 1
        fi
        sleep {FIRECRACKER_DRAIN_POLL_SECONDS}
    done
""").strip()


def collect_vmd_env_upserts(environ=None):
    """Return validated optional boolean settings for vmd.env.

    An omitted or empty setting is intentionally a no-op, allowing each
    deployment environment to opt in without overwriting another
    environment's host configuration.
    """
    environ = os.environ if environ is None else environ
    upserts = []
    for key in VMD_BOOLEAN_ENV_VARS:
        raw_value = environ.get(key, "")
        if not raw_value:
            continue
        value = raw_value.strip().lower()
        if value not in {"true", "false"}:
            raise ValueError(f"{key} must be true or false, got {raw_value!r}")
        upserts.append((key, value))
    return upserts


def optional_boolean(environ, key):
    raw_value = environ.get(key, "")
    if not raw_value:
        return None
    value = raw_value.strip().lower()
    if value not in {"true", "false"}:
        raise ValueError(f"{key} must be true or false, got {raw_value!r}")
    return value == "true"


def optional_data_disk_device(environ=None):
    """Return a shell-safe stable Google device path when configured."""
    environ = os.environ if environ is None else environ
    value = environ.get("SANDBOX_DATA_DISK_DEVICE", "").strip()
    if not value:
        return ""
    if not re.fullmatch(r"/dev/disk/by-id/google-[A-Za-z0-9._-]+", value):
        raise ValueError(
            "SANDBOX_DATA_DISK_DEVICE must be a stable "
            f"/dev/disk/by-id/google-* path, got {value!r}"
        )
    return value


def parse_data_disk_migration_probe(stdout):
    """Parse the single machine-readable line emitted by the host probe."""
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    matches = [
        line
        for line in lines
        if line == DATA_DISK_READY
        or line.startswith(DATA_DISK_MIGRATION_PREFIX)
        or line.startswith(DATA_DISK_MIGRATION_PENDING_PREFIX)
        or line.startswith(DATA_DISK_REACTIVATION_PENDING_PREFIX)
    ]
    if len(matches) != 1:
        raise RuntimeError(
            "data-disk migration probe returned no unique status line"
        )
    status = matches[0]
    if status == DATA_DISK_READY:
        return "ready", None

    prefixes = (
        (DATA_DISK_MIGRATION_PREFIX, "migration"),
        (DATA_DISK_MIGRATION_PENDING_PREFIX, "migration_pending"),
        (DATA_DISK_REACTIVATION_PENDING_PREFIX, "reactivation_pending"),
    )
    prefix, state = next(
        (prefix, state) for prefix, state in prefixes if status.startswith(prefix)
    )
    host_id = status[len(prefix):]
    if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", host_id):
        raise RuntimeError("data-disk migration probe returned an invalid HOST_ID")
    return state, host_id


def probe_data_disk_migration(inst, project):
    """Return migration/reactivation state and HOST_ID for one instance."""
    name, zone = inst["name"], inst["zone"]
    tag = f"{name}/{zone}"
    result = run_or_die(
        [
            "gcloud", "compute", "ssh", name,
            f"--zone={zone}", f"--project={project}",
            "--quiet", "--tunnel-through-iap",
            "--command", DATA_DISK_MIGRATION_PROBE_SCRIPT,
        ],
        f"[{tag}] data-disk migration probe",
    )
    return parse_data_disk_migration_probe(result.stdout)


def data_disk_migration_plan(instances, project):
    """Build one fail-safe lifecycle plan for all discovered instances.

    The database status drains a logical scheduler host, so a mixed set of
    HOST_ID values must fail before changing DB or VM state. The pending marker
    makes activation retryable after a runner/database failure.
    """
    host_ids = []
    needs_drain = False
    pending_instances = []
    new_pending_instances = []
    migration_instances = []
    with ThreadPoolExecutor(max_workers=len(instances)) as executor:
        futures = {
            executor.submit(probe_data_disk_migration, inst, project): inst
            for inst in instances
        }
        for future in as_completed(futures):
            inst = futures[future]
            state, host_id = future.result()
            if state == "ready":
                continue
            host_ids.append(host_id)
            pending_instances.append(inst)
            if state == "migration":
                new_pending_instances.append(inst)
                migration_instances.append(inst)
                needs_drain = True
            elif state == "migration_pending":
                migration_instances.append(inst)
                needs_drain = True
            elif state != "reactivation_pending":
                raise RuntimeError(f"unknown data-disk migration state: {state}")

    unique_ids = sorted(set(host_ids))
    if len(unique_ids) > 1:
        raise RuntimeError(
            "data-disk migration instances disagree on HOST_ID: "
            + ", ".join(unique_ids)
        )
    def sort_key(inst):
        return inst["name"], inst["zone"]

    return {
        "host_id": unique_ids[0] if unique_ids else None,
        "needs_drain": needs_drain,
        "pending_instances": sorted(pending_instances, key=sort_key),
        "new_pending_instances": sorted(new_pending_instances, key=sort_key),
        "migration_instances": sorted(migration_instances, key=sort_key),
    }


def update_data_disk_pending_markers(instances, project, pending):
    """Atomically create/remove the host-local reactivation retry marker."""
    if not instances:
        return
    command = (
        DATA_DISK_SET_PENDING_SCRIPT if pending else DATA_DISK_CLEAR_PENDING_SCRIPT
    )
    operation = "set" if pending else "clear"

    def update(inst):
        name, zone = inst["name"], inst["zone"]
        tag = f"{name}/{zone}"
        run_or_die(
            [
                "gcloud", "compute", "ssh", name,
                f"--zone={zone}", f"--project={project}",
                "--quiet", "--tunnel-through-iap",
                "--command", command,
            ],
            f"[{tag}] {operation} data-disk reactivation marker",
        )

    with ThreadPoolExecutor(max_workers=len(instances)) as executor:
        futures = [executor.submit(update, inst) for inst in instances]
        for future in as_completed(futures):
            future.result()


def wait_for_firecracker_quiescence(instances, project):
    """Prove each target has no Firecracker systemd units or raw processes."""
    if not instances:
        return

    def wait(inst):
        name, zone = inst["name"], inst["zone"]
        tag = f"{name}/{zone}"
        run_or_die(
            [
                "gcloud", "compute", "ssh", name,
                f"--zone={zone}", f"--project={project}",
                "--quiet", "--tunnel-through-iap",
                "--command", FIRECRACKER_DRAIN_PROBE_SCRIPT,
            ],
            f"[{tag}] wait for Firecracker drain",
        )

    with ThreadPoolExecutor(max_workers=len(instances)) as executor:
        futures = [executor.submit(wait, inst) for inst in instances]
        for future in as_completed(futures):
            future.result()


def require_database_lifecycle(database_url):
    """Validate DB lifecycle prerequisites only when a lifecycle is needed."""
    if not database_url:
        raise ValueError("DATABASE_URL is required for data-disk migration recovery")
    psql = shutil.which("psql")
    if not psql:
        raise RuntimeError(
            "psql is required for data-disk migration recovery but was not found"
        )
    return psql


def run_lifecycle_sql(psql, database_url, host_id, sql, context):
    """Run one lifecycle query without putting DATABASE_URL on the command line."""
    if not database_url:
        raise ValueError("DATABASE_URL is required for database lifecycle operation")
    if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", host_id):
        raise ValueError("invalid HOST_ID for database lifecycle operation")

    child_env = os.environ.copy()
    child_env.pop("DATABASE_URL", None)
    child_env["PGDATABASE"] = database_url
    child_env["PGCONNECT_TIMEOUT"] = str(PG_CONNECT_TIMEOUT_SECONDS)
    bounded_options = (
        f"-c statement_timeout={PG_STATEMENT_TIMEOUT_MS} "
        f"-c lock_timeout={PG_STATEMENT_TIMEOUT_MS}"
    )
    child_env["PGOPTIONS"] = " ".join(
        part for part in (child_env.get("PGOPTIONS", "").strip(), bounded_options)
        if part
    )
    try:
        result = subprocess.run(
            [
                psql,
                "--no-psqlrc",
                "--quiet",
                "--tuples-only",
                "--no-align",
                "--set", "ON_ERROR_STOP=1",
                "--set", f"host_id={host_id}",
            ],
            input=sql,
            env=child_env,
            capture_output=True,
            text=True,
            timeout=PSQL_COMMAND_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout or ""
        stderr = error.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        stdout = stdout.replace(database_url, "[REDACTED]").strip()
        stderr = stderr.replace(database_url, "[REDACTED]").strip()
        raise RuntimeError(
            f"{context} timed out after {PSQL_COMMAND_TIMEOUT_SECONDS}s\n"
            f"--- stderr ---\n{stderr or '(empty)'}\n"
            f"--- stdout ---\n{stdout or '(empty)'}"
        ) from error
    if result.returncode != 0:
        # A malformed libpq URI can be repeated by client diagnostics. Redact
        # the exact secret value before surfacing output in Actions.
        stderr = (result.stderr or "").replace(database_url, "[REDACTED]").strip()
        stdout = (result.stdout or "").replace(database_url, "[REDACTED]").strip()
        raise RuntimeError(
            f"{context} failed (exit={result.returncode})\n"
            f"--- stderr ---\n{stderr or '(empty)'}\n"
            f"--- stdout ---\n{stdout or '(empty)'}"
        )
    return result.stdout.strip()


def set_host_status(psql, database_url, host_id, status):
    """Set one existing host active/draining and prove the row was updated."""
    if status not in {"active", "draining"}:
        raise ValueError(f"unsupported host status: {status!r}")
    if status == "draining":
        status_sql = textwrap.dedent("""
            WITH draining AS (
                UPDATE host AS draining_host
                SET status = 'draining',
                    updated_at = CASE
                        WHEN status = 'draining' THEN updated_at
                        ELSE now()
                    END
                WHERE draining_host.id = :'host_id'
                RETURNING draining_host.id, draining_host.status
            ),
            preserved AS (
                UPDATE sandbox
                SET auto_delete_at = NULL
                WHERE sandbox.host_id IN (SELECT id FROM draining)
                  AND sandbox.destroyed_at IS NULL
                  AND sandbox.auto_delete_at IS NOT NULL
                RETURNING sandbox.id
            )
            SELECT draining.status
            FROM draining
            LEFT JOIN (SELECT count(*) FROM preserved) preserved_count ON true;
        """)
    else:
        status_sql = textwrap.dedent(f"""
            WITH lifecycle_fence AS MATERIALIZED (
                SELECT {HOST_LIFECYCLE_ACTIVITY_SQL} AS remaining
            ),
            updated AS (
                UPDATE host
                SET status = 'active', updated_at = now()
                WHERE id = :'host_id'
                  AND status = 'draining'
                  AND (SELECT remaining FROM lifecycle_fence) = 0
                RETURNING status
            ),
            already_active AS (
                SELECT status
                FROM host
                WHERE id = :'host_id' AND status = 'active'
            )
            SELECT status FROM updated
            UNION ALL
            SELECT status FROM already_active
            WHERE NOT EXISTS (SELECT 1 FROM updated)
            LIMIT 1;
        """)
    updated = run_lifecycle_sql(
        psql,
        database_url,
        host_id,
        status_sql,
        f"set host {host_id} {status}",
    )
    if updated != status:
        raise RuntimeError(
            f"cannot set host {host_id} {status}: host row was not updated"
        )


def count_host_lifecycle_activity(psql, database_url, host_id):
    """Count host-local sandbox lifecycle/storage operations still in flight."""
    raw_count = run_lifecycle_sql(
        psql,
        database_url,
        host_id,
        f"SELECT {HOST_LIFECYCLE_ACTIVITY_SQL};",
        f"count lifecycle activity for host {host_id}",
    )
    if not re.fullmatch(r"[0-9]+", raw_count):
        raise RuntimeError(
            f"invalid lifecycle activity count for host {host_id}: {raw_count!r}"
        )
    return int(raw_count)


def drain_host_via_database(
    psql,
    database_url,
    host_id,
    timeout_seconds=HOST_DRAIN_TIMEOUT_SECONDS,
    poll_seconds=HOST_DRAIN_POLL_SECONDS,
):
    """Fence scheduling, then wait for the API reaper to quiesce the host."""
    set_host_status(psql, database_url, host_id, "draining")
    deadline = time.monotonic() + timeout_seconds
    last_count = None
    while True:
        remaining = count_host_lifecycle_activity(
            psql, database_url, host_id
        )
        if remaining == 0:
            return
        if remaining != last_count:
            print(
                f"Waiting for host {host_id} to drain: "
                f"{remaining} lifecycle/storage operation(s) remain"
            )
            last_count = remaining

        now = time.monotonic()
        if now >= deadline:
            raise RuntimeError(
                f"host {host_id} drain did not converge within "
                f"{timeout_seconds}s; {remaining} lifecycle/storage "
                "operation(s) remain; "
                "host remains draining"
            )
        time.sleep(min(poll_seconds, deadline - now))


def main() -> int:
    project = os.environ["GCP_PROJECT"]
    region = os.environ.get("GCP_REGION", "")
    label = os.environ.get("VMD_LABEL", "component=vmd")
    service = os.environ.get("VMD_SERVICE", "superserve-vmd")
    install_dir = os.environ.get("VMD_INSTALL_DIR", "/usr/local/bin")
    sha = os.environ["SHA"][:8]
    sentry_dsn = os.environ.get("SENTRY_DSN", "")
    vmd_env_upserts = collect_vmd_env_upserts()
    vmd_env_upsert_calls = "\n".join(
        f"upsert_vmd_env {key} {value}" for key, value in vmd_env_upserts
    )
    saved_snapshot_preflight = optional_boolean(
        os.environ, "VMD_SAVED_SNAPSHOT_PREFLIGHT"
    )
    saved_snapshot_preflight_call = (
        "verify_saved_snapshot_storage" if saved_snapshot_preflight else ":"
    )
    data_disk_device = optional_data_disk_device()
    # Do not inherit the database secret into tar/gcloud/SSH subprocesses. It
    # is reintroduced only as PGDATABASE for the narrowly scoped psql calls.
    database_url = os.environ.pop("DATABASE_URL", "")

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

    lifecycle_plan = {
        "host_id": None,
        "needs_drain": False,
        "pending_instances": [],
        "new_pending_instances": [],
        "migration_instances": [],
    }
    lifecycle_psql = None
    if data_disk_device:
        lifecycle_plan = data_disk_migration_plan(instances, project)
        lifecycle_host_id = lifecycle_plan["host_id"]
        if lifecycle_host_id is not None:
            lifecycle_psql = require_database_lifecycle(database_url)
            # Write the retry intent before draining. If this or the drain
            # fails, the next run safely retries the drain while authority is
            # absent. Once authority exists, the same marker retries only the
            # activation and never pauses workloads again.
            update_data_disk_pending_markers(
                lifecycle_plan["new_pending_instances"], project, True
            )
        if lifecycle_plan["needs_drain"]:
            print(
                f"Initial data-disk migration required for host "
                f"{lifecycle_host_id}; requesting graceful drain"
            )
            drain_host_via_database(
                lifecycle_psql, database_url, lifecycle_host_id
            )
            wait_for_firecracker_quiescence(
                lifecycle_plan["migration_instances"], project
            )
            print(f"Host {lifecycle_host_id} drained")
        elif lifecycle_host_id is not None:
            print(
                f"Host {lifecycle_host_id} has a pending reactivation; "
                "retrying it after deployment"
            )

    bundle_remote = f"/tmp/deploy-bundle-{sha}.tar.gz"
    extract_dir = f"/tmp/deploy-{sha}"
    data_disk_setup_call = ":"
    if data_disk_device:
        data_disk_setup_call = textwrap.dedent(f"""
            DATA_DISK_VMD_WAS_ACTIVE=0
            if sudo systemctl is-active --quiet {service}; then
                DATA_DISK_VMD_WAS_ACTIVE=1
            fi

            sudo install -m 0755 {extract_dir}/scripts/setup-sandbox-data-disk.sh /usr/local/bin/setup-sandbox-data-disk.sh
            sudo install -m 0644 {extract_dir}/deploy/sandbox-data-disk.service /etc/systemd/system/sandbox-data-disk.service
            sudo install -d -m 0755 /etc/sandbox
            DATA_DISK_CONFIG_TMP=$(sudo mktemp /etc/sandbox/.data-disk.env.XXXXXX)
            trap 'sudo rm -f "$DATA_DISK_CONFIG_TMP"' EXIT
            printf '%s\\n' 'SANDBOX_DATA_DISK_DEVICE={data_disk_device}' | sudo tee "$DATA_DISK_CONFIG_TMP" > /dev/null
            sudo chown root:root "$DATA_DISK_CONFIG_TMP"
            sudo chmod 0644 "$DATA_DISK_CONFIG_TMP"
            sudo mv -f "$DATA_DISK_CONFIG_TMP" /etc/sandbox/data-disk.env
            DATA_DISK_CONFIG_TMP=
            trap - EXIT

            if ! command -v mkfs.xfs >/dev/null 2>&1 || ! command -v xfs_info >/dev/null 2>&1; then
                if ! command -v apt-get >/dev/null 2>&1; then
                    echo "ERROR: xfsprogs is required for staging snapshot storage" >&2
                    exit 1
                fi
                sudo apt-get update -qq
                sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq xfsprogs
            fi

            sudo systemctl daemon-reload
            sudo systemctl enable --quiet sandbox-data-disk.service
            DATA_DISK_SETUP_RC=0
            DATA_DISK_DIRECT_VERIFY=0
            if sudo systemctl is-active --quiet sandbox-data-disk.service; then
                # Never restart this required oneshot: systemd would propagate
                # its stop to active VMD/Firecracker dependents. The direct
                # verifier atomically reconciles the boot gate but never
                # restarts the storage unit or a healthy VMD.
                DATA_DISK_DIRECT_VERIFY=1
                sudo /usr/local/bin/setup-sandbox-data-disk.sh --verify-only || DATA_DISK_SETUP_RC=$?
            else
                sudo systemctl start sandbox-data-disk.service || DATA_DISK_SETUP_RC=$?
            fi

            if [ "$DATA_DISK_SETUP_RC" != 0 ]; then
                echo "sandbox-data-disk.service diagnostics:" >&2
                sudo systemctl status --no-pager sandbox-data-disk.service >&2 || true
                sudo journalctl -u sandbox-data-disk.service --no-pager -n 160 >&2 || true
                if [ "$DATA_DISK_DIRECT_VERIFY" = 1 ]; then
                    # Defense in depth: the verifier also does this after it
                    # sees the authority fence. Preserve Firecracker guests so
                    # they can reattach after the storage issue is repaired.
                    sudo systemctl stop superserve-vmd.socket {service} || true
                    echo "Data-disk steady-state verification failed; the VMD control plane remains stopped" >&2
                elif [ "$DATA_DISK_VMD_WAS_ACTIVE" = 1 ]; then
                    for attempt in $(seq 1 30); do
                        sudo systemctl is-active --quiet {service} && break
                        sleep 1
                    done
                    if sudo systemctl is-active --quiet {service}; then
                        echo "Data-disk setup failed before commit; {service} recovered on the original storage" >&2
                    else
                        echo "Data-disk setup failed closed after XFS became authoritative; {service} remains stopped" >&2
                    fi
                fi
                exit "$DATA_DISK_SETUP_RC"
            fi

            if [ "$DATA_DISK_VMD_WAS_ACTIVE" = 1 ]; then
                for attempt in $(seq 1 60); do
                    sudo systemctl is-active --quiet {service} && break
                    sleep 1
                done
                sudo systemctl is-active --quiet {service} || (
                    echo "ERROR: {service} did not recover after the data-disk migration" >&2
                    sudo systemctl status --no-pager {service} >&2 || true
                    exit 1
                )
            fi
        """).strip()

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

            # Staging supplies a stable attached-disk path. Production omits
            # it, so this block does not install storage units, config, mounts,
            # or service dependencies there.
            {data_disk_setup_call}

            # Inject boxd + rebuild rootfs only when the new binary differs
            # from what's already installed. `-buildvcs=false -trimpath`
            # removes checkout-specific build metadata, so hashes only differ
            # when source or dependencies changed. Skipping preserves the
            # rootfs hash, which keeps vmd's template cache valid.
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

            # Apply only explicitly supplied, validated boolean settings to
            # vmd.env. Preserve every unrelated line and avoid rewriting an
            # already-canonical setting so repeated deploys are idempotent.
            upsert_vmd_env() {{
                local key="$1"
                local value="$2"
                local env_file=/etc/sandbox/vmd.env
                local current_count

                if ! sudo test -f "$env_file"; then
                    echo "ERROR: $env_file is missing; cannot set $key" >&2
                    return 1
                fi

                current_count=$(sudo grep -c "^${{key}}=" "$env_file" || true)
                if [ "$current_count" -eq 1 ] && sudo grep -qxF "${{key}}=${{value}}" "$env_file"; then
                    return
                fi

                sudo sed -i "/^${{key}}=/d" "$env_file"
                printf '%s=%s\\n' "$key" "$value" | sudo tee -a "$env_file" > /dev/null
            }}

            # Saved snapshots require mandatory CoW clones both from RunDir
            # into SnapshotDir and within SnapshotDir. When requested by the
            # environment, fail the deploy here with filesystem diagnostics
            # instead of leaving the API to return an opaque capability 503.
            verify_saved_snapshot_storage() {{
                local env_file=/etc/sandbox/vmd.env
                local run_dir snapshot_dir run_source probe_dir snapshot_source

                read_vmd_env() {{
                    sudo awk -v key="$1" '
                        index($0, key "=") == 1 {{ value = substr($0, length(key) + 2) }}
                        END {{ print value }}
                    ' "$env_file" | sed -e 's/^"//; s/"$//' -e "s/^'//; s/'$//"
                }}

                run_dir=$(read_vmd_env RUN_DIR)
                snapshot_dir=$(read_vmd_env SNAPSHOT_DIR)
                run_dir=${{run_dir:-/var/lib/sandbox/rundir}}
                snapshot_dir=${{snapshot_dir:-/var/lib/sandbox/snapshots}}

                echo "Saved-snapshot storage preflight:"
                sudo findmnt -T "$run_dir" -no TARGET,SOURCE,FSTYPE,OPTIONS || true
                sudo findmnt -T "$snapshot_dir" -no TARGET,SOURCE,FSTYPE,OPTIONS || true

                if ! sudo test -d "$run_dir" || ! sudo test -d "$snapshot_dir"; then
                    echo "ERROR: saved-snapshot directories are missing (RUN_DIR=$run_dir SNAPSHOT_DIR=$snapshot_dir)" >&2
                    return 1
                fi

                run_source=$(sudo mktemp "$run_dir/.saved-snapshot-preflight.XXXXXX")
                trap "sudo rm -f -- '$run_source'" EXIT
                probe_dir=$(sudo mktemp -d "$snapshot_dir/.saved-snapshot-preflight.XXXXXX")
                trap "sudo rm -f -- '$run_source'; sudo rm -rf -- '$probe_dir'" EXIT

                printf '%s\n' superserve-saved-snapshot-reflink-preflight | sudo tee "$run_source" > /dev/null
                if ! sudo cp --reflink=always --sparse=auto -- "$run_source" "$probe_dir/from-run"; then
                    echo "ERROR: RUN_DIR -> SNAPSHOT_DIR mandatory reflink is unsupported" >&2
                    return 1
                fi

                snapshot_source="$probe_dir/snapshot-source"
                printf '%s\n' superserve-saved-snapshot-reflink-preflight | sudo tee "$snapshot_source" > /dev/null
                if ! sudo cp --reflink=always --sparse=auto -- "$snapshot_source" "$probe_dir/within-snapshot"; then
                    echo "ERROR: SNAPSHOT_DIR mandatory reflink is unsupported" >&2
                    return 1
                fi

                sudo cmp -s "$run_source" "$probe_dir/from-run"
                sudo cmp -s "$snapshot_source" "$probe_dir/within-snapshot"
                sudo rm -f -- "$run_source"
                sudo rm -rf -- "$probe_dir"
                trap - EXIT
                echo "Saved-snapshot mandatory reflink preflight passed"
            }}
            {saved_snapshot_preflight_call}
            {vmd_env_upsert_calls}

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

    lifecycle_host_id = lifecycle_plan["host_id"]
    if lifecycle_host_id is not None:
        print(f"Deployment succeeded; activating host {lifecycle_host_id}")
        set_host_status(
            lifecycle_psql, database_url, lifecycle_host_id, "active"
        )
        update_data_disk_pending_markers(
            lifecycle_plan["pending_instances"], project, False
        )
        print(f"Host {lifecycle_host_id} active")

    print(f"Deployed VMD to {len(instances)} instance(s). sha={sha}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
