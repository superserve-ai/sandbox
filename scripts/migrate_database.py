"""Run regional migrations with the verified history of each database."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile
import time
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit


ROOT = Path(__file__).resolve().parents[1]
CLI_VERSION = "2.119.0"
COMMAND_TIMEOUT = 60
STARTUP_OPTIONS = "-c transaction_timeout=2s -c lock_timeout=250ms"
EXECUTION_GUARD = """RESET ALL;
DO $$ BEGIN
 IF current_setting('server_version_num')::int < 170000
 OR NOT EXISTS (SELECT FROM pg_settings WHERE name='transaction_timeout'
                AND setting='2000' AND reset_val='2000')
 OR NOT EXISTS (SELECT FROM pg_settings WHERE name='lock_timeout'
                AND setting='250' AND reset_val='250') THEN
  RAISE EXCEPTION 'Migration execution settings are unavailable';
 END IF;
END $$;
"""
PROJECTS = {
    "staging": "rifhalqzxgskwajjgipj",
    "use4": "xompkvadqplatcchfqjq",
    "usw2": "kggutwjaulpridgvkbpl",
}
VERSION = "20261002155220"
NAME = "shared_signup_device_evidence_setup"
AGGREGATE = f"{VERSION}_{NAME}.sql"
SHA256 = "64347e1e9998937dd8d7661a13e9aa9ba180a7b577998fbd4a45124ec70e3331"
SOURCES = {
    "20260925000000_signup_device_evidence.sql": "6a7cda0f8f9f2415a2e6bc80340d38b9905621a3bbadf2a5ecdc49ed7abe61f4",
    "20260925183413_protect_shared_signup_device_evidence.sql": "5c943af765e07bb20c074c77fc0f8760c5a32412f8b4076b495e7c0b0e832e60",
    "20260925190000_promotion_evidence_proxy_role.sql": "6b7f1f84105dbfed7ca529cc604b17c4dc93996b11e666f175f71c41759f9425",
}


class MigrationError(Exception):
    pass


def connection_rejection(database_url, target):
    """Return a fixed category only; connection details must never reach logs."""
    if not database_url:
        return "missing_url"
    try:
        url = urlsplit(database_url)
        project = PROJECTS[target]
        user = unquote(url.username or "")
        params = parse_qsl(url.query, strict_parsing=True, keep_blank_values=True)
        port = url.port
        if url.scheme not in ("postgres", "postgresql"):
            return "unsupported_scheme"
        if not user:
            return "missing_user"
        if url.fragment:
            return "fragment_not_allowed"
        if url.path != "/postgres":
            return "database_mismatch"
        if any(k not in {"sslmode", "connect_timeout", "application_name"} for k, _ in params):
            return "unsupported_query_parameter"
        if len({k for k, _ in params}) != len(params):
            return "duplicate_query_parameter"
        if url.hostname == f"db.{project}.supabase.co":
            if "." in user and user.rsplit(".", 1)[1] != project:
                return "user_project_mismatch"
            return None if port in (None, 5432) else "unsupported_port"
        if re.fullmatch(r"aws-\d+-[a-z0-9-]+\.pooler\.supabase\.com", url.hostname or ""):
            if user != f"postgres.{project}":
                return "user_project_mismatch"
            if port in (None, 5432):
                return None
            if port == 6543:
                return "transaction_pooler_not_supported"
            return "unsupported_port"
        return "host_or_project_mismatch"
    except (ValueError, KeyError):
        return "malformed_url"


def verify_connection_identity(database_url, target):
    """Allow project-bound direct or session connections; settings are checked next."""
    reason = connection_rejection(database_url, target)
    if reason is not None:
        raise MigrationError(f"Migration connection rejected: {reason}")


def bounded_url(database_url):
    url = urlsplit(database_url)
    params = parse_qsl(url.query, keep_blank_values=True)
    return urlunsplit(url._replace(query=urlencode(params + [("options", STARTUP_OPTIONS)], quote_via=quote)))


def run_cli(args, deadline=None):
    timeout = COMMAND_TIMEOUT if deadline is None else deadline - time.monotonic()
    if timeout <= 0:
        raise MigrationError("Migration command deadline exceeded")
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except BaseException:
        # The CLI can have child processes. Local cancellation is secondary to
        # the server transaction timer, which also survives loss of the runner.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate()
        raise
    return subprocess.CompletedProcess(args, process.returncode, stdout, stderr)


# Only these known codes and fixed text markers may cross the CLI log boundary.
SQLSTATES = {"08000", "08001", "08003", "08004", "08006", "08007", "08P01",
             "22023", "25006", "25P02", "25P04", "28000", "28P01", "3D000",
             "42501", "42601", "42704", "42883", "53300", "53400", "55P03",
             "57014", "57P01", "57P02", "57P03", "P0001"}
ERROR_MARKERS = {
    "dns": ("no such host", "name resolution"),
    "connection_refused": ("connection refused",),
    "network_unreachable": ("network is unreachable", "no route to host"),
    "timeout": ("i/o timeout", "context deadline exceeded", "connection timed out"),
    "tls": ("tls error", "tls handshake", "certificate verify failed", "x509:"),
    "authentication": ("password authentication failed", "authentication failed"),
    "startup_parameter": ("unsupported startup parameter", "unrecognized configuration parameter"),
    "cli_usage": ("unknown flag", "unknown command"),
    "execution_settings": ("migration execution settings are unavailable",),
}


def invoke_cli(args, deadline, stage):
    try:
        result = run_cli(args, deadline)
    except subprocess.TimeoutExpired:
        raise MigrationError(f"stage={stage} category=command_timeout") from None
    except OSError:
        raise MigrationError(f"stage={stage} category=process_io_error") from None
    except MigrationError as error:
        raise MigrationError(f"stage={stage}: {error}") from None
    if result.returncode:
        output = (result.stdout or "") + (result.stderr or "")
        states = sorted(SQLSTATES.intersection(re.findall(r"SQLSTATE ([A-Z0-9]{5})\b", output)))
        lowered = output.lower()
        markers = sorted(name for name, patterns in ERROR_MARKERS.items()
                         if any(pattern in lowered for pattern in patterns))
        # Markers describe observed CLI text, not a proven underlying cause.
        raise MigrationError(f"stage={stage} category=cli_exit exit_code={result.returncode} "
                             f"SQLSTATE {', '.join(states) or 'none'} "
                             f"markers={','.join(markers) or 'none'}; no raw output logged")
    return result


def query_rows(result, stage):
    try:
        data = json.loads(result.stdout)
    except (ValueError, TypeError):
        raise MigrationError(f"stage={stage} category=invalid_json") from None
    rows = data.get("rows") if isinstance(data, dict) else data
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise MigrationError(f"stage={stage} category=output_shape")
    return rows


PREFLIGHT_CHECKS = {
    "postgres_version_ok": "current_setting('server_version_num')::int >= 170000",
    "transaction_timeout_present": "EXISTS (SELECT FROM pg_settings WHERE name='transaction_timeout')",
    "transaction_timeout_setting_ok": "EXISTS (SELECT FROM pg_settings WHERE name='transaction_timeout' AND setting='2000')",
    "transaction_timeout_reset_ok": "EXISTS (SELECT FROM pg_settings WHERE name='transaction_timeout' AND reset_val='2000')",
    "lock_timeout_present": "EXISTS (SELECT FROM pg_settings WHERE name='lock_timeout')",
    "lock_timeout_setting_ok": "EXISTS (SELECT FROM pg_settings WHERE name='lock_timeout' AND setting='250')",
    "lock_timeout_reset_ok": "EXISTS (SELECT FROM pg_settings WHERE name='lock_timeout' AND reset_val='250')",
}


def preflight(cli, database_url, project, deadline):
    # These booleans preserve the readiness predicate without logging arbitrary values.
    sql = "SELECT " + ", ".join(f"{expression} AS {name}" for name, expression in PREFLIGHT_CHECKS.items())
    result = invoke_cli([cli, "db", "query", sql, "--db-url", database_url,
                         "--workdir", str(project), "--output", "json"], deadline, "preflight_query")
    rows = query_rows(result, "preflight_response")
    if (len(rows) != 1 or rows[0].keys() != PREFLIGHT_CHECKS.keys()
            or any(type(value) is not bool for value in rows[0].values())):
        raise MigrationError("stage=preflight_response category=check_shape")
    checks = " ".join(f"{name}={str(rows[0][name]).lower()}" for name in PREFLIGHT_CHECKS)
    if not all(rows[0].values()):
        raise MigrationError(f"stage=preflight_settings category=settings_mismatch {checks}")
    print(f"stage=preflight_settings category=passed {checks}")


def verified_aggregate(root):
    data = (root / "supabase/shared-auth-history" / AGGREGATE).read_bytes()
    parts = []
    for name, expected in SOURCES.items():
        source = (root / "supabase/shared-auth-migrations" / name).read_bytes()
        if hashlib.sha256(source).hexdigest() != expected:
            raise MigrationError("Canonical shared-Auth source hash mismatch")
        parts.append(b"-- Source: " + name.encode() + b"\n" + source)
    if hashlib.sha256(data).hexdigest() != SHA256 or data != b"\n\n".join(parts):
        raise MigrationError("Historical shared-Auth aggregate hash mismatch")
    return data


def cli_run(cli, database_url, project, args, deadline=None):
    stage = ("migration_preview" if "--dry-run" in args else
             "migration_execute" if args[:2] == ["db", "push"] else "migration_list")
    result = invoke_cli([cli, *args, "--db-url", database_url, "--workdir", str(project)], deadline, stage)
    return result.stdout + result.stderr


def history_row(cli, database_url, project, deadline=None):
    # A fresh database has no migration ledger yet.
    def query(sql, stage):
        result = invoke_cli(
            [cli, "db", "query", sql, "--db-url", database_url,
             "--workdir", str(project), "--output", "json"], deadline, stage)
        return query_rows(result, stage)

    present = query("SELECT to_regclass('supabase_migrations.schema_migrations') IS NOT NULL AS present",
                    "history_presence")
    if present != [{"present": True}]:
        if present == [{"present": False}]:
            return []
        raise MigrationError("stage=history_presence category=presence_shape; Unrecognized migration history presence")
    return query(f"SELECT version,name,cardinality(statements) AS statement_count, "
                 "encode(sha256(convert_to(statements[1],'UTF8')),'hex') AS sha256 "
                 f"FROM supabase_migrations.schema_migrations WHERE version='{VERSION}'", "history_query")


def verify_history(rows, target):
    if target == "use4":
        expected = [{"version": VERSION, "name": NAME, "statement_count": 1, "sha256": SHA256}]
        if rows != expected:
            raise MigrationError("stage=history_verification category=east_history_mismatch; East shared-Auth history is missing or mismatched; refusing replay")
    elif rows:
        raise MigrationError("stage=history_verification category=unexpected_regional_history; Unexpected shared-Auth history in a regional-only migration target")


def migrate(target, action, database_url, root=ROOT, cli="supabase"):
    deadline = time.monotonic() + COMMAND_TIMEOUT
    if action not in ("preflight", "recovery-preflight", "recover", "push", "list", "dry-run"):
        raise MigrationError("Unsupported migration action")
    verify_connection_identity(database_url, target)
    database_url = bounded_url(database_url)
    version = invoke_cli([cli, "--version"], deadline, "cli_version")
    if version.returncode or version.stdout.strip() != CLI_VERSION:
        raise MigrationError(f"stage=cli_version category=version_mismatch expected={CLI_VERSION} version_ok=false")
    aggregate = verified_aggregate(root)
    with tempfile.TemporaryDirectory(prefix="regional-migrations-") as workdir:
        project = Path(workdir)
        migrations = project / "supabase/migrations"
        migrations.mkdir(parents=True)
        (project / "supabase/config.toml").write_text('project_id = "regional-migrations"\n')
        if action == "preflight":
            preflight(cli, database_url, project, deadline)
            print(f"{target}: read-only connection preflight succeeded")
            return
        # This CLI hook runs on its migration session without a history row.
        # Never copy repository roles: this file only verifies startup defaults.
        (project / "supabase/roles.sql").write_text(EXECUTION_GUARD)
        versions = set()
        for source in sorted((root / "supabase/migrations").glob("*.sql")):
            version = source.name.split("_", 1)[0]
            if version in versions or version == VERSION or version in {s.split("_", 1)[0] for s in SOURCES}:
                raise MigrationError("Duplicate or shared-Auth version in regional migrations")
            versions.add(version)
            shutil.copyfile(source, migrations / source.name)
        rows = history_row(cli, database_url, project, deadline)
        verify_history(rows, target)
        if target == "use4":
            (migrations / AGGREGATE).write_bytes(aggregate)
        if action in ("recovery-preflight", "recover"):
            import retained_storage_recovery as recovery
            import recovery_evidence
            runner = recovery.Recovery(target, database_url, root, cli, deadline)
            revision = os.environ.get("GITHUB_SHA", "")
            evidence_run = os.environ.get("RECOVERY_EVIDENCE_RUN_ID", "")
            if target == "usw2":
                runner.observation = recovery_evidence.Observation(
                    repository=os.environ.get("GITHUB_REPOSITORY", ""), revision=revision,
                    run_id=evidence_run, plan_hash=runner.plan_hash,
                    database_project=PROJECTS[target], deadline=deadline)
                runner.observe()
            with runner.connection(lock=False) as conn:
                state = runner.inspect(conn)
            receipt = {"revision": revision, "target": target, "plan_hash": runner.plan_hash,
                       "history": recovery.digest(state["history"]), "catalog": recovery.digest(state["catalog"]),
                       "physical_catalog": state["guard_catalog"],
                       "preparations": recovery.digest(state["receipts"]),
                       "writer_state": runner.observation.state_digest if target == "usw2" else None}
            receipt_dir = Path(os.environ.get("RECOVERY_RECEIPT_DIR", ""))
            if not os.environ.get("RECOVERY_RECEIPT_DIR") or not re.fullmatch(r"[a-f0-9]{40}", revision):
                raise MigrationError("Recovery requires an exact revision and receipt directory")
            receipt_path = receipt_dir / (target + ".json")
            if action == "recovery-preflight":
                receipt_dir.mkdir(parents=True, exist_ok=True)
                receipt_path.write_text(json.dumps(receipt, sort_keys=True) + "\n")
                print(f"{target}: read-only recovery preflight succeeded")
                return
            if json.loads(receipt_path.read_text()) != receipt:
                raise MigrationError("Recovery state changed since the approved preflight")
            runner.run(project, state)
            verify_history(history_row(cli, database_url, project, runner.command_deadline()), target)
            print(f"{target}: recovery verified; existing history preserved")
            return
        import retained_storage_recovery as recovery
        ordinary_guard = recovery.ordinary_guard(target, database_url, root, cli, deadline)
        (project / "supabase/roles.sql").write_text(EXECUTION_GUARD + ordinary_guard)
        preview = cli_run(cli, database_url, project, ["db", "push", "--dry-run", "--yes"], deadline)
        if AGGREGATE in preview:
            raise MigrationError("CLI proposed replaying the shared-Auth aggregate")
        # Recheck before executing against the same composed snapshot. No path
        # can provision shared Auth or repair a missing history entry.
        verify_history(history_row(cli, database_url, project, deadline), target)
        if action == "push":
            cli_run(cli, database_url, project, ["db", "push", "--yes", "--include-roles"], deadline)
        elif action == "list":
            cli_run(cli, database_url, project, ["migration", "list"], deadline)
        elif action != "dry-run":
            raise MigrationError("Unsupported migration action")
        verify_history(history_row(cli, database_url, project, deadline), target)
        print(f"{target}: migration {action} succeeded; shared-Auth history preserved")


def main():
    def cancelled(signum, frame):
        raise MigrationError("Migration command cancelled")

    signal.signal(signal.SIGTERM, cancelled)
    signal.signal(signal.SIGINT, cancelled)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", choices=PROJECTS)
    parser.add_argument("action", choices=["preflight", "recovery-preflight", "recover", "dry-run", "list", "push"])
    args = parser.parse_args()
    database_url = os.environ.get("DATABASE_URL", "")
    try:
        migrate(args.target, args.action, database_url)
    except Exception:
        # OSError and subprocess exceptions may contain command arguments.
        import sys
        error = sys.exc_info()[1]
        print(str(error) if isinstance(error, MigrationError) else "stage=runner category=unexpected_error; no raw output logged", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    import sys
    sys.modules.setdefault("migrate_database", sys.modules[__name__])
    raise SystemExit(main())
