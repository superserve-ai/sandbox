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


def verify_connection_identity(database_url, target):
    """Require a direct project connection that reapplies startup defaults."""
    try:
        url = urlsplit(database_url)
        project = PROJECTS[target]
        user = unquote(url.username or "")
        params = parse_qsl(url.query, strict_parsing=True, keep_blank_values=True)
        if (url.scheme not in ("postgres", "postgresql") or not user or url.fragment
                or url.path != "/postgres" or url.port not in (None, 5432)
                or any(k not in {"sslmode", "connect_timeout", "application_name"}
                       for k, _ in params)
                or len({k for k, _ in params}) != len(params)):
            raise ValueError()
        if url.hostname == f"db.{project}.supabase.co":
            if "." in user and user.rsplit(".", 1)[1] != project:
                raise ValueError()
            return
    except (ValueError, KeyError):
        pass
    # Never include a connection URL or parsed credentials in errors.
    raise MigrationError("Database connection must use the selected project's direct port 5432 endpoint")


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


def preflight(cli, database_url, project, deadline):
    # Read-only even on an empty database: no push, roles hook or ledger setup.
    result = run_cli([cli, "db", "query",
                      "SELECT current_setting('server_version_num')::int >= 170000 "
                      "AND EXISTS (SELECT FROM pg_settings WHERE name='transaction_timeout' "
                      "AND setting='2000' AND reset_val='2000') "
                      "AND EXISTS (SELECT FROM pg_settings WHERE name='lock_timeout' "
                      "AND setting='250' AND reset_val='250') AS ready",
                      "--db-url", database_url, "--workdir", str(project), "--output", "json"], deadline)
    try:
        data = json.loads(result.stdout)
        rows = data.get("rows") if isinstance(data, dict) else data
        if result.returncode or rows != [{"ready": True}]:
            raise ValueError()
    except (ValueError, TypeError):
        raise MigrationError("Read-only migration preflight failed; no raw output logged") from None


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
    result = run_cli([cli, *args, "--db-url", database_url, "--workdir", str(project)], deadline)
    if result.returncode:
        # CLI failures may echo connection strings or database statement data.
        states = sorted(set(re.findall(r"SQLSTATE ([A-Z0-9]{5})", result.stdout + result.stderr)))
        suffix = f" (SQLSTATE {', '.join(states)})" if states else ""
        raise MigrationError(f"Supabase {args[0]} {args[1]} failed{suffix}; no raw output logged")
    return result.stdout + result.stderr


def history_row(cli, database_url, project, deadline=None):
    # The migration runner creates this table on a fresh database. Query its
    # existence first so ordinary fresh regional databases need no setup.
    def query(sql):
        result = run_cli(
            [cli, "db", "query", sql, "--db-url", database_url,
             "--workdir", str(project), "--output", "json"], deadline)
        if result.returncode:
            raise MigrationError("Could not verify migration history; no raw output logged")
        try:
            data = json.loads(result.stdout)
            # Normal CLI output is an array; agent mode wraps it in an envelope.
            rows = data["rows"] if isinstance(data, dict) else data
            if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
                raise ValueError()
            return rows
        except (ValueError, KeyError, TypeError):
            raise MigrationError("Unrecognized CLI history response") from None

    present = query("SELECT to_regclass('supabase_migrations.schema_migrations') IS NOT NULL AS present")
    if present != [{"present": True}]:
        if present == [{"present": False}]:
            return []
        raise MigrationError("Unrecognized migration history presence")
    return query(f"SELECT version,name,cardinality(statements) AS statement_count, "
                 "encode(sha256(convert_to(statements[1],'UTF8')),'hex') AS sha256 "
                 f"FROM supabase_migrations.schema_migrations WHERE version='{VERSION}'")


def verify_history(rows, target):
    if target == "use4":
        expected = [{"version": VERSION, "name": NAME, "statement_count": 1, "sha256": SHA256}]
        if rows != expected:
            raise MigrationError("East shared-Auth history is missing or mismatched; refusing replay")
    elif rows:
        raise MigrationError("Unexpected shared-Auth history in a regional-only migration target")


def migrate(target, action, database_url, root=ROOT, cli="supabase"):
    deadline = time.monotonic() + COMMAND_TIMEOUT
    if action not in ("preflight", "recovery-preflight", "recover", "push", "list", "dry-run"):
        raise MigrationError("Unsupported migration action")
    verify_connection_identity(database_url, target)
    database_url = bounded_url(database_url)
    version = run_cli([cli, "--version"], deadline)
    if version.returncode or version.stdout.strip() != CLI_VERSION:
        raise MigrationError(f"Migration execution requires Supabase CLI {CLI_VERSION}")
    aggregate = verified_aggregate(root)
    with tempfile.TemporaryDirectory(prefix="regional-migrations-") as workdir:
        project = Path(workdir)
        migrations = project / "supabase/migrations"
        migrations.mkdir(parents=True)
        (project / "supabase/config.toml").write_text('project_id = "regional-migrations"\n')
        if action == "preflight":
            preflight(cli, database_url, project, deadline)
            print(f"{target}: read-only direct-connection preflight succeeded")
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
        print(str(error) if isinstance(error, MigrationError) else "Migration command failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    import sys
    sys.modules.setdefault("migrate_database", sys.modules[__name__])
    raise SystemExit(main())
