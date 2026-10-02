"""Run regional migrations with the verified history of each database."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from urllib.parse import parse_qsl, unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
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
    """Accept direct project hosts or project-scoped Supabase pooler logins."""
    try:
        url = urlsplit(database_url)
        project = PROJECTS[target]
        user = unquote(url.username or "")
        params = parse_qsl(url.query, strict_parsing=True, keep_blank_values=True)
        if (url.scheme not in ("postgres", "postgresql") or not user or url.fragment
                or url.path != "/postgres" or url.port not in (None, 5432, 6543)
                or any(k not in {"sslmode", "connect_timeout", "application_name"}
                       for k, _ in params)
                or len({k for k, _ in params}) != len(params)):
            raise ValueError()
        if url.hostname == f"db.{project}.supabase.co":
            if "." in user and user.rsplit(".", 1)[1] != project:
                raise ValueError()
            return
        if (re.fullmatch(r"aws-\d+-[a-z0-9-]+\.pooler\.supabase\.com", url.hostname or "")
                and user == f"postgres.{project}"):
            return
    except (ValueError, KeyError):
        pass
    # Never include a connection URL or parsed credentials in errors.
    raise MigrationError("Database connection does not match the selected project")


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


def cli_run(cli, database_url, project, args):
    result = subprocess.run(
        [cli, *args, "--db-url", database_url, "--workdir", str(project)],
        capture_output=True, text=True, timeout=1200)
    if result.returncode:
        # CLI failures may echo connection strings or database statement data.
        states = sorted(set(re.findall(r"SQLSTATE ([A-Z0-9]{5})", result.stdout + result.stderr)))
        suffix = f" (SQLSTATE {', '.join(states)})" if states else ""
        raise MigrationError(f"Supabase {args[0]} {args[1]} failed{suffix}; no raw output logged")
    return result.stdout + result.stderr


def history_row(cli, database_url, project):
    # The migration runner creates this table on a fresh database. Query its
    # existence first so ordinary fresh regional databases need no setup.
    def query(sql):
        result = subprocess.run(
            [cli, "db", "query", sql, "--db-url", database_url,
             "--workdir", str(project), "--output", "json"],
            capture_output=True, text=True, timeout=60)
        if result.returncode:
            raise MigrationError("Could not verify migration history; no raw output logged")
        try:
            return json.loads(result.stdout)["rows"]
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
    verify_connection_identity(database_url, target)
    aggregate = verified_aggregate(root)
    with tempfile.TemporaryDirectory(prefix="regional-migrations-") as workdir:
        project = Path(workdir)
        migrations = project / "supabase/migrations"
        migrations.mkdir(parents=True)
        (project / "supabase/config.toml").write_text('project_id = "regional-migrations"\n')
        versions = set()
        for source in sorted((root / "supabase/migrations").glob("*.sql")):
            version = source.name.split("_", 1)[0]
            if version in versions or version == VERSION or version in {s.split("_", 1)[0] for s in SOURCES}:
                raise MigrationError("Duplicate or shared-Auth version in regional migrations")
            versions.add(version)
            shutil.copyfile(source, migrations / source.name)
        rows = history_row(cli, database_url, project)
        verify_history(rows, target)
        if target == "use4":
            (migrations / AGGREGATE).write_bytes(aggregate)
        preview = cli_run(cli, database_url, project, ["db", "push", "--dry-run", "--yes"])
        if AGGREGATE in preview:
            raise MigrationError("CLI proposed replaying the shared-Auth aggregate")
        # Recheck before executing against the same composed snapshot. No path
        # can provision shared Auth or repair a missing history entry.
        verify_history(history_row(cli, database_url, project), target)
        if action == "push":
            cli_run(cli, database_url, project, ["db", "push", "--yes"])
        elif action == "list":
            cli_run(cli, database_url, project, ["migration", "list"])
        elif action != "dry-run":
            raise MigrationError("Unsupported migration action")
        verify_history(history_row(cli, database_url, project), target)
        print(f"{target}: migration {action} succeeded; shared-Auth history preserved")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", choices=PROJECTS)
    parser.add_argument("action", choices=["dry-run", "list", "push"])
    args = parser.parse_args()
    database_url = os.environ.get("DATABASE_URL", "")
    try:
        migrate(args.target, args.action, database_url)
    except (MigrationError, OSError, subprocess.TimeoutExpired):
        # OSError and subprocess exceptions may contain command arguments.
        import sys
        error = sys.exc_info()[1]
        print(str(error) if isinstance(error, MigrationError) else "Migration command failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
