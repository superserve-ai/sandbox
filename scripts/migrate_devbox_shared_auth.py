"""Initialize reviewed shared Auth migrations on one bound, empty devbox."""

import sys

if __name__ == "__main__" and not sys.flags.isolated:
    raise SystemExit("Run this initializer with python -I to isolate imports")

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import types
from urllib.parse import parse_qsl, unquote, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

import psycopg

def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("inspect", "apply"))
    parser.add_argument("--binding", required=True, type=Path)
    parser.add_argument("--revision", required=True)
    return parser.parse_args()


def pinned_engine(revision):
    root = Path(__file__).resolve().parents[1]
    # Ignore caller Git configuration/executable lookup and keep object reads
    # local. No worktree Git operation may invoke fsmonitor or content filters.
    git = ["/usr/bin/git", "--no-pager", "-c", "core.fsmonitor=false",
           "-c", "core.hooksPath=/dev/null", "-c", "protocol.allow=never"]
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_CONFIG_GLOBAL": "/dev/null",
           "GIT_ATTR_NOSYSTEM": "1", "GIT_NO_REPLACE_OBJECTS": "1", "GIT_OPTIONAL_LOCKS": "0",
           "GIT_TERMINAL_PROMPT": "0", "GIT_NO_LAZY_FETCH": "1", "GIT_ALLOW_PROTOCOL": ""}
    def read(*args):
        return subprocess.check_output([*git, *args], cwd=root, env=env, stderr=subprocess.PIPE)
    if not re.fullmatch(r"[a-f0-9]{40}", revision):
        raise ValueError("invalid_revision")
    if read("rev-parse", "HEAD").decode().strip() != revision:
        raise ValueError("source_revision_mismatch")
    sources = {}
    for name in ("migrate_devbox_shared_auth", "migrate_database", "migrate_shared_auth"):
        path = f"scripts/{name}.py"
        sources[name] = read("cat-file", "blob", f"{revision}:{path}")
        if (root / path).read_bytes() != sources[name]:
            raise ValueError("source_checkout_mismatch")
    # Never add the checkout to sys.path. Load helpers from the selected Git
    # objects, bypassing untracked modules and executable bytecode caches.
    for name in ("migrate_database", "migrate_shared_auth"):
        path = f"scripts/{name}.py"
        code = sources[name]
        module = types.ModuleType(name)
        module.__file__ = str(root / path)
        sys.modules[name] = module
        exec(compile(code, module.__file__, "exec"), module.__dict__)
    return sys.modules["migrate_shared_auth"]


if __name__ == "__main__":
    CLI_ARGS = arguments()
    try:
        shared = pinned_engine(CLI_ARGS.revision)
    except Exception:
        raise SystemExit("Pinned initializer source could not be verified")
else:
    import migrate_shared_auth as shared


CONFIG = Path("/etc/superserve-devbox/devbox.env")
RUNTIME = Path("/var/lib/superserve-devbox/runtime.json")
METADATA = "http://169.254.169.254/computeMetadata/v1/"
MIGRATIONS = (
    ("authority", shared.source), ("claims", shared.claim_source),
    ("approvals", shared.approval_source), ("acceptances", shared.acceptance_source),
)
require = shared.require


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def protected_file(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), encoding="utf-8") as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                "unsafe_binding_file")
        data = source.read(262145)
        require(len(data) <= 262144, "binding_file_too_large")
        return data


def validate_binding(binding, now=None):
    require(binding.get("purpose") == "disposable-shared-auth-bootstrap", "invalid_binding_purpose")
    for key in ("project", "zone", "instance", "instance_id", "devbox_id", "run_id",
                "database_system_identifier", "database_oid", "candidate_revision", "expires_at"):
        require(isinstance(binding.get(key), str) and bool(binding[key]), "incomplete_binding")
    require(re.fullmatch(r"devbox-[a-z0-9-]+", binding["instance"]), "not_devbox_instance")
    require(re.fullmatch(r"[a-f0-9]{12}", binding["devbox_id"]), "invalid_devbox_id")
    for key in ("instance_id", "run_id", "database_system_identifier", "database_oid"):
        require(re.fullmatch(r"[0-9]+", binding[key]), "invalid_binding_identifier")
    require(re.fullmatch(r"[a-f0-9]{40}", binding["candidate_revision"]), "invalid_candidate_revision")
    expiry = datetime.fromisoformat(binding["expires_at"].replace("Z", "+00:00"))
    require(expiry.tzinfo is not None and expiry > (now or datetime.now(timezone.utc)), "expired_binding")
    require(binding.get("database") == {"host": "127.0.0.1", "port": 54322, "name": "postgres"},
            "invalid_database_binding")
    expected = {name: hashlib.sha256(source().encode()).hexdigest() for name, source in MIGRATIONS}
    require(binding.get("source_sha256") == expected, "candidate_source_mismatch")


def metadata_value(path):
    opener = build_opener(ProxyHandler({}), NoRedirect())
    with opener.open(Request(METADATA + path, headers={"Metadata-Flavor": "Google"}), timeout=3) as response:
        require(response.headers.get("Metadata-Flavor") == "Google", "invalid_metadata_response")
        data = response.read(4097)
        require(len(data) <= 4096, "invalid_metadata_response")
        return data.decode().strip()


def verify_host(binding):
    actual = {
        "project": metadata_value("project/project-id"),
        "zone": metadata_value("instance/zone").rsplit("/", 1)[-1],
        "instance": metadata_value("instance/name"),
        "instance_id": metadata_value("instance/id"),
    }
    require(all(binding[key] == value for key, value in actual.items()), "vm_identity_mismatch")
    config = {}
    for line in protected_file(CONFIG).splitlines():
        tokens = shlex.split(line, comments=True)
        if tokens:
            require(len(tokens) == 1 and "=" in tokens[0], "invalid_devbox_config")
            key, value = tokens[0].split("=", 1)
            require(key not in config, "invalid_devbox_config")
            config[key] = value
    require(config.get("DEVBOX_ID") == binding["devbox_id"], "devbox_identity_mismatch")
    runtime = json.loads(protected_file(RUNTIME))
    require(runtime.get("host") == {
        "project": binding["project"], "zone": binding["zone"],
        "instance": binding["instance"], "instance_id": binding["instance_id"],
    }, "runtime_identity_mismatch")


def connection_parameters(url):
    require(not any(os.environ.get(key) for key in ("PGSERVICE", "PGSERVICEFILE", "PGSYSCONFDIR")),
            "libpq_service_not_allowed")
    parsed = urlsplit(url)
    require(parsed.scheme in ("postgres", "postgresql") and parsed.hostname == "127.0.0.1"
            and parsed.port == 54322 and parsed.path == "/postgres"
            and unquote(parsed.username or "") == "postgres" and not parsed.fragment,
            "local_connection_required")
    params = parse_qsl(parsed.query, strict_parsing=True, keep_blank_values=True)
    require(params in ([], [("sslmode", "disable")]), "unsupported_connection_parameter")
    # Explicit libpq fields prevent PGHOSTADDR/PGSERVICE from redirecting a
    # seemingly local connection. Passwords are never placed in process argv.
    return dict(host="127.0.0.1", hostaddr="127.0.0.1", port=54322,
                dbname="postgres", user="postgres", password=unquote(parsed.password or ""),
                sslmode="disable", options=shared.OPTIONS,
                application_name="devbox-shared-auth-bootstrap", connect_timeout=10)


def verify_database(conn, binding):
    actual = conn.execute("""SELECT current_database(), current_user, session_user,
        (SELECT system_identifier::text FROM pg_control_system()),
        (SELECT oid::text FROM pg_database WHERE datname=current_database()),
        inet_server_addr()::text, inet_server_port()""").fetchone()
    require(actual[:5] == ("postgres", "postgres", "postgres", binding["database_system_identifier"],
                           binding["database_oid"]) and actual[6] == 54322,
            "database_identity_mismatch")


def initialize(conn, revision, execute=False):
    results = []
    with conn.transaction():
        if not execute:
            conn.execute("SET TRANSACTION READ ONLY")
        else:
            require(conn.execute("SELECT pg_try_advisory_xact_lock(%s)", (shared.MUTEX,)).fetchone()[0],
                    "shared_migration_busy")
            # No signup may appear between the empty-database check and commit.
            conn.execute("LOCK TABLE auth.users IN SHARE MODE")
        before = shared.prerequisites(conn, "devbox")
        require(conn.execute("""SELECT rolcanlogin AND NOT rolsuper AND NOT rolinherit
            AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls
            AND NOT EXISTS(SELECT FROM pg_auth_members m WHERE (m.roleid=r.oid OR m.member=r.oid)
                AND NOT (m.roleid=r.oid AND m.member='postgres'::regrole
                         AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option))
            FROM pg_roles r WHERE rolname='promotion_evidence_proxy'""").fetchone() == (True,),
                "proxy_role_mismatch")
        shared.inspect(conn, shared.source(), "authority")
        if execute:
            require(conn.execute("SELECT NOT EXISTS(SELECT FROM auth.users)").fetchone()[0],
                    "nonempty_auth_database")
        for name, source in MIGRATIONS:
            sql = source()
            if execute:
                results.append(shared._apply(conn, "devbox", revision, sql, True, name))
            else:
                results.append({"target": "devbox", "migration": name, "state": shared.inspect(conn, sql, name)})
        if execute:
            for name, source in MIGRATIONS:
                require(shared.inspect(conn, source(), name) == "applied", "migration_readback_failed")
        require(shared.ordinary_history(conn) == before, "regional_history_changed")
    return results


def main():
    args = CLI_ARGS
    try:
        require(os.geteuid() == 0, "root_executor_required")
        binding = json.loads(protected_file(args.binding))
        validate_binding(binding)
        verify_host(binding)
        params = connection_parameters(os.environ.get("DATABASE_URL", ""))
        with psycopg.connect(autocommit=True, **params) as conn:
            verify_database(conn, binding)
            results = initialize(conn, args.revision, args.action == "apply")
        print(json.dumps({"target": "devbox", "instance_id": binding["instance_id"],
                          "devbox_id": binding["devbox_id"], "run_id": binding["run_id"],
                          "candidate_revision": binding["candidate_revision"], "tool_revision": args.revision,
                          "migrations": results}, sort_keys=True))
    except Exception as error:
        category = str(error) if isinstance(error, shared.SharedMigrationError) else "devbox_bootstrap_failed"
        print(json.dumps({"error": category, "next_step": "inspect the bound devbox; do not reset or bypass guards"}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
