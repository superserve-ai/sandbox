"""Apply the reviewed shared Auth migration without changing regional history."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

import psycopg
from psycopg.types.json import Jsonb

import migrate_database as regional


ROOT = Path(__file__).resolve().parents[1]
VERSION = "20261016070000"
NAME = "yc_company_activation_authority"
SOURCE_HASH = "c74824a26e75a88b6593aa46df5ff1540289f5de3fd9e92f1395296869742295"
TABLE = "public.yc_company_activation_authority"
RPCS = (
    "public.read_yc_activation_authority(text,uuid)",
    "public.reserve_yc_activation_authority(text,uuid,text,uuid,text,text,uuid)",
    "public.revoke_yc_activation_authority(uuid,uuid,uuid)",
    "public.lock_yc_activation_authority(uuid,uuid,text)",
)
FUNCTIONS = RPCS + ("public.guard_yc_company_activation_authority()",)
ROLES = ("anon", "authenticated", "service_role", "promotion_evidence_proxy")
LEDGER = "shared_auth_migrations.schema_migrations"
MUTEX = 6834211091020402
OPTIONS = "-c statement_timeout=15000 -c lock_timeout=1000 -c transaction_timeout=30000"
ACL_SQL = """
REVOKE ALL ON TABLE public.yc_company_activation_authority FROM service_role;
GRANT SELECT,INSERT,UPDATE ON TABLE public.yc_company_activation_authority TO service_role;
REVOKE ALL ON FUNCTION public.guard_yc_company_activation_authority() FROM service_role;
"""
CLAIM_VERSION = "20261016174553"
CLAIM_NAME = "yc_claim_authority"
CLAIM_HASH = "fb950d14161c49f47dd6ea9d2094cdf35283165ba29d582807c942e85821cfa4"
CLAIM_TABLES = tuple("public." + name for name in (
    "yc_claim", "yc_claim_decision", "yc_claim_mail", "yc_claim_rate", "yc_claim_identity_history"))
CLAIM_FUNCTIONS = ("public.yc_claim_view(public.yc_claim)", "public.yc_claim_rpc(text,jsonb)",
                   "public.yc_claim_auth_lifecycle()", "public.yc_claim_preserve_evidence()")
CLAIM_ACL_SQL = """
REVOKE ALL ON FUNCTION public.yc_claim_auth_lifecycle(),public.yc_claim_preserve_evidence()
FROM anon,authenticated,service_role,promotion_evidence_proxy;
"""


class SharedMigrationError(Exception):
    pass


def require(condition, category):
    if not condition:
        raise SharedMigrationError(category)


def source(root=ROOT):
    data = (root / "supabase/shared-auth-migrations" / f"{VERSION}_{NAME}.sql").read_bytes()
    require(hashlib.sha256(data).hexdigest() == SOURCE_HASH, "source_hash_mismatch")
    return data.decode("utf-8")


def claim_source(root=ROOT):
    data = (root / "supabase/shared-auth-migrations" / f"{CLAIM_VERSION}_{CLAIM_NAME}.sql").read_bytes()
    require(hashlib.sha256(data).hexdigest() == CLAIM_HASH, "source_hash_mismatch")
    return data.decode("utf-8")


def claim_execution(sql):
    # Only this pinned source may have its outer wrapper removed. Executing its
    # COMMIT inside our transaction would separate the schema from its receipt.
    require(hashlib.sha256(sql.encode()).hexdigest() == CLAIM_HASH, "source_hash_mismatch")
    prefix = "-- Shared Auth/control-plane database only, never a regional claim replica.\nBEGIN;\n"
    require(sql.startswith(prefix) and sql.endswith("COMMIT;\n"), "claim_transaction_wrapper_mismatch")
    return sql[len(prefix):-len("COMMIT;\n")] + CLAIM_ACL_SQL


def ordinary_history(conn):
    return conn.execute("SELECT version,name,statements FROM supabase_migrations.schema_migrations ORDER BY version").fetchall()


def prerequisites(conn, target):
    require(conn.execute("SELECT current_user='postgres' AND session_user='postgres' "
                         "AND current_setting('server_version_num')::int>=170000").fetchone()[0],
            "privileged_postgres_session_required")
    require(conn.execute("SELECT to_regclass('auth.users') IS NOT NULL "
                         "AND to_regclass('public.signup_device_attempt') IS NOT NULL "
                         "AND to_regclass('supabase_migrations.schema_migrations') IS NOT NULL").fetchone()[0],
            "existing_auth_setup_required")
    require(conn.execute("SELECT count(*) FROM pg_roles WHERE rolname=ANY(%s)", (list(ROLES),)).fetchone()[0] == len(ROLES),
            "required_roles_missing")
    rows = ordinary_history(conn)
    require(not any(row[0] in (VERSION, CLAIM_VERSION) for row in rows), "shared_version_in_regional_history")
    aggregate = [row for row in rows if row[0] == regional.VERSION]
    if target == "use4":
        require(len(aggregate) == 1 and aggregate[0][1] == regional.NAME
                and len(aggregate[0][2] or []) == 1
                and hashlib.sha256(aggregate[0][2][0].encode()).hexdigest() == regional.SHA256,
                "historical_aggregate_mismatch")
    else:
        require(not aggregate, "unexpected_historical_aggregate")
    return rows


def objects_present(conn):
    return conn.execute("SELECT to_regclass(%s) IS NOT NULL OR EXISTS "
                        "(SELECT FROM unnest(%s::text[]) f WHERE to_regprocedure(f) IS NOT NULL)",
                        (TABLE, list(FUNCTIONS))).fetchone()[0]


def catalog(conn, table=TABLE, functions=FUNCTIONS):
    """Record definitions and privileges, never customer rows or credentials."""
    return conn.execute("""
      SELECT jsonb_build_object(
        'table', (SELECT jsonb_build_array(c.relkind,c.relrowsecurity,c.relforcerowsecurity,
                     pg_get_userbyid(c.relowner),c.relacl) FROM pg_class c WHERE c.oid=%s::regclass),
        'columns', (SELECT jsonb_agg(jsonb_build_array(a.attname,format_type(a.atttypid,a.atttypmod),
                     a.attnotnull,pg_get_expr(d.adbin,d.adrelid)) ORDER BY a.attnum)
                     FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
                     WHERE a.attrelid=%s::regclass AND a.attnum>0 AND NOT a.attisdropped),
        'constraints', (SELECT jsonb_agg(jsonb_build_array(conname,pg_get_constraintdef(oid),convalidated) ORDER BY conname)
                     FROM pg_constraint WHERE conrelid=%s::regclass),
        'triggers', (SELECT jsonb_agg(jsonb_build_array(tgname,pg_get_triggerdef(oid),tgenabled) ORDER BY tgname)
                     FROM pg_trigger WHERE tgrelid=%s::regclass AND NOT tgisinternal),
        'policies', (SELECT jsonb_agg(jsonb_build_array(polname,polcmd,polroles,pg_get_expr(polqual,polrelid),
                     pg_get_expr(polwithcheck,polrelid)) ORDER BY polname) FROM pg_policy WHERE polrelid=%s::regclass),
        'functions', (SELECT jsonb_agg(jsonb_build_array(p.oid::regprocedure::text,pg_get_functiondef(p.oid),
                     pg_get_userbyid(p.proowner),p.proacl) ORDER BY p.oid::regprocedure::text)
                     FROM pg_proc p WHERE p.oid=ANY(SELECT to_regprocedure(f) FROM unnest(%s::text[]) f)))
    """, (table, table, table, table, table, list(functions))).fetchone()[0]


def claim_objects_present(conn):
    # Resolve function names without resolving the composite claim type first:
    # it does not exist before this migration.
    return conn.execute("""SELECT
        EXISTS(SELECT FROM unnest(%s::text[]) t WHERE to_regclass(t) IS NOT NULL)
        OR EXISTS(SELECT FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                  WHERE n.nspname='public' AND p.proname=ANY(%s))
        OR EXISTS(SELECT FROM pg_trigger WHERE tgrelid='auth.users'::regclass
                  AND tgname='yc_claim_auth_lifecycle')""",
        (list(CLAIM_TABLES), [f.split('.')[1].split('(')[0] for f in CLAIM_FUNCTIONS])).fetchone()[0]


def claim_catalog(conn):
    return {
        "tables": {table: catalog(conn, table, CLAIM_FUNCTIONS if i == 0 else ())
                   for i, table in enumerate(CLAIM_TABLES)},
        "indexes": conn.execute("""SELECT jsonb_agg(pg_get_indexdef(i.indexrelid) ORDER BY c.relname)
            FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid
            WHERE i.indrelid=ANY(SELECT to_regclass(t) FROM unnest(%s::text[]) t)""",
            (list(CLAIM_TABLES),)).fetchone()[0],
        "auth_trigger": conn.execute("""SELECT jsonb_build_array(pg_get_triggerdef(oid),tgenabled)
            FROM pg_trigger WHERE tgrelid='auth.users'::regclass AND tgname='yc_claim_auth_lifecycle'
            AND NOT tgisinternal""").fetchone()[0],
    }


def verify_claim_permissions(conn):
    for table in CLAIM_TABLES:
        require(conn.execute("SELECT relkind='r' AND relrowsecurity AND relowner='postgres'::regrole "
                             "FROM pg_class WHERE oid=%s::regclass", (table,)).fetchone()[0],
                "claim_table_security_mismatch")
        for role in ROLES:
            require(not conn.execute("SELECT has_table_privilege(%s,%s,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')",
                                     (role, table)).fetchone()[0], "claim_table_privileges_mismatch")
            require(not conn.execute("SELECT has_any_column_privilege(%s,%s,'SELECT,INSERT,UPDATE,REFERENCES')",
                                     (role, table)).fetchone()[0], "claim_column_privileges_mismatch")
    for function in CLAIM_FUNCTIONS:
        for role in ROLES:
            allowed = conn.execute("SELECT has_function_privilege(%s,%s,'EXECUTE')", (role, function)).fetchone()[0]
            require(allowed == (role == "promotion_evidence_proxy" and function == "public.yc_claim_rpc(text,jsonb)"),
                    "claim_rpc_privileges_mismatch")
    require(conn.execute("SELECT count(*)=1 FROM pg_trigger WHERE tgrelid='auth.users'::regclass "
                         "AND tgname='yc_claim_auth_lifecycle' AND tgenabled='O' AND NOT tgisinternal").fetchone()[0],
            "claim_auth_trigger_mismatch")


def verify_permissions(conn):
    require(conn.execute("SELECT relrowsecurity AND relowner='postgres'::regrole FROM pg_class WHERE oid=%s::regclass",
                         (TABLE,)).fetchone()[0], "authority_table_security_mismatch")
    for role in ROLES:
        for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"):
            allowed = conn.execute("SELECT has_table_privilege(%s,%s,%s)", (role, TABLE, privilege)).fetchone()[0]
            require(allowed == (role == "service_role" and privilege in ("SELECT", "INSERT", "UPDATE")),
                    "authority_table_privileges_mismatch")
        for function in FUNCTIONS:
            allowed = conn.execute("SELECT has_function_privilege(%s,%s,'EXECUTE')", (role, function)).fetchone()[0]
            require(allowed == (role in ("service_role", "promotion_evidence_proxy") and function in RPCS),
                    "authority_rpc_privileges_mismatch")


def ledger_exists(conn):
    schema, table = conn.execute("SELECT to_regnamespace('shared_auth_migrations') IS NOT NULL, "
                                "to_regclass(%s) IS NOT NULL", (LEDGER,)).fetchone()
    require(schema == table, "partial_shared_ledger")
    if not table:
        return False
    columns = conn.execute("SELECT attname,format_type(atttypid,atttypmod),attnotnull FROM pg_attribute "
                           "WHERE attrelid=%s::regclass AND attnum>0 AND NOT attisdropped ORDER BY attnum", (LEDGER,)).fetchall()
    require(columns == [("version", "text", True), ("name", "text", True), ("source_sql", "text", True), ("applied_sql", "text", True),
                        ("source_sha256", "text", True), ("catalog", "jsonb", True),
                        ("revision", "text", True), ("applied_at", "timestamp with time zone", True)], "shared_ledger_shape_mismatch")
    require(conn.execute("SELECT c.relkind='r' AND c.relrowsecurity AND c.relowner='postgres'::regrole "
                         "AND n.nspowner='postgres'::regrole FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                         "WHERE c.oid=%s::regclass", (LEDGER,)).fetchone()[0], "shared_ledger_security_mismatch")
    for role in ROLES:
        require(not conn.execute("SELECT has_schema_privilege(%s,'shared_auth_migrations','USAGE') "
                                 "OR has_schema_privilege(%s,'shared_auth_migrations','CREATE') "
                                 "OR has_table_privilege(%s,%s,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')",
                                 (role, role, role, LEDGER)).fetchone()[0], "shared_ledger_privileges_mismatch")
    return True


def inspect(conn, sql, migration="authority"):
    authority_sql = sql if migration == "authority" else source()
    claim_sql = sql if migration == "claims" else claim_source()
    definitions = {
        VERSION: (NAME, authority_sql, authority_sql + ACL_SQL, SOURCE_HASH, objects_present, verify_permissions, catalog),
        CLAIM_VERSION: (CLAIM_NAME, claim_sql, claim_execution(claim_sql), CLAIM_HASH,
                        claim_objects_present, verify_claim_permissions, claim_catalog),
    }
    if not ledger_exists(conn):
        require(not objects_present(conn) and not claim_objects_present(conn), "schema_without_shared_history")
        return "pending"
    rows = conn.execute(f"SELECT version,name,source_sql,applied_sql,source_sha256,catalog,revision FROM {LEDGER} ORDER BY version").fetchall()
    versions = {row[0] for row in rows}
    require(len(versions) == len(rows) and versions <= definitions.keys(), "unknown_shared_history")
    require(CLAIM_VERSION not in versions or VERSION in versions, "claim_authority_history_missing")
    for version, name, stored_sql, applied_sql, stored_hash, stored_catalog, revision in rows:
        expected_name, original, executed, expected_hash, present, permissions, snapshot = definitions[version]
        require(name == expected_name and stored_sql == original and applied_sql == executed and stored_hash == expected_hash
                and re.fullmatch(r"[a-f0-9]{40}", revision), "shared_history_mismatch")
        require(present(conn), "shared_schema_missing")
        permissions(conn)
        require(snapshot(conn) == stored_catalog, "shared_catalog_mismatch")
    for version, definition in definitions.items():
        if version not in versions:
            require(not definition[4](conn), "schema_without_shared_history")
    selected = VERSION if migration == "authority" else CLAIM_VERSION
    return "applied" if selected in versions else "pending"


def apply(conn, target, revision, sql, execute=False, migration="authority"):
    require(target in ("staging", "use4"), "unsupported_auth_target")
    require(re.fullmatch(r"[a-f0-9]{40}", revision), "invalid_revision")
    require(migration in ("authority", "claims"), "unsupported_shared_migration")
    version, name, expected_hash, executed_sql, permissions, snapshot = (
        (VERSION, NAME, SOURCE_HASH, sql + ACL_SQL, verify_permissions, catalog) if migration == "authority" else
        (CLAIM_VERSION, CLAIM_NAME, CLAIM_HASH, claim_execution(sql), verify_claim_permissions, claim_catalog))
    require(hashlib.sha256(sql.encode()).hexdigest() == expected_hash, "source_hash_mismatch")
    with conn.transaction():
        if execute:
            require(conn.execute("SELECT pg_try_advisory_xact_lock(%s)", (MUTEX,)).fetchone()[0], "shared_migration_busy")
        else:
            conn.execute("SET TRANSACTION READ ONLY")
        before = prerequisites(conn, target)
        state = inspect(conn, sql, migration)
        if execute and state == "pending":
            if migration == "claims":
                require(inspect(conn, source()) == "applied", "authority_migration_required")
            if not ledger_exists(conn):
                conn.execute("""
                    CREATE SCHEMA shared_auth_migrations AUTHORIZATION postgres;
                    REVOKE ALL ON SCHEMA shared_auth_migrations FROM PUBLIC,anon,authenticated,service_role,promotion_evidence_proxy;
                    CREATE TABLE shared_auth_migrations.schema_migrations (
                        version text PRIMARY KEY, name text NOT NULL, source_sql text NOT NULL, applied_sql text NOT NULL,
                        source_sha256 text NOT NULL, catalog jsonb NOT NULL, revision text NOT NULL,
                        applied_at timestamptz NOT NULL DEFAULT clock_timestamp());
                    ALTER TABLE shared_auth_migrations.schema_migrations ENABLE ROW LEVEL SECURITY;
                    REVOKE ALL ON shared_auth_migrations.schema_migrations FROM PUBLIC,anon,authenticated,service_role,promotion_evidence_proxy;
                """)
            conn.execute(executed_sql)
            permissions(conn)
            conn.execute(f"INSERT INTO {LEDGER}(version,name,source_sql,applied_sql,source_sha256,catalog,revision) VALUES(%s,%s,%s,%s,%s,%s,%s)",
                         (version, name, sql, executed_sql, expected_hash, Jsonb(snapshot(conn)), revision))
            state = inspect(conn, sql, migration)
        require(ordinary_history(conn) == before, "regional_history_changed")
    return {"target": target, "version": version, "state": state, "regional_history_unchanged": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", choices=("staging", "use4"))
    parser.add_argument("action", choices=("inspect", "apply"))
    parser.add_argument("--migration", choices=("authority", "claims"), default="authority")
    parser.add_argument("--revision", required=True)
    parser.add_argument("--runtime-project", required=True,
                        help="Previously verified runtime authority project, not an inferred environment label")
    args = parser.parse_args()
    try:
        require(args.runtime_project == regional.PROJECTS[args.target], "runtime_authority_target_mismatch")
        require(subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip() == args.revision,
                "source_revision_mismatch")
        url = regional.migration_connection_url(os.environ.get("DATABASE_URL", ""), args.target)
        with psycopg.connect(url, autocommit=True, connect_timeout=10, options=OPTIONS, sslmode="require") as conn:
            sql = source() if args.migration == "authority" else claim_source()
            result = apply(conn, args.target, args.revision, sql, args.action == "apply", args.migration)
        print(json.dumps(result, sort_keys=True))
    except Exception as error:
        # Driver errors may contain connection details or SQL parameters.
        category = str(error) if isinstance(error, SharedMigrationError) else "database_operation_failed"
        print(json.dumps({"error": category, "next_step": "inspect before retry; never repair history blindly"}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
