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
from psycopg.pq import TransactionStatus

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


APPROVAL_VERSION = "20261020224623"
APPROVAL_NAME = "yc_staff_claim_approval_notification"
APPROVAL_HASH = "fde8a73b8f6aeb1bff110727119cb44c111ede55eb354490a0fb8dddb9a1e114"
APPROVAL_TABLES = ("public.yc_claim_approval_mail", "public.yc_staff_claim_request")
APPROVAL_FUNCTIONS = ("public.yc_staff_claim_rpc(text,jsonb)", "public.yc_claim_approval_mail_rpc(text,jsonb)")

ACCEPTANCE_VERSION = "20261021135531"
ACCEPTANCE_NAME = "yc_offer_acceptance_authority"
ACCEPTANCE_HASH = "d68b1ba9abf38589bf328aeef932f8326d081dfbea19186fe7f9a0840ba09c72"
ACCEPTANCE_TABLES = ("public.yc_offer_acceptance_authority", "public.yc_preferred_identity_review",
    "public.yc_financial_serialization", "public.yc_financial_authorization", "public.yc_financial_invalidation")
ACCEPTANCE_WRITER_TRIGGERS = {
    "yc_financial_auth_writer": "auth.users", "yc_financial_history_writer": "public.yc_claim_identity_history",
    "yc_financial_company_writer": "public.yc_company_activation_authority", "yc_financial_claim_writer": "public.yc_claim",
    "yc_financial_decision_writer": "public.yc_claim_decision",
}
ACCEPTANCE_RPCS = ("public.yc_offer_acceptance_rpc(text,jsonb)", "public.yc_preferred_claim_rpc(text,jsonb)",
                   "public.yc_preferred_staff_rpc(text,jsonb)", "public.yc_financial_authority_rpc(text,jsonb)")
ACCEPTANCE_FUNCTIONS = ACCEPTANCE_RPCS + ("public.yc_offer_acceptance_immutable()",
    "public.yc_preferred_identity_immutable()", "public.yc_preferred_claim_view(public.yc_claim)",
    "public.yc_financial_touch(text)", "public.yc_financial_authorization_immutable()",
    "public.yc_financial_invalidate(text,text,text)", "public.yc_financial_writer()", "public.yc_financial_state(uuid,boolean)")


ACCEPTANCE_HARDENED_FUNCTIONS = (CLAIM_FUNCTIONS[1], *APPROVAL_FUNCTIONS,
    CLAIM_FUNCTIONS[0], RPCS[1], RPCS[3])
ACCEPTANCE_CHANGED_FUNCTIONS = ACCEPTANCE_FUNCTIONS + ACCEPTANCE_HARDENED_FUNCTIONS


MAIL_LEASE_VERSION = "20261022031858"
MAIL_LEASE_NAME = "yc_claim_mail_lease_aliases"
MAIL_LEASE_HASH = "602eb662d8bb53b0e298fdb9e2aea518278718ef985dfa403513c16ab6ce31e1"
MAIL_LEASE_BODY_HASH = "1a95c22740b395df59e14f9164810d53ef07d978ac130341d69cf8fd0c6f08b7"
APPROVAL_SCOPE_VERSION = "20261022232449"
APPROVAL_SCOPE_NAME = "yc_approval_mail_claim_scope"
APPROVAL_SCOPE_HASH = "ce4bb72dcba919e1eae646a89026d4c0195a00fcb13753941d57263396bc949a"
APPROVAL_SCOPE_BODY_HASH = "5f3544387c1f0731454cf82af02dbd63e00aaed107d5dac94c4238edafa93b64"
DEVBOX_BASELINE_HASH = "410eaddeb679e0114fbb667761e8f57e00327f99c9a0f927e4f39cf2023b5424"


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


def approval_source(root=ROOT):
    data = (root / "supabase/shared-auth-migrations" / f"{APPROVAL_VERSION}_{APPROVAL_NAME}.sql").read_bytes()
    require(hashlib.sha256(data).hexdigest() == APPROVAL_HASH, "source_hash_mismatch")
    return data.decode("utf-8")


def approval_execution(sql):
    require(hashlib.sha256(sql.encode()).hexdigest() == APPROVAL_HASH, "source_hash_mismatch")
    prefix = "-- Shared Auth only. Staff eligibility remains separate from customer acceptance.\nBEGIN;\n"
    require(sql.startswith(prefix) and sql.endswith("COMMIT;\n"), "approval_transaction_wrapper_mismatch")
    return sql[len(prefix):-len("COMMIT;\n")]


def approval_objects_present(conn):
    return conn.execute("""SELECT
        EXISTS(SELECT FROM unnest(%s::text[]) t WHERE to_regclass(t) IS NOT NULL)
        OR EXISTS(SELECT FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                  WHERE n.nspname='public' AND p.proname=ANY(%s))
        OR EXISTS(SELECT FROM pg_attribute WHERE attrelid=to_regclass('public.yc_claim')
                  AND attname='acceptance_required' AND NOT attisdropped)""",
        (list(APPROVAL_TABLES), [f.split('.')[1].split('(')[0] for f in APPROVAL_FUNCTIONS])).fetchone()[0]


def acceptance_source(root=ROOT):
    data = (root / "supabase/shared-auth-migrations" / f"{ACCEPTANCE_VERSION}_{ACCEPTANCE_NAME}.sql").read_bytes()
    require(hashlib.sha256(data).hexdigest() == ACCEPTANCE_HASH, "source_hash_mismatch")
    return data.decode("utf-8")


def acceptance_execution(sql):
    require(hashlib.sha256(sql.encode()).hexdigest() == ACCEPTANCE_HASH, "source_hash_mismatch")
    prefix = "-- Shared Auth only. Acceptance is separate from approval and provider execution.\nBEGIN;\n"
    require(sql.startswith(prefix) and sql.endswith("COMMIT;\n"), "acceptance_transaction_wrapper_mismatch")
    return sql[len(prefix):-len("COMMIT;\n")]


def acceptance_objects_present(conn):
    return conn.execute("""SELECT
        EXISTS(SELECT FROM unnest(%s::text[]) t WHERE to_regclass(t) IS NOT NULL)
        OR EXISTS(SELECT FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                  WHERE n.nspname='public' AND p.proname=ANY(%s))""",
        (list(ACCEPTANCE_TABLES), [f.split('.')[1].split('(')[0] for f in ACCEPTANCE_FUNCTIONS])).fetchone()[0]


def acceptance_catalog(conn):
    return {
        "tables": {table: catalog(conn, table, ACCEPTANCE_CHANGED_FUNCTIONS if i == 0 else ())
                   for i, table in enumerate(ACCEPTANCE_TABLES)},
        "writer_triggers": conn.execute("""SELECT jsonb_agg(jsonb_build_array(n.nspname,c.relname,t.tgname,pg_get_triggerdef(t.oid),t.tgenabled) ORDER BY t.tgname)
            FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE t.tgname=ANY(%s::text[]) AND NOT t.tgisinternal""", (list(ACCEPTANCE_WRITER_TRIGGERS),)).fetchone()[0],
        "indexes": conn.execute("""SELECT jsonb_agg(pg_get_indexdef(i.indexrelid) ORDER BY c.relname)
            FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid
            WHERE i.indrelid=ANY(SELECT to_regclass(t) FROM unnest(%s::text[]) t)""",
            (list(ACCEPTANCE_TABLES),)).fetchone()[0],
    }


def verify_acceptance_permissions(conn):
    verify_changed_permissions(conn, "acceptances")


def approval_catalog(conn):
    return {
        "claims": claim_catalog(conn),
        "authority": catalog(conn),
        "tables": {table: catalog(conn, table, APPROVAL_FUNCTIONS if i == 0 else ())
                   for i, table in enumerate(APPROVAL_TABLES)},
        "indexes": conn.execute("""SELECT jsonb_agg(pg_get_indexdef(i.indexrelid) ORDER BY c.relname)
            FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid
            WHERE i.indrelid=ANY(SELECT to_regclass(t) FROM unnest(%s::text[]) t)""",
            (list(APPROVAL_TABLES),)).fetchone()[0],
    }


def verify_approval_permissions(conn):
    verify_claim_permissions(conn)
    for table in APPROVAL_TABLES:
        require(conn.execute("SELECT relkind='r' AND relrowsecurity AND relowner='postgres'::regrole "
                             "FROM pg_class WHERE oid=%s::regclass", (table,)).fetchone()[0],
                "approval_table_security_mismatch")
        for role in ROLES:
            require(not conn.execute("SELECT has_table_privilege(%s,%s,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') "
                                     "OR has_any_column_privilege(%s,%s,'SELECT,INSERT,UPDATE,REFERENCES')",
                                     (role, table, role, table)).fetchone()[0], "approval_table_privileges_mismatch")
    for function in APPROVAL_FUNCTIONS:
        for role in ROLES:
            allowed = conn.execute("SELECT has_function_privilege(%s,%s,'EXECUTE')", (role, function)).fetchone()[0]
            require(allowed == (role == "promotion_evidence_proxy"), "approval_rpc_privileges_mismatch")


def predecessor_acceptance_catalog(current):
    # Compare prior receipts using only the six exact search_path changes. The
    # acceptance receipt pins their complete hardened definitions and ACLs.
    signatures = {f.replace("public.", "") for f in ACCEPTANCE_HARDENED_FUNCTIONS}
    def visit(value):
        if isinstance(value, dict):
            if value.get("triggers"):
                value["triggers"] = [row for row in value["triggers"] if row[0] not in ACCEPTANCE_WRITER_TRIGGERS] or None
            for function in value.get("functions") or ():
                if function[0] in signatures:
                    for path in ("'pg_catalog', 'public', 'auth'", "'pg_catalog', 'public'"):
                        function[1] = function[1].replace(
                            "SET search_path TO " + path + ", 'pg_temp'\n",
                            "SET search_path TO " + path + "\n", 1)
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)
    visit(current)
    return current


def predecessor_claim_catalog(conn, recorded):
    # Preserve the original receipt while allowing only this migration's two
    # deliberate replacements. The approval receipt verifies the full new view
    # and column, including all other claim definitions and privileges.
    current = claim_catalog(conn)
    table = current["tables"]["public.yc_claim"]
    table["columns"] = [column for column in table["columns"] if column[0] != "acceptance_required"]
    prior_functions = recorded["tables"]["public.yc_claim"]["functions"]
    for function in table["functions"]:
        if function[0] == "yc_claim_view(yc_claim)":
            old = next(f for f in prior_functions if f[0] == function[0])
            function[1] = old[1]
    return current


def predecessor_authority_catalog(conn, recorded):
    # Only these two function bodies change; attributes and ACLs still match the
    # original receipt. The approval receipt independently pins both new bodies.
    current = catalog(conn)
    replaced = {"reserve_yc_activation_authority(text,uuid,text,uuid,text,text,uuid)",
                "lock_yc_activation_authority(uuid,uuid,text)"}
    for function in current["functions"]:
        if function[0] in replaced:
            function[1] = next(f[1] for f in recorded["functions"] if f[0] == function[0])
    return current


def mail_lease_source(root=ROOT):
    data = (root / "supabase/shared-auth-migrations" / f"{MAIL_LEASE_VERSION}_{MAIL_LEASE_NAME}.sql").read_bytes()
    require(hashlib.sha256(data).hexdigest() == MAIL_LEASE_HASH, "source_hash_mismatch")
    return data.decode("utf-8")


def mail_lease_execution(sql):
    require(hashlib.sha256(sql.encode()).hexdigest() == MAIL_LEASE_HASH, "source_hash_mismatch")
    prefix = "-- Shared Auth only. Preserve the existing claim RPC attributes and privileges.\nBEGIN;\n"
    require(sql.startswith(prefix) and sql.endswith("COMMIT;\n"), "mail_lease_transaction_wrapper_mismatch")
    return sql[len(prefix):-len("COMMIT;\n")]


def mail_lease_objects_present(conn):
    return conn.execute("SELECT EXISTS (SELECT FROM pg_proc WHERE oid=to_regprocedure(%s) "
                        "AND encode(sha256(convert_to(prosrc,'UTF8')),'hex')=%s)",
                        (CLAIM_FUNCTIONS[1], MAIL_LEASE_BODY_HASH)).fetchone()[0]


def mail_lease_catalog(conn):
    return {"functions": conn.execute("""SELECT jsonb_agg(jsonb_build_array(
        p.oid::regprocedure::text,pg_get_functiondef(p.oid),pg_get_userbyid(p.proowner),p.proacl))
        FROM pg_proc p WHERE p.oid=to_regprocedure(%s)""", (CLAIM_FUNCTIONS[1],)).fetchone()[0]}


def verify_mail_lease_permissions(conn):
    verify_changed_permissions(conn, "claim-mail")


def claim_rpc_definitions(value):
    if isinstance(value, dict):
        for function in value.get("functions") or ():
            if function[0] == "yc_claim_rpc(text,jsonb)":
                yield function
        for child in value.values():
            yield from claim_rpc_definitions(child)
    elif isinstance(value, list):
        for child in value:
            yield from claim_rpc_definitions(child)


def verify_mail_lease_predecessor(conn, versions):
    version = (ACCEPTANCE_VERSION if ACCEPTANCE_VERSION in versions else
               APPROVAL_VERSION if APPROVAL_VERSION in versions else CLAIM_VERSION)
    recorded = conn.execute(f"SELECT catalog FROM {LEDGER} WHERE version=%s", (version,)).fetchone()[0]
    expected = list(claim_rpc_definitions(recorded))
    require(len(expected) == 1 and mail_lease_catalog(conn)["functions"] == expected,
            "mail_lease_predecessor_mismatch")


def predecessor_mail_lease_catalog(current, recorded):
    # Later receipts may already include the fix. Reverse only the exact branch
    # when comparing against a receipt that predates it; never rewrite receipts.
    sql = mail_lease_source()
    original = sql.split("$original$", 2)[1]
    corrected = sql.split("$corrected$", 2)[1]
    restore = any(original in function[1] for function in claim_rpc_definitions(recorded))
    for function in claim_rpc_definitions(current):
        require(function[1].count(corrected) == 1, "mail_lease_function_mismatch")
        if restore:
            function[1] = function[1].replace(corrected, original, 1)
    return current


def ordinary_history(conn):
    return conn.execute("SELECT version,name,statements FROM supabase_migrations.schema_migrations ORDER BY version").fetchall()


def approval_scope_source(root=ROOT):
    data = (root / "supabase/shared-auth-migrations" / f"{APPROVAL_SCOPE_VERSION}_{APPROVAL_SCOPE_NAME}.sql").read_bytes()
    require(hashlib.sha256(data).hexdigest() == APPROVAL_SCOPE_HASH, "source_hash_mismatch")
    return data.decode("utf-8")


def approval_scope_execution(sql):
    require(hashlib.sha256(sql.encode()).hexdigest() == APPROVAL_SCOPE_HASH, "source_hash_mismatch")
    prefix = "-- Shared Auth only. Preserve the existing approval mail RPC attributes and privileges.\nBEGIN;\n"
    require(sql.startswith(prefix) and sql.endswith("COMMIT;\n"), "approval_scope_transaction_wrapper_mismatch")
    return sql[len(prefix):-len("COMMIT;\n")]


def approval_scope_objects_present(conn):
    return conn.execute("SELECT EXISTS (SELECT FROM pg_proc WHERE oid=to_regprocedure(%s) "
                        "AND encode(sha256(convert_to(prosrc,'UTF8')),'hex')=%s)",
                        (APPROVAL_FUNCTIONS[1], APPROVAL_SCOPE_BODY_HASH)).fetchone()[0]


def approval_scope_catalog(conn):
    return {"functions": conn.execute("""SELECT jsonb_agg(jsonb_build_array(
        p.oid::regprocedure::text,pg_get_functiondef(p.oid),pg_get_userbyid(p.proowner),p.proacl))
        FROM pg_proc p WHERE p.oid=to_regprocedure(%s)""", (APPROVAL_FUNCTIONS[1],)).fetchone()[0]}


def verify_approval_scope_permissions(conn):
    verify_changed_permissions(conn, "approval-mail-scope")


def approval_mail_definitions(value):
    if isinstance(value, dict):
        for function in value.get("functions") or ():
            if function[0] == "yc_claim_approval_mail_rpc(text,jsonb)":
                yield function
        for child in value.values():
            yield from approval_mail_definitions(child)
    elif isinstance(value, list):
        for child in value:
            yield from approval_mail_definitions(child)


def verify_approval_scope_predecessor(conn):
    recorded = conn.execute(f"SELECT catalog FROM {LEDGER} WHERE version=%s", (ACCEPTANCE_VERSION,)).fetchone()[0]
    expected = list(approval_mail_definitions(recorded))
    require(len(expected) == 1 and approval_scope_catalog(conn)["functions"] == expected,
            "approval_scope_predecessor_mismatch")


def predecessor_approval_scope_catalog(current):
    sql = approval_scope_source()
    original, scoped = sql.split("$original$", 2)[1], sql.split("$scoped$", 2)[1]
    for function in approval_mail_definitions(current):
        require(function[1].count(scoped) == 1, "approval_scope_function_mismatch")
        function[1] = function[1].replace(scoped, original, 1)
    return current


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
    require(not any(row[0] in (VERSION, CLAIM_VERSION, APPROVAL_VERSION, ACCEPTANCE_VERSION, MAIL_LEASE_VERSION, APPROVAL_SCOPE_VERSION) for row in rows), "shared_version_in_regional_history")
    aggregate = [row for row in rows if row[0] == regional.VERSION]
    if target == "devbox":
        require(len(aggregate) == 1 and aggregate[0][1] == regional.NAME
                and hashlib.sha256(json.dumps(aggregate[0][2], separators=(",", ":"),
                                               ensure_ascii=False).encode()).hexdigest() == DEVBOX_BASELINE_HASH,
                "historical_aggregate_mismatch")
    elif target == "use4":
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
    approval_sql = sql if migration == "approvals" else approval_source()
    acceptance_sql = sql if migration == "acceptances" else acceptance_source()
    mail_sql = sql if migration == "claim-mail" else mail_lease_source()
    scope_sql = sql if migration == "approval-mail-scope" else approval_scope_source()
    definitions = {
        VERSION: (NAME, authority_sql, authority_sql + ACL_SQL, SOURCE_HASH, objects_present, verify_permissions, catalog),
        CLAIM_VERSION: (CLAIM_NAME, claim_sql, claim_execution(claim_sql), CLAIM_HASH,
                        claim_objects_present, verify_claim_permissions, claim_catalog),
        APPROVAL_VERSION: (APPROVAL_NAME, approval_sql, approval_execution(approval_sql), APPROVAL_HASH,
                           approval_objects_present, verify_approval_permissions, approval_catalog),
        ACCEPTANCE_VERSION: (ACCEPTANCE_NAME, acceptance_sql, acceptance_execution(acceptance_sql), ACCEPTANCE_HASH,
                             acceptance_objects_present, verify_acceptance_permissions, acceptance_catalog),
        MAIL_LEASE_VERSION: (MAIL_LEASE_NAME, mail_sql, mail_lease_execution(mail_sql), MAIL_LEASE_HASH,
                             mail_lease_objects_present, verify_mail_lease_permissions, mail_lease_catalog),
        APPROVAL_SCOPE_VERSION: (APPROVAL_SCOPE_NAME, scope_sql, approval_scope_execution(scope_sql), APPROVAL_SCOPE_HASH,
                                 approval_scope_objects_present, verify_approval_scope_permissions, approval_scope_catalog),
    }
    if not ledger_exists(conn):
        require(not objects_present(conn) and not claim_objects_present(conn) and not approval_objects_present(conn) and not acceptance_objects_present(conn), "schema_without_shared_history")
        return "pending"
    rows = conn.execute(f"SELECT version,name,source_sql,applied_sql,source_sha256,catalog,revision FROM {LEDGER} ORDER BY version").fetchall()
    versions = {row[0] for row in rows}
    require(len(versions) == len(rows) and versions <= definitions.keys(), "unknown_shared_history")
    require(CLAIM_VERSION not in versions or VERSION in versions, "claim_authority_history_missing")
    require(APPROVAL_VERSION not in versions or CLAIM_VERSION in versions, "approval_claim_history_missing")
    require(ACCEPTANCE_VERSION not in versions or APPROVAL_VERSION in versions, "acceptance_approval_history_missing")
    require(MAIL_LEASE_VERSION not in versions or CLAIM_VERSION in versions, "mail_lease_claim_history_missing")
    require(APPROVAL_SCOPE_VERSION not in versions or ACCEPTANCE_VERSION in versions, "approval_scope_acceptance_history_missing")
    for version, name, stored_sql, applied_sql, stored_hash, stored_catalog, revision in rows:
        expected_name, original, executed, expected_hash, present, permissions, snapshot = definitions[version]
        require(name == expected_name and stored_sql == original and applied_sql == executed and stored_hash == expected_hash
                and re.fullmatch(r"[a-f0-9]{40}", revision), "shared_history_mismatch")
        require(present(conn), "shared_schema_missing")
        permissions(conn)
        if APPROVAL_VERSION in versions and version == CLAIM_VERSION:
            actual = predecessor_claim_catalog(conn, stored_catalog)
        elif APPROVAL_VERSION in versions and version == VERSION:
            actual = predecessor_authority_catalog(conn, stored_catalog)
        else:
            actual = snapshot(conn)
        if APPROVAL_SCOPE_VERSION in versions and version != APPROVAL_SCOPE_VERSION:
            actual = predecessor_approval_scope_catalog(actual)
        if ACCEPTANCE_VERSION in versions and version not in (ACCEPTANCE_VERSION, APPROVAL_SCOPE_VERSION):
            # The optional mail fix can be applied before or after hardening.
            mail_already_hardened = (version == MAIL_LEASE_VERSION and
                "SET search_path TO 'pg_catalog', 'public', 'auth', 'pg_temp'\n" in stored_catalog["functions"][0][1])
            if not mail_already_hardened:
                actual = predecessor_acceptance_catalog(actual)
        if MAIL_LEASE_VERSION in versions and version != MAIL_LEASE_VERSION:
            actual = predecessor_mail_lease_catalog(actual, stored_catalog)
        require(actual == stored_catalog, "shared_catalog_mismatch")
    for version, definition in definitions.items():
        if version not in versions:
            require(not definition[4](conn), "schema_without_shared_history")
    selected = {"authority": VERSION, "claims": CLAIM_VERSION, "approvals": APPROVAL_VERSION, "acceptances": ACCEPTANCE_VERSION, "claim-mail": MAIL_LEASE_VERSION, "approval-mail-scope": APPROVAL_SCOPE_VERSION}[migration]
    return "applied" if selected in versions else "pending"


def receipt_ledger_exists(conn):
    privileged, schema, table = conn.execute(
        "SELECT current_user='postgres' AND session_user='postgres' "
        "AND current_setting('server_version_num')::int>=170000, "
        "to_regnamespace('shared_auth_migrations') IS NOT NULL, to_regclass(%s) IS NOT NULL",
        (LEDGER,)).fetchone()
    require(privileged, "privileged_postgres_session_required")
    require(schema == table, "partial_shared_ledger")
    return table


def receipt_versions(conn):
    # The private ledger is authoritative during deployment; drift audits are explicit.
    authority, claims, approvals, acceptances = source(), claim_source(), approval_source(), acceptance_source()
    mail = mail_lease_source()
    scope = approval_scope_source()
    expected = {
        VERSION: (NAME, authority, authority + ACL_SQL, SOURCE_HASH),
        CLAIM_VERSION: (CLAIM_NAME, claims, claim_execution(claims), CLAIM_HASH),
        APPROVAL_VERSION: (APPROVAL_NAME, approvals, approval_execution(approvals), APPROVAL_HASH),
        ACCEPTANCE_VERSION: (ACCEPTANCE_NAME, acceptances, acceptance_execution(acceptances), ACCEPTANCE_HASH),
        MAIL_LEASE_VERSION: (MAIL_LEASE_NAME, mail, mail_lease_execution(mail), MAIL_LEASE_HASH),
        APPROVAL_SCOPE_VERSION: (APPROVAL_SCOPE_NAME, scope, approval_scope_execution(scope), APPROVAL_SCOPE_HASH),
    }
    rows = conn.execute(f"SELECT version,name,source_sql,applied_sql,source_sha256,revision FROM {LEDGER} ORDER BY version").fetchall()
    versions = {row[0] for row in rows}
    require(len(versions) == len(rows) and versions <= expected.keys(), "unknown_shared_history")
    require(CLAIM_VERSION not in versions or VERSION in versions, "claim_authority_history_missing")
    require(APPROVAL_VERSION not in versions or CLAIM_VERSION in versions, "approval_claim_history_missing")
    require(ACCEPTANCE_VERSION not in versions or APPROVAL_VERSION in versions, "acceptance_approval_history_missing")
    require(MAIL_LEASE_VERSION not in versions or CLAIM_VERSION in versions, "mail_lease_claim_history_missing")
    require(APPROVAL_SCOPE_VERSION not in versions or ACCEPTANCE_VERSION in versions, "approval_scope_acceptance_history_missing")
    for version, name, original, executed, digest, revision in rows:
        require((name, original, executed, digest) == expected[version]
                and re.fullmatch(r"[a-f0-9]{40}", revision), "shared_history_mismatch")
    return versions


def verify_changed_permissions(conn, migration, created_ledger=False):
    tables, functions = {
        "authority": ((TABLE,), FUNCTIONS),
        "claims": (CLAIM_TABLES, CLAIM_FUNCTIONS),
        "approvals": (APPROVAL_TABLES + ("public.yc_claim",), APPROVAL_FUNCTIONS + (CLAIM_FUNCTIONS[0], RPCS[1], RPCS[3])),
        "acceptances": (ACCEPTANCE_TABLES, ACCEPTANCE_CHANGED_FUNCTIONS),
        "claim-mail": ((), (CLAIM_FUNCTIONS[1],)),
        "approval-mail-scope": ((), (APPROVAL_FUNCTIONS[1],)),
    }[migration]
    valid = conn.execute("""
      WITH tables AS (SELECT unnest(%s::text[]) AS name),
           functions AS (SELECT unnest(%s::text[]) AS name),
           roles AS (SELECT unnest(%s::text[]) AS name)
      SELECT
        NOT EXISTS (SELECT FROM tables t LEFT JOIN pg_class c ON c.oid=to_regclass(t.name)
                    WHERE c.oid IS NULL OR c.relkind<>'r' OR NOT c.relrowsecurity
                       OR c.relowner<>'postgres'::regrole)
        AND NOT EXISTS (
          SELECT FROM tables t CROSS JOIN roles r
          CROSS JOIN unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER']) p
          WHERE has_table_privilege(r.name,t.name,p) <>
                (t.name='public.yc_company_activation_authority' AND r.name='service_role'
                 AND p IN ('SELECT','INSERT','UPDATE')))
        AND NOT EXISTS (
          SELECT FROM tables t CROSS JOIN roles r
          CROSS JOIN unnest(ARRAY['SELECT','INSERT','UPDATE','REFERENCES']) p
          WHERE has_any_column_privilege(r.name,t.name,p) <>
                (t.name='public.yc_company_activation_authority' AND r.name='service_role'
                 AND p IN ('SELECT','INSERT','UPDATE')))
        AND NOT EXISTS (SELECT FROM functions f LEFT JOIN pg_proc p ON p.oid=to_regprocedure(f.name)
                        WHERE p.oid IS NULL OR p.proowner<>'postgres'::regrole)
        AND NOT EXISTS (
          SELECT FROM functions f CROSS JOIN roles r
          WHERE has_function_privilege(r.name,f.name,'EXECUTE') <>
            ((f.name=ANY(%s::text[]) AND r.name IN ('service_role','promotion_evidence_proxy'))
             OR (f.name=ANY(%s::text[]) AND r.name='promotion_evidence_proxy')))
        AND (%s<>'claims' OR EXISTS (
          SELECT FROM pg_trigger WHERE tgrelid=to_regclass('auth.users')
            AND tgname='yc_claim_auth_lifecycle' AND tgenabled='O' AND NOT tgisinternal))
        AND (NOT %s OR NOT EXISTS (
          SELECT FROM roles r
          WHERE has_schema_privilege(r.name,'shared_auth_migrations','USAGE,CREATE')
             OR has_table_privilege(r.name,%s,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')))
    """, (list(tables), list(functions), list(ROLES), list(RPCS),
          [CLAIM_FUNCTIONS[1], *APPROVAL_FUNCTIONS, *ACCEPTANCE_RPCS], migration, created_ledger, LEDGER)).fetchone()[0]
    require(valid, "migration_privileges_mismatch")


def apply_bound_devbox_claim_mail(conn, revision, *, system_identifier, database_oid, server_port,
                                  database_name="postgres", execute=False):
    require(conn.autocommit and conn.info.transaction_status == TransactionStatus.IDLE,
            "idle_autocommit_connection_required")
    # The operator verifies the VM/runtime binding before opening this connection.
    # This entry permits only the selected additive repair on that exact database.
    require(re.fullmatch(r"[0-9]+", system_identifier or "") and
            re.fullmatch(r"[0-9]+", database_oid or "") and
            isinstance(server_port, int) and 1 <= server_port <= 65535 and
            isinstance(database_name, str) and bool(database_name),
            "invalid_database_binding")
    require(conn.info.host in ("127.0.0.1", "::1") and
            conn.info.hostaddr in ("127.0.0.1", "::1"), "local_connection_required")
    actual = conn.execute("""SELECT current_database(),current_user,session_user,
        (SELECT system_identifier::text FROM pg_control_system()),
        (SELECT oid::text FROM pg_database WHERE datname=current_database()),inet_server_port(),
        current_setting('server_version_num')::int>=170000""").fetchone()
    require(actual == (database_name, "postgres", "postgres", system_identifier, database_oid, server_port, True),
            "database_identity_mismatch")
    prerequisites(conn, "devbox")
    return _apply(conn, "devbox", revision, mail_lease_source(), execute, "claim-mail")


def apply(conn, target, revision, sql, execute=False, migration="authority"):
    require(target in ("staging", "use4"), "unsupported_auth_target")
    return _apply(conn, target, revision, sql, execute, migration)


def _apply(conn, target, revision, sql, execute=False, migration="authority"):
    require(re.fullmatch(r"[a-f0-9]{40}", revision), "invalid_revision")
    require(migration in ("authority", "claims", "approvals", "acceptances", "claim-mail", "approval-mail-scope"), "unsupported_shared_migration")
    version, name, expected_hash, executed_sql, snapshot = (
        (VERSION, NAME, SOURCE_HASH, sql + ACL_SQL, catalog) if migration == "authority" else
        (CLAIM_VERSION, CLAIM_NAME, CLAIM_HASH, claim_execution(sql), claim_catalog) if migration == "claims" else
        (APPROVAL_VERSION, APPROVAL_NAME, APPROVAL_HASH, approval_execution(sql), approval_catalog) if migration == "approvals" else
        (ACCEPTANCE_VERSION, ACCEPTANCE_NAME, ACCEPTANCE_HASH, acceptance_execution(sql), acceptance_catalog) if migration == "acceptances" else
        (MAIL_LEASE_VERSION, MAIL_LEASE_NAME, MAIL_LEASE_HASH, mail_lease_execution(sql), mail_lease_catalog) if migration == "claim-mail" else
        (APPROVAL_SCOPE_VERSION, APPROVAL_SCOPE_NAME, APPROVAL_SCOPE_HASH, approval_scope_execution(sql), approval_scope_catalog))
    require(hashlib.sha256(sql.encode()).hexdigest() == expected_hash, "source_hash_mismatch")
    result = {"target": target, "version": version, "state": "applied", "regional_history_unchanged": True}
    if not execute:
        with conn.transaction():
            conn.execute("SET TRANSACTION READ ONLY")
            before = prerequisites(conn, target)
            result["state"] = inspect(conn, sql, migration)
            require(ordinary_history(conn) == before, "regional_history_changed")
        return result

    exists = receipt_ledger_exists(conn)
    versions = receipt_versions(conn) if exists else set()
    if version in versions:
        return result
    with conn.transaction():
        require(conn.execute("SELECT pg_try_advisory_xact_lock(%s)", (MUTEX,)).fetchone()[0], "shared_migration_busy")
        # A different executor may have committed since the unlocked receipt read.
        if not exists:
            exists = receipt_ledger_exists(conn)
        versions = receipt_versions(conn) if exists else set()
        if version not in versions:
            if migration == "claims":
                require(VERSION in versions, "authority_migration_required")
            if migration in ("approvals", "claim-mail"):
                require(CLAIM_VERSION in versions, "claims_migration_required")
            if migration == "acceptances":
                require(APPROVAL_VERSION in versions, "approvals_migration_required")
            if migration == "approval-mail-scope":
                require(ACCEPTANCE_VERSION in versions, "acceptances_migration_required")
            roles, auth = conn.execute(
                "SELECT (SELECT count(*) FROM pg_roles WHERE rolname=ANY(%s)), "
                "to_regclass('auth.users') IS NOT NULL", (list(ROLES),)).fetchone()
            require(roles == len(ROLES), "required_roles_missing")
            require(migration == "authority" or auth, "existing_auth_setup_required")
            before = prerequisites(conn, target) if target == "devbox" else ordinary_history(conn)
            require(not any(row[0] in (VERSION, CLAIM_VERSION, APPROVAL_VERSION, ACCEPTANCE_VERSION, MAIL_LEASE_VERSION, APPROVAL_SCOPE_VERSION) for row in before),
                    "shared_version_in_regional_history")
            if not exists:
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
            if migration == "claim-mail":
                verify_mail_lease_predecessor(conn, versions)
            if migration == "approval-mail-scope":
                verify_approval_scope_predecessor(conn)
            conn.execute(executed_sql)
            verify_changed_permissions(conn, migration, created_ledger=not exists)
            conn.execute(f"INSERT INTO {LEDGER}(version,name,source_sql,applied_sql,source_sha256,catalog,revision) VALUES(%s,%s,%s,%s,%s,%s,%s)",
                         (version, name, sql, executed_sql, expected_hash, Jsonb(snapshot(conn)), revision))
            require(ordinary_history(conn) == before, "regional_history_changed")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", choices=("staging", "use4"))
    parser.add_argument("action", choices=("inspect", "apply"))
    parser.add_argument("--migration", choices=("authority", "claims", "approvals", "acceptances", "claim-mail", "approval-mail-scope"), default="authority")
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
            sql = {"authority": source, "claims": claim_source, "approvals": approval_source, "acceptances": acceptance_source, "claim-mail": mail_lease_source, "approval-mail-scope": approval_scope_source}[args.migration]()
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
