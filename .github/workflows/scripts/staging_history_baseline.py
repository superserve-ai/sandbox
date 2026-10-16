"""Catalog evidence for an explicitly reviewed staging history baseline."""

import hashlib
import json

from migration_gate import GateError


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def require(condition, message):
    if not condition:
        raise GateError(message)


# Collect catalog evidence in one round trip within the existing short read-only
# transaction. No application rows or role passwords are read by this query.
CATALOG_SQL = """
SELECT json_build_object(
 'constraints', (SELECT json_agg(r ORDER BY r.relname,r.conname) FROM (
   SELECT cl.relname,c.conname,c.convalidated,pg_get_constraintdef(c.oid)
   FROM pg_constraint c JOIN pg_class cl ON cl.oid=c.conrelid
   WHERE cl.relnamespace='public'::regnamespace AND
   (cl.relname='template' AND c.conname IN ('template_vcpu_range','template_memory_range','template_disk_range')
    OR cl.relname='sandbox' AND c.conname LIKE 'sandbox_preview_%%')) r),
 'legacy_columns', (SELECT json_agg(r ORDER BY r.attname) FROM (
   SELECT a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,pg_get_expr(d.adbin,d.adrelid)
   FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
   WHERE a.attrelid='public.sandbox'::regclass AND NOT a.attisdropped
   AND a.attname IN ('preview_access','preview_token_version')) r),
 'preview_tables', (SELECT json_agg(r ORDER BY r.relname) FROM (
   SELECT relname,relrowsecurity,relforcerowsecurity FROM pg_class
   WHERE relnamespace='public'::regnamespace AND relname IN ('sandbox_preview_policy','sandbox_published_port')) r),
 'indexes', (SELECT json_agg(r ORDER BY r.relname) FROM (
   SELECT c.relname,i.indisvalid,i.indisready,i.indisunique,pg_get_indexdef(i.indexrelid)
   FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid
   WHERE c.relnamespace='public'::regnamespace
   AND c.relname IN ('template_name_unique_per_team_active','sandbox_by_source_snapshot')) r),
 'source_snapshot_fk', (SELECT json_agg(r) FROM (
   SELECT conname,convalidated,pg_get_constraintdef(oid) FROM pg_constraint
   WHERE conname='sandbox_source_snapshot_fk' AND conrelid='public.sandbox'::regclass) r),
 'columns', (SELECT json_agg(r ORDER BY r.attname) FROM (
   SELECT attname,format_type(atttypid,atttypmod),attnotnull FROM pg_attribute
   WHERE NOT attisdropped AND (attrelid='public.template'::regclass AND attname IN ('name','alias')
    OR attrelid='public.sandbox'::regclass AND attname='source_snapshot_id')) r),
 'grafana_role', (SELECT json_agg(r) FROM (
   SELECT rolname,rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls
   FROM pg_roles WHERE rolname='grafana_readonly') r),
 'analytics_grants', (SELECT json_build_array(
   has_schema_privilege('grafana_readonly','analytics','USAGE'),
   bool_and(has_table_privilege('grafana_readonly',c.oid,'SELECT')))
   FROM pg_class c WHERE c.relnamespace='analytics'::regnamespace AND c.relkind IN ('r','v','m','p')),
 'triggers', (SELECT json_agg(r ORDER BY r.relname,r.tgname) FROM (
   SELECT c.relname,t.tgname,t.tgenabled,p.proname,pg_get_triggerdef(t.oid)
   FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_proc p ON p.oid=t.tgfoid
   WHERE NOT t.tgisinternal AND c.relnamespace='public'::regnamespace
   AND p.pronamespace='public'::regnamespace AND p.proname=ANY(%s)) r),
 'functions', (SELECT json_agg(r ORDER BY r.proname) FROM (
   SELECT p.proname,pg_get_function_identity_arguments(p.oid) AS arguments,p.prosrc,l.lanname,p.prosecdef,
          p.provolatile,pg_get_function_result(p.oid),p.proconfig
   FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang
   WHERE p.pronamespace='public'::regnamespace AND p.proname=ANY(%s)) r)
)
"""


def catalog_state(conn, policy):
    names = sorted(policy['functions'])
    result = conn.execute(CATALOG_SQL, (names, names)).fetchone()[0]
    # json_agg(record) preserves named fields; policy rows use their query order.
    return {key: ([list(row.values()) for row in value] if key != 'analytics_grants' and value is not None
                  else value) for key, value in result.items()}


def check_catalog(catalog, policy, root, *, applied=False):
    expected = policy['catalog']
    require({k: v for k, v in catalog.items() if k != 'functions'} == expected,
            'Historical baseline catalog differs from reviewed effects')
    functions = dict(policy['functions'])
    if applied:
        functions.update(policy['applied_functions'])
    wanted = []
    for name, spec in sorted(functions.items()):
        path = root / spec['source']
        require(hashlib.sha256(path.read_bytes()).hexdigest() == spec['source_sha256'],
                'Historical baseline function source changed')
        wanted.append([name, spec['arguments'], spec['body_sha256'], spec['language'], spec['security_definer'],
                       spec['volatility'], spec['result'], spec['configuration']])
    actual = [[name, args, digest(body), *attributes]
              for name, args, body, *attributes in catalog['functions'] or []]
    require(actual == wanted, 'Historical baseline billing or snapshot function differs')
    return digest(dict(catalog, functions=actual))
