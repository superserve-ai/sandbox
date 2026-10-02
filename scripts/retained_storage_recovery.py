"""Execute the fixed retained-storage recovery without rewriting applied history."""

import contextlib
import hashlib
import json
import time

import psycopg
from psycopg.types.json import Jsonb
from psycopg.sql import Literal

import migrate_database as migration

PLAN = "retained-storage-v1"
FIRST = "20261003010001"
LAST = "20261003010024"
MUTEX = 6834211091020401
RECOVERY_TIMEOUT = 180
PREPARATIONS = ("host", "storage_index", "reason", "validated_reason", "owner_index", "snapshot_index")
INDEXES = {
    "storage_index": (0, "sandbox_storage_interval", "sandbox_storage_interval_host_window",
                      "host_id,started_at,ended_at"),
    "owner_index": (13, "sandbox", "sandbox_retained_receiver_host_lifetime",
                    "host_id,created_at,destroyed_at,id"),
    "snapshot_index": (13, "sandbox_snapshot", "sandbox_snapshot_retained_receiver_host_lifetime",
                       "host_id,created_at,deleted_at,retention_ended_at,id"),
}
CANDIDATE = "storage_reason_recovery_candidate"
CATALOG_SQL = """
WITH objects AS (
 SELECT 'column:'||c.relname||'.'||a.attname key,
 jsonb_build_array(format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attidentity,
                  pg_get_expr(d.adbin,d.adrelid),a.attgenerated) value
 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid
 JOIN pg_namespace n ON n.oid=c.relnamespace
 LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum
 WHERE n.nspname='public' AND c.relkind IN('r','p') AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL
 SELECT 'constraint:'||c.relname||'.'||k.conname,
 jsonb_build_array(pg_get_constraintdef(k.oid),k.convalidated,k.condeferrable,k.condeferred)
 FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid
 JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'
 UNION ALL
 SELECT 'index:'||c.relname, jsonb_build_array(pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready,i.indislive)
 FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid
 JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'
 UNION ALL
 SELECT 'function:'||p.oid::regprocedure::text,jsonb_build_array(pg_get_functiondef(p.oid))
 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname='public' AND p.prokind='f'
 UNION ALL
 SELECT 'trigger:'||c.relname||'.'||t.tgname,jsonb_build_array(pg_get_triggerdef(t.oid),t.tgenabled)
 FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
 JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND NOT t.tgisinternal
 UNION ALL
 SELECT 'table:'||c.relname,jsonb_build_array(c.relkind,c.relrowsecurity,c.relforcerowsecurity)
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND c.relkind IN('r','p')
) SELECT COALESCE(jsonb_object_agg(key,value),'{}'::jsonb) FROM objects
"""
HISTORY_GUARD = "SELECT md5(COALESCE(jsonb_agg(jsonb_build_array(version,name,statements) ORDER BY version),'[]'::jsonb)::text) FROM supabase_migrations.schema_migrations"
RECEIPT_GUARD = "SELECT md5(COALESCE(jsonb_object_agg(name,jsonb_build_array(state,evidence)),'{}'::jsonb)::text) FROM migration_recovery.preparation"
HISTORY_SQL = "SELECT version,name,statements FROM supabase_migrations.schema_migrations ORDER BY version"
JOURNAL_SQL = """
CREATE SCHEMA migration_recovery;
REVOKE ALL ON SCHEMA migration_recovery FROM PUBLIC;
CREATE TABLE migration_recovery.plan (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 plan_hash text NOT NULL, predecessor_hash text NOT NULL,
 complete boolean NOT NULL DEFAULT false
);
CREATE TABLE migration_recovery.preparation (
 name text PRIMARY KEY, state text NOT NULL CHECK(state IN('intent','dropping','ready')),
 evidence jsonb NOT NULL
);
REVOKE ALL ON ALL TABLES IN SCHEMA migration_recovery FROM PUBLIC;
"""


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def require(condition, message):
    if not condition:
        raise migration.MigrationError(message)


def render(sources):
    """Only exact, hash-pinned source fragments may be replaced."""
    first = sources[FIRST]
    host = "ALTER TABLE sandbox_storage_interval ADD COLUMN host_id text;"
    start = first.index("CREATE FUNCTION stamp_sandbox_storage_interval_host()")
    end = first.index("CREATE INDEX sandbox_storage_interval_host_window")
    stamp = first[start:end]
    output = dict(sources)
    def remove(version, fragment):
        require(output[version].count(fragment) == 1, "Recovery source fragment changed")
        output[version] = output[version].replace(fragment, "")
    remove(FIRST, host)
    remove(FIRST, stamp)
    remove(FIRST, "CREATE INDEX sandbox_storage_interval_host_window ON sandbox_storage_interval(host_id,started_at,ended_at);")
    third = "20261003010003"
    start = output[third].index("ALTER TABLE sandbox_storage_interval")
    end = output[third].index("-- Preserve the legacy")
    output[third] = output[third][:start] + (
        "ALTER TABLE sandbox_storage_interval DROP CONSTRAINT sandbox_storage_interval_reason_valid;\n"
        f"ALTER TABLE sandbox_storage_interval RENAME CONSTRAINT {CANDIDATE} TO sandbox_storage_interval_reason_valid;\n\n"
    ) + output[third][end:]
    for phase in ("owner_index", "snapshot_index"):
        _, table, name, columns = INDEXES[phase]
        remove("20261003010014", f"CREATE INDEX {name}\n  ON {table}({columns});")
    # Preparation/catalog checks run on the CLI session before it executes one
    # migration. The receipt and its truthful SQL are committed with CLI history.
    for version in (FIRST, third, "20261003010014"):
        output[version] += "\nUPDATE migration_recovery.plan SET complete=false WHERE singleton;\n"
    return output, host + "\n" + stamp


def load_plan(root):
    path = root / "supabase/recovery" / (PLAN + ".json")
    manifest = json.loads(path.read_text())
    sources, names = {}, {}
    for name, expected in manifest["sources"].items():
        data = (root / "supabase/migrations" / name).read_bytes()
        require(hashlib.sha256(data).hexdigest() == expected, "Recovery source hash mismatch")
        version = name.split("_", 1)[0]
        if FIRST <= version <= LAST:
            sources[version], names[version] = data.decode(), name
    require(len(sources) == 24, "Recovery requires the pinned 24 migrations")
    overlays, host_sql = render(sources)
    return manifest, digest(manifest), overlays, names, host_sql


class Recovery:
    def __init__(self, target, database_url, root, cli, deadline, observation=None):
        self.target, self.url, self.root, self.cli = target, database_url, root, cli
        self.deadline, self.observation = deadline, observation
        self.overall_deadline = deadline
        self.manifest, self.plan_hash, self.overlays, self.names, self.host_sql = load_plan(root)

    @contextlib.contextmanager
    def connection(self, lock=True):
        require(time.monotonic() < self.deadline, "Recovery command deadline exceeded")
        with psycopg.connect(self.url, autocommit=True, connect_timeout=5) as conn:
            conn.execute(migration.EXECUTION_GUARD)
            conn.execute("SET search_path=public,pg_catalog")
            if lock:
                require(conn.execute("SELECT pg_try_advisory_lock(%s)", (MUTEX,)).fetchone()[0],
                        "Another migration executor holds the recovery mutex")
            yield conn

    def catalog_query(self):
        keys = Literal(self.manifest["catalog_keys"]).as_string()
        tables = Literal(self.manifest["catalog_tables"]).as_string()
        return f"""WITH catalog(obj) AS ({CATALOG_SQL}), keys(k) AS (
          SELECT unnest({keys}::text[])
          UNION SELECT key FROM catalog, jsonb_each(obj)
           WHERE split_part(key,':',1) IN ('column','constraint','trigger','table')
             AND split_part(split_part(key,':',2),'.',1)=ANY({tables}::text[])
          UNION SELECT 'index:'||i.relname FROM pg_index x
           JOIN pg_class i ON i.oid=x.indexrelid JOIN pg_class t ON t.oid=x.indrelid
           JOIN pg_namespace n ON n.oid=t.relnamespace
           WHERE n.nspname='public' AND t.relname=ANY({tables}::text[])
          UNION SELECT 'function:'||p.oid::regprocedure::text FROM pg_trigger g
           JOIN pg_proc p ON p.oid=g.tgfoid JOIN pg_class t ON t.oid=g.tgrelid
           JOIN pg_namespace n ON n.oid=t.relnamespace
           WHERE n.nspname='public' AND NOT g.tgisinternal AND t.relname=ANY({tables}::text[])
        ) SELECT jsonb_object_agg(k,obj->k) FROM catalog CROSS JOIN keys"""

    def catalog(self, conn):
        return conn.execute(self.catalog_query()).fetchone()[0]

    def history(self, conn):
        return [list(row) for row in conn.execute(HISTORY_SQL).fetchall()]

    def writer_check(self, conn, prefix):
        # An empty cutover also makes migration23's baseline seed a no-op.
        # Disabled sampling alone does not exclude queued retained reports.
        for table in ("retained_storage_cutover", "retained_storage_interval",
                      "retained_storage_measurement_obligation"):
            if conn.execute("SELECT to_regclass(%s)", (table,)).fetchone()[0]:
                require(not conn.execute(f"SELECT EXISTS(SELECT FROM {table})").fetchone()[0],
                        "Retained accounting is already active")
        if prefix >= 13:
            require(not conn.execute("SELECT EXISTS(SELECT FROM sandbox_storage_baseline)").fetchone()[0],
                    "Retained baselines prevent recovery")
        for table in ("host_storage_report", "legacy_host_storage_report"):
            require(not conn.execute(f"SELECT EXISTS(SELECT FROM {table} WHERE payload @? '$[*].retained')").fetchone()[0],
                    "Pending retained reports prevent recovery")

    def inspect(self, conn, *, ordinary=False):
        history = self.history(conn)
        auth = [row for row in history if row[0] == migration.VERSION]
        expected_auth = [[migration.VERSION, migration.NAME, [migration.verified_aggregate(self.root).decode()]]]
        require(auth == (expected_auth if self.target == "use4" else []), "Recovery Auth history mismatch")
        predecessors = [r for r in history if r[0] < FIRST and r[0] != migration.VERSION]
        expected_names = self.manifest["predecessors"]
        require([[r[0], r[1]] for r in predecessors] == expected_names, "Recovery predecessor ledger mismatch")
        retained = [r for r in history if FIRST <= r[0] <= LAST]
        prefix = len(retained)
        require([r[0] for r in retained] == sorted(self.names)[:prefix], "Recovery history is not a contiguous prefix")
        require(ordinary or all(r[0] <= LAST or r[0] == migration.VERSION for r in history),
                "Unrecognized migrations after the recovery plan")
        present = conn.execute("SELECT to_regclass('migration_recovery.plan') IS NOT NULL").fetchone()[0]
        journal, receipts = None, {}
        if present:
            require(self.target == "usw2", "Recovery journal on an ineligible target")
            rows = conn.execute("SELECT plan_hash,predecessor_hash,complete FROM migration_recovery.plan").fetchall()
            require(len(rows) == 1, "Recovery journal is missing or ambiguous")
            journal = list(rows[0])
            require(not ordinary or journal[2], "Ordinary migration refuses incomplete recovery")
            require(journal[:2] == [self.plan_hash, digest(predecessors)], "Recovery journal provenance mismatch")
            receipts = {name: (state, data) for name, state, data in conn.execute(
                "SELECT name,state,evidence FROM migration_recovery.preparation").fetchall()}
            require(list(sorted(receipts, key=lambda n: PREPARATIONS.index(n) if n in PREPARATIONS else 99))
                    == list(PREPARATIONS[:len(receipts)]), "Recovery preparation has holes or unknown steps")
            for name, (state, data) in receipts.items():
                require(isinstance(data, dict) and data.get("plan_hash") == self.plan_hash,
                        "Recovery preparation provenance mismatch")
                require(set(data) == ({"plan_hash", "table_oid"} if name in INDEXES else {"plan_hash"}),
                        "Recovery preparation evidence has unexpected fields")
                if name in INDEXES and not (ordinary and journal[2] and any(r[0] > LAST for r in history)):
                    require(data["table_oid"] == conn.execute("SELECT %s::regclass::oid", (INDEXES[name][1],)).fetchone()[0],
                            "Index intent table identity changed")
                require(state == "ready" or name in INDEXES and name == PREPARATIONS[len(receipts)-1],
                        "Recovery has an inconsistent unfinished preparation")
        else:
            require(not conn.execute("SELECT EXISTS(SELECT FROM pg_namespace WHERE nspname='migration_recovery')").fetchone()[0],
                    "Unrecognized recovery schema")
            require(prefix == 24 or self.target == "usw2" and prefix == 0, "Recovery initialization is ineligible")
        kind = "overlay" if journal else "canonical"
        for row in retained:
            require(digest(row) == self.manifest["history"][kind][row[0]], "Recovery executed-history mismatch")
        catalog = self.catalog(conn)
        stage = str(prefix)
        if journal:
            needed = 0 if prefix == 0 else 2 if prefix <= 2 else 4 if prefix <= 13 else 6
            allowed = 2 if prefix == 0 else 4 if prefix == 2 else 6 if prefix == 13 else needed
            require(needed <= len(receipts) <= allowed, "Recovery preparation does not match its migration prefix")
            for name in PREPARATIONS[:needed]:
                require(receipts[name][0] == "ready", "Migration history advanced before preparation completed")
            if len(receipts) > needed:
                name = PREPARATIONS[len(receipts)-1]
                stage = name
                if receipts[name][0] != "ready":
                    require(name in INDEXES, "Only concurrent work may have a pending intent")
                    _, table, index, _ = INDEXES[name]
                    require(receipts[name][1].get("table_oid") == conn.execute(
                        "SELECT %s::regclass::oid", (table,)).fetchone()[0], "Index intent table identity changed")
                    value = catalog.get("index:" + index)
                    if value is not None:
                        require(value[0] == self.manifest["indexes"][name][0], "Index definition conflicts with owned intent")
                        require(not conn.execute("SELECT EXISTS(SELECT FROM pg_constraint WHERE conindid=%s::regclass)",
                                                 (index,)).fetchone()[0], "Recovery index has an unexpected constraint dependency")
                    catalog["index:" + index] = None
                    stage = {"storage_index":"host", "owner_index":"13", "snapshot_index":"owner_index"}[name]
            require(not journal[2] or prefix == 24 and len(receipts) == 6, "Invalid completed recovery receipt")
        future = [r for r in history if r[0] > LAST]
        if ordinary and journal and journal[2] and future:
            # Later ordinary migrations may deliberately evolve this catalog.
            # Require their versions/names to remain represented in this checkout;
            # the CLI continues to own their ordinary statement/history contract.
            names = {p.name.split("_", 1)[0]: p.stem.split("_", 1)[1]
                     for p in (self.root / "supabase/migrations").glob("*.sql")}
            require(all(names.get(row[0]) == row[1] for row in future),
                    "Unrecognized migration after completed recovery")
        else:
            require(digest(catalog) == self.manifest["catalog_hashes"][stage], "Recovery catalog mismatch at " + stage)
        if not ordinary or journal and not journal[2]:
            self.writer_check(conn, prefix)
        return {"prefix": prefix, "journal": journal, "receipts": receipts,
                "history": history, "catalog": catalog, "stage": stage,
                "predecessor_hash": digest(predecessors),
                "guard_history": conn.execute(HISTORY_GUARD).fetchone()[0],
                "guard_catalog": conn.execute("SELECT md5(value::text) FROM (" + self.catalog_query() + ") q(value)").fetchone()[0],
                "guard_receipts": conn.execute(RECEIPT_GUARD).fetchone()[0] if journal else None}

    def guard_mutation(self, conn):
        remaining = min(self.deadline, self.overall_deadline) - time.monotonic()
        if self.target == "usw2":
            remaining = min(remaining, float(self.observation.valid_until) - time.time())
        milliseconds = min(2000, int(remaining * 1000))
        require(milliseconds > 0, "Recovery deadline or evidence expired before mutation")
        conn.execute("SELECT set_config('statement_timeout', %s, false)", (str(milliseconds),))

    def initialize(self, conn, state):
        require(self.target == "usw2" and state["prefix"] == 0, "Only an eligible West database can initialize recovery")
        with conn.transaction():
            self.guard_mutation(conn)
            conn.execute(JOURNAL_SQL)
            self.guard_mutation(conn)
            conn.execute("INSERT INTO migration_recovery.plan(plan_hash,predecessor_hash) VALUES(%s,%s)",
                         (self.plan_hash, state["predecessor_hash"]))

    def receipt(self, conn, name, state="ready", **data):
        self.guard_mutation(conn)
        evidence = {"plan_hash": self.plan_hash, **data}
        conn.execute("INSERT INTO migration_recovery.preparation(name,state,evidence) VALUES(%s,%s,%s) "
                     "ON CONFLICT(name) DO UPDATE SET state=excluded.state,evidence=excluded.evidence",
                     (name, state, Jsonb(evidence)))

    def prepare(self, conn, state, name):
        if name in INDEXES:
            _, table, index, columns = INDEXES[name]
            item = state["receipts"].get(name)
            oid = conn.execute("SELECT %s::regclass::oid", (table,)).fetchone()[0]
            if not item:
                self.receipt(conn, name, "intent", table_oid=oid)
                item = ("intent", {"table_oid": oid})
            value = conn.execute("SELECT indisvalid,indisready,indislive FROM pg_index WHERE indexrelid=to_regclass(%s)",
                                 (index,)).fetchone()
            if value == (True, True, True):
                self.receipt(conn, name, table_oid=oid)
                return
            if value is not None or item[0] == "dropping":
                self.receipt(conn, name, "dropping", table_oid=oid)
                if value is not None:
                    self.guard_mutation(conn)
                    conn.execute(f"DROP INDEX CONCURRENTLY public.{index}")
                self.receipt(conn, name, "intent", table_oid=oid)
                raise migration.MigrationError("Owned invalid index removed; obtain authorization before resuming")
            self.guard_mutation(conn)
            conn.execute(f"CREATE INDEX CONCURRENTLY {index} ON public.{table}({columns})")
            self.receipt(conn, name, table_oid=oid)
        else:
            with conn.transaction():
                self.guard_mutation(conn)
                if name == "host":
                    conn.execute(self.host_sql)
                elif name == "reason":
                    conn.execute(f"ALTER TABLE sandbox_storage_interval ADD CONSTRAINT {CANDIDATE} "
                                 "CHECK (end_reason IS NULL OR end_reason IN ('deleted','measurement','reassigned')) NOT VALID")
                elif name == "validated_reason":
                    conn.execute(f"ALTER TABLE sandbox_storage_interval VALIDATE CONSTRAINT {CANDIDATE}")
                else:
                    raise migration.MigrationError("Unknown recovery preparation")
                self.receipt(conn, name)

    def next_preparation(self, state):
        count, prefix = len(state["receipts"]), state["prefix"]
        if count and state["receipts"][PREPARATIONS[count-1]][0] != "ready":
            return PREPARATIONS[count-1]
        limit = {0: 2, 2: 4, 13: 6}.get(prefix, count)
        return PREPARATIONS[count] if count < limit else None

    def push_one(self, state, project):
        self.command_deadline()
        self.observe()
        version = sorted(self.names)[state["prefix"]]
        paths = project / "supabase/migrations"
        for file in paths.glob("*.sql"):
            if file.name.split("_", 1)[0] > version and file.name != migration.AGGREGATE:
                file.unlink()
        for v, name in self.names.items():
            if v <= version:
                (paths / name).write_text(self.overlays[v])
        # A different executor may advance state between the preparation and
        # CLI sessions. Guard the observed ledger/journal on the session that
        # actually mutates, after taking the same mutex.
        guard = migration.EXECUTION_GUARD + "SET search_path=public,pg_catalog;\n" + f"""
DO $$ BEGIN
 IF NOT pg_try_advisory_lock({MUTEX}) THEN RAISE EXCEPTION 'migration mutex busy'; END IF;
 IF clock_timestamp() >= to_timestamp({float(self.observation.valid_until)})
 THEN RAISE EXCEPTION 'recovery evidence expired'; END IF;
 IF ({HISTORY_GUARD}) <> '{state["guard_history"]}'
 OR NOT EXISTS(SELECT FROM migration_recovery.plan WHERE plan_hash='{self.plan_hash}' AND NOT complete)
 OR (SELECT md5(value::text) FROM ({self.catalog_query()}) q(value)) <> '{state["guard_catalog"]}'
 OR ({RECEIPT_GUARD}) <> '{state["guard_receipts"]}'
 THEN RAISE EXCEPTION 'recovery state changed'; END IF;
END $$;
DO $writers$ DECLARE relation_name text; populated boolean; BEGIN
 FOREACH relation_name IN ARRAY ARRAY['retained_storage_cutover','retained_storage_interval',
   'retained_storage_measurement_obligation','sandbox_storage_baseline'] LOOP
  IF to_regclass(relation_name) IS NOT NULL THEN
   EXECUTE format('SELECT EXISTS(SELECT FROM %I)',relation_name) INTO populated;
   IF populated THEN RAISE EXCEPTION 'retained accounting is active'; END IF;
  END IF;
 END LOOP;
 IF EXISTS(SELECT FROM host_storage_report WHERE payload @? '$[*].retained')
 OR EXISTS(SELECT FROM legacy_host_storage_report WHERE payload @? '$[*].retained')
 THEN RAISE EXCEPTION 'retained reports prevent recovery'; END IF;
END $writers$;
"""
        (project / "supabase/roles.sql").write_text(guard)
        migration.cli_run(self.cli, self.url, project, ["db", "push", "--yes", "--include-roles"], self.deadline)

    def command_deadline(self):
        self.deadline = min(self.overall_deadline, time.monotonic() + migration.COMMAND_TIMEOUT)
        require(time.monotonic() < self.deadline, "Whole recovery deadline exceeded")
        if self.observation is not None:
            self.observation.deadline = self.deadline
        return self.deadline

    def observe(self):
        require(self.observation is not None, "Authenticated deployment observation is required")
        self.observation.verify()

    @staticmethod
    def approved_state(state):
        return {key: state[key] for key in ("prefix", "journal", "receipts", "history", "catalog", "guard_catalog")}

    def run(self, project, approved):
        expected, pushed = self.approved_state(approved), False
        self.overall_deadline = time.monotonic() + RECOVERY_TIMEOUT
        while True:
            self.command_deadline()
            with self.connection() as conn:
                if self.target == "usw2":
                    self.observe()
                state = self.inspect(conn)
                if pushed:
                    # The CLI released its mutex after committing exactly one
                    # migration. Accept only that transition, never progress
                    # made by another executor in the intervening gap.
                    previous = self.approved_state(state)
                    previous["prefix"] -= 1
                    version = sorted(self.names)[expected["prefix"]]
                    previous["history"] = [r for r in state["history"] if r[0] != version]
                    previous["catalog"] = expected["catalog"]
                    previous["guard_catalog"] = expected["guard_catalog"]
                    require(previous == expected, "Recovery state changed after the approved migration")
                else:
                    require(self.approved_state(state) == expected,
                            "Recovery state changed since the approved preflight or previous phase")
                if state["prefix"] == 24:
                    if state["journal"] and not state["journal"][2]:
                        self.guard_mutation(conn)
                        conn.execute("UPDATE migration_recovery.plan SET complete=true WHERE singleton")
                    return
                if not state["journal"]:
                    self.initialize(conn, state)
                    state = self.inspect(conn)
                name = self.next_preparation(state)
                if name:
                    self.prepare(conn, state, name)
                    expected = self.approved_state(self.inspect(conn))
                    pushed = False
                    continue
                expected = self.approved_state(state)
            self.push_one(state, project)
            pushed = True


def ordinary_guard(target, database_url, root, cli, deadline):
    with psycopg.connect(database_url, autocommit=True, connect_timeout=5) as conn:
        present = conn.execute("SELECT to_regclass('migration_recovery.plan') IS NOT NULL").fetchone()[0]
        if present:
            runner = Recovery(target, database_url, root, cli, deadline)
            conn.execute("SET search_path=public,pg_catalog")
            state = runner.inspect(conn, ordinary=True)
            require(state["journal"][2], "Ordinary migration refuses incomplete recovery")
            condition = (f"NOT EXISTS(SELECT FROM migration_recovery.plan WHERE complete AND plan_hash='{runner.plan_hash}')"
                         f" OR ({HISTORY_GUARD}) IS DISTINCT FROM '{state['guard_history']}'"
                         f" OR ({RECEIPT_GUARD}) IS DISTINCT FROM '{state['guard_receipts']}'"
                         f" OR (SELECT md5(value::text) FROM ({runner.catalog_query()}) q(value))"
                         f" IS DISTINCT FROM '{state['guard_catalog']}'")
        else:
            require(target != "usw2", "Ordinary West migration requires completed recovery")
            condition = "EXISTS(SELECT FROM pg_namespace WHERE nspname='migration_recovery')"
            require(not conn.execute("SELECT EXISTS(SELECT FROM pg_namespace WHERE nspname='migration_recovery')").fetchone()[0],
                    "Unrecognized recovery namespace")
            if conn.execute("SELECT to_regclass('supabase_migrations.schema_migrations') IS NOT NULL").fetchone()[0]:
                retained = conn.execute("SELECT version,name,statements FROM supabase_migrations.schema_migrations "
                                        "WHERE version BETWEEN %s AND %s ORDER BY version", (FIRST, LAST)).fetchall()
                if retained:
                    manifest, _, _, _, _ = load_plan(root)
                    require(all(digest(list(row)) == manifest["history"]["canonical"].get(row[0]) for row in retained),
                            "Alternate retained history requires its recovery journal")
    return f"""
SET search_path=public,pg_catalog;
DO $$ BEGIN
 IF NOT pg_try_advisory_lock({MUTEX}) THEN RAISE EXCEPTION 'migration mutex busy'; END IF;
 IF {condition} THEN RAISE EXCEPTION 'recovery state changed'; END IF;
END $$;
"""
