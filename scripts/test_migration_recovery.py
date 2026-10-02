"""Exercise recovery admission and crash boundaries with the actual CLI and PostgreSQL."""

from decimal import Decimal
import json
import os
import shutil
import time
import unittest
from unittest.mock import Mock, patch

import psycopg

import migrate_database as migration
import retained_storage_recovery as recovery
import test_migration_cli as fixture


class RecoveryTest(fixture.MigrationCLITest):
    test_fresh_database = None
    test_partial_rollout_timeout_atomicity_and_recovery = None

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        seed = cls("runTest")
        fixture.MigrationCLITest.setUp(seed)
        cls.addClassCleanup(seed.doCleanups)
        seed.copy_migrations("20261003010000")
        seed.push()
        cls.template = seed.database

    def setUp(self):
        super().setUp()
        self.sql("SELECT 1")
        result = fixture.run("docker", "exec", self.container, "dropdb", "-U", "postgres", self.database)
        self.assertEqual(result.returncode, 0, result.stdout)
        result = fixture.run("docker", "exec", self.container, "createdb", "-U", "postgres", "-T", self.template, self.database)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.copy_migrations("20261003010000")
        self.url = f"postgresql://postgres@127.0.0.1:{self.port}/{self.database}?sslmode=disable"
        self.runner = recovery.Recovery("usw2", migration.bounded_url(self.url), fixture.ROOT,
                                        fixture.CLI, time.monotonic() + 60, observation=Mock())

    def inspect(self):
        with self.runner.connection() as conn:
            return self.runner.inspect(conn)

    def initialize(self):
        with self.runner.connection() as conn:
            self.runner.initialize(conn, self.runner.inspect(conn))

    def prepare_next(self):
        with self.runner.connection() as conn:
            state = self.runner.inspect(conn)
            name = self.runner.next_preparation(state)
            if name:
                self.runner.prepare(conn, state, name)
            return name

    def test_every_prefix_and_preparation_survives_acknowledgment_loss(self):
        team, owner = '00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000003'
        self.sql(f"INSERT INTO team(id,name) VALUES('{team}','accounting-fixture'); "
                 f"INSERT INTO sandbox(id,team_id,name,status,host_id,vcpu_count,memory_mib,disk_mib) "
                 f"VALUES('{owner}','{team}','attribution','active','host-a',1,128,8); "
                 f"INSERT INTO team_storage_billing_activation(team_id,effective_at,approved_cutoff) "
                 f"VALUES('{team}','2019-01-01','2019-01-01')")
        def insert(day):
            self.sql(f"INSERT INTO sandbox_storage_interval(sandbox_id,team_id,disk_mib,started_at,ended_at,end_reason) "
                     f"VALUES('{owner}','{team}',8,'2020-01-0{day}','2020-01-0{day+1}','measurement')")
        def amount():
            return Decimal(self.sql(f"SELECT billable_storage_mib_seconds('{team}','2020-01-01','2020-01-02')"))
        insert(1)
        before_amount = amount()
        self.assertEqual(before_amount, Decimal(691200))
        self.initialize()
        for prefix in range(25):
            with self.subTest(prefix=prefix):
                state = self.inspect()
                self.assertEqual(state["prefix"], prefix)
                while (prepared := self.prepare_next()):
                    if prepared == "host":
                        insert(2)
                        self.sql(f"UPDATE sandbox SET host_id='host-b' WHERE id='{owner}'")
                        insert(3)
                        self.sql(f"UPDATE sandbox SET destroyed_at=now(),status='deleted' WHERE id='{owner}'")
                        self.assertEqual(amount(), before_amount)
                    # Re-open the session after every committed preparation,
                    # as a process restart without its previous response would.
                    self.inspect()
                state = self.inspect()
                if prefix < 24:
                    self.runner.push_one(state, self.project)
        before = self.history()
        with self.assertRaisesRegex(migration.MigrationError, "incomplete"):
            recovery.ordinary_guard("usw2", self.runner.url, fixture.ROOT, fixture.CLI, self.runner.deadline)
        self.runner.run(self.project)
        self.assertTrue(self.inspect()["journal"][2])
        self.runner.run(self.project)
        self.assertEqual(self.history(), before)
        self.assertEqual(amount(), before_amount)
        self.assertEqual(self.sql(f"SELECT COALESCE(host_id,'NULL') FROM sandbox_storage_interval "
                                  f"WHERE sandbox_id='{owner}' ORDER BY started_at").splitlines(),
                         ['NULL', 'host-a', 'host-b'])
        root = self.project / "future-root"
        shutil.copytree(fixture.ROOT / "supabase", root / "supabase")
        # Evolve a catalog key monitored during recovery, then execute another
        # migration and a no-op through the ordinary guard on the CLI session.
        for version, statement in (("20261004000001", "ALTER TABLE sandbox_storage_interval ADD CONSTRAINT future_check CHECK (true)"),
                                   ("20261004000002", "ALTER FUNCTION stamp_sandbox_storage_interval_host() SET search_path=public"),
                                   ("20261004000003", "ALTER TABLE sandbox_storage_interval RENAME TO archived_storage_interval"),
                                   ("20261004000004", "SELECT 1")):
            name = version + "_future.sql"
            (root / "supabase/migrations" / name).write_text(statement + ";")
            (self.migrations / name).write_text(statement + ";")
            guard = recovery.ordinary_guard("usw2", self.runner.url, root, fixture.CLI, self.runner.deadline)
            (self.project / "supabase/roles.sql").write_text(migration.EXECUTION_GUARD + "SET search_path=public,pg_catalog;" + guard)
            migration.cli_run(fixture.CLI, self.runner.url, self.project, ["db", "push", "--yes", "--include-roles"], self.runner.deadline)
        guard = recovery.ordinary_guard("usw2", self.runner.url, root, fixture.CLI, self.runner.deadline)
        (self.project / "supabase/roles.sql").write_text(migration.EXECUTION_GUARD + "SET search_path=public,pg_catalog;" + guard)
        migration.cli_run(fixture.CLI, self.runner.url, self.project, ["db", "push", "--yes", "--include-roles"], self.runner.deadline)
        self.sql("UPDATE migration_recovery.plan SET complete=false")
        with self.assertRaises(migration.MigrationError):
            recovery.ordinary_guard("usw2", self.runner.url, root, fixture.CLI, self.runner.deadline)

    def test_failed_observation_prevents_journal_and_mutation(self):
        self.runner.observation.verify.side_effect = migration.MigrationError("evidence unavailable")
        before = self.history()
        with self.assertRaisesRegex(migration.MigrationError, "evidence unavailable"):
            self.runner.run(self.project)
        self.assertEqual(self.history(), before)
        self.assertEqual(self.sql("SELECT to_regnamespace('migration_recovery') IS NULL"), "t")

    def test_mutex_and_stale_cli_state_refuse_mutation(self):
        self.initialize()
        while self.prepare_next():
            pass
        state = self.inspect()
        before = self.history()
        with self.runner.connection() as conn:
            with self.assertRaisesRegex(migration.MigrationError, "mutex"):
                self.inspect()
            with self.assertRaises(migration.MigrationError):
                self.runner.push_one(state, self.project)
        self.assertEqual(self.history(), before)
        self.sql("UPDATE migration_recovery.preparation SET evidence=evidence||'{\"unexpected\":true}'::jsonb WHERE name='host'")
        with self.assertRaises(migration.MigrationError):
            self.runner.push_one(state, self.project)
        self.assertEqual(self.history(), before)

    def test_history_failure_rolls_back_overlay_and_recovers(self):
        self.initialize()
        for prefix in range(24):
            while self.prepare_next():
                pass
            state = self.inspect()
            version = sorted(self.runner.names)[prefix]
            if prefix in (0, 2, 13):
                before = self.history()
                self.sql(f"CREATE FUNCTION reject_recovery_history() RETURNS trigger LANGUAGE plpgsql AS $$ "
                         f"BEGIN IF NEW.version='{version}' THEN RAISE EXCEPTION 'fixture failure'; END IF; RETURN NEW; END $$; "
                         "CREATE TRIGGER reject_recovery_history BEFORE INSERT ON supabase_migrations.schema_migrations "
                         "FOR EACH ROW EXECUTE FUNCTION reject_recovery_history();")
                with self.assertRaises(migration.MigrationError):
                    self.runner.push_one(state, self.project)
                self.assertEqual(self.history(), before)
                self.assertEqual(self.inspect()["prefix"], prefix)
                self.sql("DROP TRIGGER reject_recovery_history ON supabase_migrations.schema_migrations; DROP FUNCTION reject_recovery_history();")
            self.runner.push_one(self.inspect(), self.project)
        self.runner.run(self.project)
        self.assertEqual(self.inspect()["prefix"], 24)

    def test_admission_rejects_history_catalog_and_journal_drift(self):
        state = self.inspect()
        self.assertEqual(state["prefix"], 0)
        self.sql("ALTER TABLE sandbox_storage_interval ADD COLUMN host_id text")
        with self.assertRaisesRegex(migration.MigrationError, "catalog"):
            self.inspect()
        self.sql("ALTER TABLE sandbox_storage_interval DROP COLUMN host_id")
        self.initialize()
        self.sql("UPDATE migration_recovery.plan SET predecessor_hash='wrong'")
        with self.assertRaisesRegex(migration.MigrationError, "provenance"):
            self.inspect()
        self.sql("UPDATE migration_recovery.plan SET predecessor_hash='" + state["predecessor_hash"] + "'")
        self.sql("INSERT INTO supabase_migrations.schema_migrations(version,name,statements) VALUES('20261003010002','wrong',ARRAY['SELECT 1'])")
        with self.assertRaisesRegex(migration.MigrationError, "contiguous"):
            self.inspect()

    def test_valid_index_without_receipt_is_accepted_but_wrong_index_is_not(self):
        self.initialize()
        self.assertEqual(self.prepare_next(), "host")
        with self.runner.connection() as conn:
            oid = conn.execute("SELECT 'sandbox_storage_interval'::regclass::oid").fetchone()[0]
            self.runner.receipt(conn, "storage_index", "intent", table_oid=oid)
            conn.execute("CREATE INDEX CONCURRENTLY sandbox_storage_interval_host_window ON sandbox_storage_interval(host_id,started_at,ended_at)")
        self.assertEqual(self.prepare_next(), "storage_index")
        with self.runner.connection() as conn:
            self.runner.receipt(conn, "storage_index", "intent", table_oid=oid)
            conn.execute("DROP INDEX CONCURRENTLY sandbox_storage_interval_host_window")
            conn.execute("CREATE INDEX CONCURRENTLY sandbox_storage_interval_host_window ON sandbox_storage_interval(started_at)")
        with self.assertRaisesRegex(migration.MigrationError, "definition"):
            self.inspect()
        self.assertIn("(started_at)", self.sql("SELECT pg_get_indexdef('sandbox_storage_interval_host_window'::regclass)"))

    def test_interrupted_index_build_and_drop_require_owned_intent(self):
        self.initialize()
        self.assertEqual(self.prepare_next(), "host")
        with psycopg.connect(self.url, autocommit=True) as holder:
            with holder.transaction():
                holder.execute("LOCK TABLE sandbox_storage_interval IN ROW EXCLUSIVE MODE")
                with self.assertRaises(psycopg.errors.LockNotAvailable):
                    self.prepare_next()
        state = self.inspect()
        self.assertEqual(state["receipts"]["storage_index"][0], "intent")
        self.assertEqual(self.sql("SELECT indisvalid FROM pg_index WHERE indexrelid='sandbox_storage_interval_host_window'::regclass"), "f")
        with psycopg.connect(self.url, autocommit=True) as holder:
            with holder.transaction():
                holder.execute("SELECT count(*) FROM sandbox_storage_interval")
                with self.assertRaises(psycopg.errors.LockNotAvailable):
                    self.prepare_next()
        self.assertEqual(self.inspect()["receipts"]["storage_index"][0], "dropping")
        with self.assertRaisesRegex(migration.MigrationError, "obtain authorization"):
            self.prepare_next()
        self.assertEqual(self.sql("SELECT to_regclass('sandbox_storage_interval_host_window') IS NULL"), "t")
        self.assertEqual(self.prepare_next(), "storage_index")
        self.assertEqual(self.inspect()["receipts"]["storage_index"][0], "ready")

    def test_extra_accounting_trigger_and_constraint_refuse_initialization(self):
        self.sql("CREATE FUNCTION extra_accounting() RETURNS trigger LANGUAGE plpgsql AS $$ "
                 "BEGIN NEW.disk_mib := 999; RETURN NEW; END $$; "
                 "CREATE TRIGGER extra_accounting BEFORE INSERT ON sandbox_storage_interval "
                 "FOR EACH ROW EXECUTE FUNCTION extra_accounting()")
        with self.assertRaisesRegex(migration.MigrationError, "catalog"):
            self.initialize()
        self.assertEqual(self.sql("SELECT to_regnamespace('migration_recovery') IS NULL"), "t")
        self.sql("DROP TRIGGER extra_accounting ON sandbox_storage_interval; DROP FUNCTION extra_accounting()")
        self.sql("ALTER TABLE sandbox_storage_interval ADD CONSTRAINT extra_check CHECK(true)")
        with self.assertRaisesRegex(migration.MigrationError, "catalog"):
            self.initialize()

    def test_canonical_staging_and_east_are_read_only(self):
        self.copy_migrations()
        self.push()
        for target in ("staging", "use4"):
            with self.subTest(target=target):
                if target == "use4":
                    # Install the real shared-Auth artifact with its required
                    # fixture roles/schema, using the existing overlay helper.
                    self.sql("CREATE SCHEMA auth; CREATE TABLE auth.users(id uuid, created_at timestamptz)")
                    aggregate = migration.verified_aggregate(fixture.ROOT).decode()
                    self.sql(aggregate)
                    with psycopg.connect(self.url, autocommit=True) as conn:
                        conn.execute("INSERT INTO supabase_migrations.schema_migrations(version,name,statements) VALUES(%s,%s,%s)",
                                     (migration.VERSION, migration.NAME, [aggregate]))
                runner = recovery.Recovery(target, self.runner.url, fixture.ROOT, fixture.CLI, time.monotonic() + 60)
                before = self.history()
                runner.run(self.project)
                receipts = self.project / "receipts"
                with patch.object(migration, "verify_connection_identity"), patch.dict(os.environ, {
                        "GITHUB_SHA": "a" * 40, "RECOVERY_RECEIPT_DIR": str(receipts)}):
                    migration.migrate(target, "recovery-preflight", self.url, cli=fixture.CLI)
                    receipt_path = receipts / (target + ".json")
                    receipt = json.loads(receipt_path.read_text())
                    self.assertEqual(receipt["target"], target)
                    migration.migrate(target, "recover", self.url, cli=fixture.CLI)
                    receipt["revision"] = "b" * 40
                    receipt_path.write_text(json.dumps(receipt))
                    with self.assertRaisesRegex(migration.MigrationError, "changed since"):
                        migration.migrate(target, "recover", self.url, cli=fixture.CLI)
                self.assertEqual(self.history(), before)
                self.assertEqual(self.sql("SELECT to_regnamespace('migration_recovery') IS NULL"), "t")

    def test_source_drift_and_retained_report_admission(self):
        root = self.project / "changed-source"
        shutil.copytree(fixture.ROOT / "supabase", root / "supabase")
        path = next((root / "supabase/migrations").glob("20261003010001_*.sql"))
        path.write_text(path.read_text() + "\nSELECT 1;\n")
        with self.assertRaisesRegex(migration.MigrationError, "source hash"):
            recovery.Recovery("usw2", self.runner.url, root, fixture.CLI, time.monotonic() + 60, observation=Mock())
        # Disable the fixture FK only to inject a queued report without needing
        # an unrelated host's registration protocol.
        self.sql("SET session_replication_role=replica; INSERT INTO legacy_host_storage_report(host_id,report_id,received_at,payload) "
                 "VALUES('fixture-host','00000000-0000-0000-0000-000000000001',now(),'[{\"retained\":{}}]'::jsonb)")
        with self.assertRaisesRegex(migration.MigrationError, "Pending retained reports"):
            self.inspect()


if __name__ == "__main__":
    unittest.main(verbosity=2)
