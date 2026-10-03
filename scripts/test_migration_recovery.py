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
                                        fixture.CLI, time.monotonic() + 60, observation=Mock(valid_until=time.time() + 120))

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
        self.runner.run(self.project, self.inspect())
        self.assertTrue(self.inspect()["journal"][2])
        self.runner.run(self.project, self.inspect())
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
            self.runner.run(self.project, self.inspect())
        self.assertEqual(self.history(), before)
        self.assertEqual(self.sql("SELECT to_regnamespace('migration_recovery') IS NULL"), "t")

    def test_entrypoint_refuses_state_advanced_after_receipt_comparison(self):
        observation = Mock(state_digest="stable-writers", valid_until=time.time() + 120)
        with patch.object(migration, "verify_connection_identity"), patch.dict(os.environ, {
                "GITHUB_SHA": "a" * 40, "RECOVERY_RECEIPT_DIR": str(self.project / "receipts")}), \
                patch("recovery_evidence.Observation", return_value=observation):
            migration.migrate("usw2", "recovery-preflight", self.url, cli=fixture.CLI)
            original = recovery.Recovery.run
            def race(runner, project, approved):
                self.initialize()
                self.prepare_next()
                with psycopg.connect(self.url, autocommit=True) as holder:
                    with holder.transaction():
                        holder.execute("LOCK TABLE sandbox_storage_interval IN ROW EXCLUSIVE MODE")
                        with self.assertRaises(psycopg.errors.LockNotAvailable):
                            self.prepare_next()
                failed = self.inspect()
                with self.assertRaisesRegex(migration.MigrationError, "changed since"):
                    original(runner, project, approved)
                self.assertEqual(recovery.Recovery.approved_state(self.inspect()),
                                 recovery.Recovery.approved_state(failed))
                self.assertEqual(self.sql("SELECT indisvalid FROM pg_index WHERE indexrelid="
                                          "'sandbox_storage_interval_host_window'::regclass"), "f")
                raise migration.MigrationError("approved state race refused")
            with patch.object(recovery.Recovery, "run", race), self.assertRaisesRegex(
                    migration.MigrationError, "approved state race refused"):
                migration.migrate("usw2", "recover", self.url, cli=fixture.CLI)

    def test_progress_by_another_executor_between_cli_phases_is_not_adopted(self):
        self.initialize()
        while self.prepare_next():
            pass
        approved = self.inspect()
        original = self.runner.push_one
        after = []
        def race(state, project):
            original(state, project)
            original(self.inspect(), project)
            after.append(self.history())
        with patch.object(self.runner, "push_one", race), self.assertRaisesRegex(
                migration.MigrationError, "changed after"):
            self.runner.run(self.project, approved)
        self.assertEqual(self.history(), after[0])
        self.assertEqual(self.inspect()["prefix"], 2)
        self.assertEqual(len(self.inspect()["receipts"]), 2)

    def test_inspection_crossing_expiry_never_initializes_journal(self):
        approved = self.inspect()
        original = self.runner.inspect
        for boundary in ("evidence", "deadline"):
            with self.subTest(boundary=boundary):
                self.runner.observation.valid_until = time.time() + 120
                def inspect_then_expire(conn):
                    state = original(conn)
                    if boundary == "evidence":
                        self.runner.observation.valid_until = time.time() - 1
                    else:
                        self.runner.overall_deadline = time.monotonic() - 1
                    return state
                with patch.object(self.runner, "inspect", inspect_then_expire), self.assertRaisesRegex(
                        migration.MigrationError, "expired before mutation"):
                    self.runner.run(self.project, approved)
                self.assertEqual(self.sql("SELECT to_regnamespace('migration_recovery') IS NULL"), "t")

    def test_expiry_after_committed_preparation_stops_and_fresh_receipt_resumes(self):
        approved = self.inspect()
        original = self.runner.prepare
        def expire_after_commit(conn, state, name):
            original(conn, state, name)
            self.runner.observation.valid_until = time.time() - 1
        with patch.object(self.runner, "prepare", expire_after_commit), self.assertRaisesRegex(
                migration.MigrationError, "expired before mutation"):
            self.runner.run(self.project, approved)
        state = self.inspect()
        self.assertEqual(state["prefix"], 0)
        self.assertEqual(list(state["receipts"]), ["host"])
        self.runner.observation.valid_until = time.time() + 120
        self.runner.observation.verify.reset_mock()
        self.runner.run(self.project, state)
        self.assertEqual(self.inspect()["prefix"], 24)
        self.assertTrue(self.inspect()["journal"][2])
        # Five remaining preparations, 24 CLI transactions and completion.
        # Read-only loop inspections must not fetch a redundant inventory.
        self.assertEqual(self.runner.observation.verify.call_count, 30)

    def test_index_physical_state_change_requires_a_new_receipt(self):
        self.initialize()
        self.prepare_next()
        with psycopg.connect(self.url, autocommit=True) as holder:
            with holder.transaction():
                holder.execute("LOCK TABLE sandbox_storage_interval IN ROW EXCLUSIVE MODE")
                with self.assertRaises(psycopg.errors.LockNotAvailable):
                    self.prepare_next()
        approved = self.inspect()
        # Simulate another authorized cleanup completing while our receipt
        # still describes the physically present invalid index.
        self.sql("DROP INDEX sandbox_storage_interval_host_window")
        self.assertEqual(self.inspect()["catalog"], approved["catalog"])
        with self.assertRaisesRegex(migration.MigrationError, "changed since"):
            self.runner.run(self.project, approved)
        self.assertEqual(self.sql("SELECT to_regclass('sandbox_storage_interval_host_window') IS NULL"), "t")

    def test_west_ordinary_empty_partial_and_canonical_ledgers_are_refused(self):
        for through in ("20261003010000", "20261003010002", "20261003010024"):
            self.copy_migrations(through)
            self.push()
            before = self.history()
            with self.assertRaisesRegex(migration.MigrationError, "completed recovery"):
                recovery.ordinary_guard("usw2", self.runner.url, fixture.ROOT, fixture.CLI, self.runner.deadline)
            self.assertEqual(self.history(), before)

    def test_expired_evidence_is_rechecked_on_cli_mutation_session(self):
        self.initialize()
        while self.prepare_next():
            pass
        before = self.history()
        self.runner.observation.valid_until = time.time() - 1
        with self.assertRaises(migration.MigrationError):
            self.runner.push_one(self.inspect(), self.project)
        self.assertEqual(self.history(), before)

    def test_cli_expiry_after_roles_rejects_before_migration_ddl(self):
        self.initialize()
        while self.prepare_next():
            pass
        before = self.history()
        # Sequence increments survive rollback, proving migration DDL was never
        # reached rather than merely proving its eventual atomic rollback.
        self.sql("CREATE SEQUENCE fixture_ddl_attempt; "
                 "CREATE FUNCTION fixture_observe_ddl() RETURNS event_trigger LANGUAGE plpgsql AS $$ "
                 "BEGIN IF current_query() LIKE '%CREATE TABLE retained_storage_cutover%' THEN "
                 "PERFORM nextval('fixture_ddl_attempt'); END IF; END $$; "
                 "CREATE EVENT TRIGGER fixture_observe_ddl ON ddl_command_start "
                 "WHEN TAG IN ('CREATE TABLE') EXECUTE FUNCTION fixture_observe_ddl()")
        original = migration.cli_run
        def delayed_cli(*args):
            self.runner.observation.valid_until = time.time() + 1
            roles = self.project / "supabase/roles.sql"
            text = roles.read_text().replace(str(expiry), str(self.runner.observation.valid_until))
            roles.write_text(text + "\nSELECT pg_sleep(1.2);\n")
            return original(*args)
        expiry = self.runner.observation.valid_until
        with patch.object(migration, "cli_run", delayed_cli), self.assertRaisesRegex(
                migration.MigrationError, "SQLSTATE P0001"):
            self.runner.push_one(self.inspect(), self.project)
        self.assertEqual(self.history(), before)
        self.assertEqual(self.sql("SELECT is_called FROM fixture_ddl_attempt"), "f")
        self.assertEqual(self.sql("SELECT to_regclass('retained_storage_cutover') IS NULL"), "t")
        self.assertEqual(self.sql("SELECT expires_at < clock_timestamp() FROM migration_recovery.authorization"), "t")

    def test_authorization_binds_backend_version_phase_and_mutex(self):
        self.initialize()
        while self.prepare_next():
            pass
        with patch.object(migration, "cli_run"):
            self.runner.push_one(self.inspect(), self.project)
        roles = (self.project / "supabase/roles.sql").read_text()
        before = self.history()
        with psycopg.connect(self.runner.url, autocommit=True) as conn:
            for mutation in (
                "UPDATE migration_recovery.authorization SET version='wrong'",
                "UPDATE migration_recovery.authorization SET backend_start=backend_start-interval '1 second'",
                "UPDATE migration_recovery.authorization SET plan_hash='wrong'",
                "UPDATE migration_recovery.authorization SET history_hash='wrong'",
                "UPDATE migration_recovery.authorization SET receipts_hash='wrong'",
                "UPDATE migration_recovery.authorization SET expires_at=clock_timestamp()+interval '1 second'",
                "SELECT pg_advisory_unlock_all()",
            ):
                with self.subTest(mutation=mutation):
                    conn.execute(roles)
                    conn.execute(mutation)
                    with self.assertRaisesRegex(psycopg.Error, "authorization expired or mismatched"):
                        conn.execute(f"SELECT migration_recovery.check_authorization('{recovery.FIRST}'); "
                                     "CREATE TABLE fixture_forbidden(id integer)")
            conn.execute(roles)
        # Reacquiring the lock on a replacement connection cannot reuse the
        # previous backend's authorization, even after RESET ALL.
        with self.runner.connection() as replacement:
            replacement.execute("RESET ALL")
            with self.assertRaisesRegex(psycopg.Error, "authorization expired or mismatched"):
                replacement.execute(f"SELECT migration_recovery.check_authorization('{recovery.FIRST}')")
        self.assertEqual(self.history(), before)
        self.assertEqual(self.sql("SELECT to_regclass('fixture_forbidden') IS NULL"), "t")

    def test_client_suspension_after_prelude_terminates_transaction(self):
        self.initialize()
        while self.prepare_next():
            pass
        with patch.object(migration, "cli_run"):
            self.runner.push_one(self.inspect(), self.project)
        before = self.history()
        with psycopg.connect(self.runner.url, autocommit=True) as conn:
            conn.execute((self.project / "supabase/roles.sql").read_text())
            conn.execute("RESET ALL")
            with self.assertRaises(psycopg.errors.TransactionTimeout), conn.transaction():
                conn.execute(f"SELECT migration_recovery.check_authorization('{recovery.FIRST}')")
                time.sleep(2.2)
                conn.execute("CREATE TABLE fixture_forbidden(id integer)")
        self.assertEqual(self.history(), before)
        self.assertEqual(self.sql("SELECT to_regclass('fixture_forbidden') IS NULL"), "t")

    def test_client_suspension_after_reset_refuses_before_ddl(self):
        self.initialize()
        while self.prepare_next():
            pass
        self.runner.observation.valid_until = time.time() + 3.5
        with patch.object(migration, "cli_run"):
            self.runner.push_one(self.inspect(), self.project)
        before = self.history()
        with psycopg.connect(self.runner.url, autocommit=True) as conn:
            conn.execute((self.project / "supabase/roles.sql").read_text())
            conn.execute("RESET ALL")
            time.sleep(max(0, self.runner.observation.valid_until - time.time()) + 0.1)
            with self.assertRaisesRegex(psycopg.Error, "authorization expired or mismatched"):
                conn.execute(f"SELECT migration_recovery.check_authorization('{recovery.FIRST}'); "
                             "CREATE TABLE fixture_forbidden(id integer)")
        self.assertEqual(self.history(), before)
        self.assertEqual(self.sql("SELECT to_regclass('fixture_forbidden') IS NULL"), "t")

    def test_history_guard_rolls_back_changed_transaction_authorization(self):
        self.initialize()
        while self.prepare_next():
            pass
        with patch.object(migration, "cli_run"):
            self.runner.push_one(self.inspect(), self.project)
        before = self.history()
        with psycopg.connect(self.runner.url, autocommit=True) as conn:
            conn.execute((self.project / "supabase/roles.sql").read_text())
            conn.execute("RESET ALL")
            with self.assertRaisesRegex(psycopg.Error, "authorization expired or mismatched"), conn.transaction():
                conn.execute(f"SELECT migration_recovery.check_authorization('{recovery.FIRST}')")
                conn.execute("CREATE TABLE fixture_forbidden(id integer)")
                conn.execute("UPDATE migration_recovery.authorization SET version='wrong'")
                conn.execute("INSERT INTO supabase_migrations.schema_migrations(version,name,statements) "
                             "VALUES(%s,'fixture',ARRAY['CREATE TABLE fixture_forbidden(id integer)'])", (recovery.FIRST,))
        self.assertEqual(self.history(), before)
        self.assertEqual(self.sql("SELECT to_regclass('fixture_forbidden') IS NULL"), "t")

    def test_authorization_guard_tampering_is_refused(self):
        self.initialize()
        self.sql("ALTER TABLE supabase_migrations.schema_migrations DISABLE TRIGGER retained_recovery_authorization")
        with self.assertRaisesRegex(migration.MigrationError, "authorization guard changed"):
            self.inspect()
        self.sql("ALTER TABLE supabase_migrations.schema_migrations ENABLE TRIGGER retained_recovery_authorization")
        state = self.inspect()
        self.sql("ALTER FUNCTION migration_recovery.check_authorization(text) SECURITY DEFINER")
        with self.assertRaisesRegex(migration.MigrationError, "SQLSTATE P0001"):
            self.runner.push_one(state, self.project)

    def test_suspended_preparation_client_cannot_start_concurrent_index(self):
        self.initialize()
        self.assertEqual(self.prepare_next(), "host")
        guard = self.runner.guard_mutation
        admissions = 0
        def suspend_after_guard(conn):
            nonlocal admissions
            guard(conn)
            admissions += 1
            # This is the admission immediately before the index, after the
            # intent has committed. No new statement resets the idle timer.
            if admissions == 2:
                time.sleep(2.2)
        with patch.object(self.runner, "guard_mutation", suspend_after_guard):
            with self.assertRaises(psycopg.errors.IdleSessionTimeout):
                self.prepare_next()
        self.assertEqual(self.sql("SELECT to_regclass('sandbox_storage_interval_host_window') IS NULL"), "t")
        self.assertEqual(self.inspect()["receipts"]["storage_index"][0], "intent")

    def test_concurrent_index_statement_timer_spans_internal_transactions(self):
        self.sql("CREATE TABLE fixture_slow_index(id integer); "
                 "INSERT INTO fixture_slow_index VALUES(1),(2); "
                 "CREATE FUNCTION fixture_slow_key(value integer) RETURNS integer IMMUTABLE LANGUAGE plpgsql AS $$ "
                 "BEGIN PERFORM pg_sleep(0.6); RETURN value; END $$; "
                 "CREATE FUNCTION fixture_delay_index() RETURNS event_trigger LANGUAGE plpgsql AS $$ "
                 "BEGIN PERFORM pg_sleep(1); END $$; "
                 "CREATE EVENT TRIGGER fixture_delay_index ON ddl_command_start "
                 "WHEN TAG IN ('CREATE INDEX') EXECUTE FUNCTION fixture_delay_index()")
        # The initial catalog transaction and later index scan each fit within
        # 2s. Only the strictly shorter whole-statement timer spans both phases.
        with self.runner.connection() as conn:
            self.runner.guard_mutation(conn)
            with self.assertRaisesRegex(psycopg.errors.QueryCanceled, "statement timeout"):
                conn.execute("CREATE INDEX CONCURRENTLY fixture_slow_index_key "
                             "ON fixture_slow_index(fixture_slow_key(id))")

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
        self.runner.run(self.project, self.inspect())
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
        self.sql("SET session_replication_role=replica; INSERT INTO supabase_migrations.schema_migrations(version,name,statements) VALUES('20261003010002','wrong',ARRAY['SELECT 1'])")
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
                with runner.connection(lock=False) as conn:
                    approved = runner.inspect(conn)
                runner.run(self.project, approved)
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

    def test_canonical_west_without_journal_refuses_both_recovery_entrypoints(self):
        self.copy_migrations()
        self.push()
        before = self.history()
        receipts = self.project / "canonical-west-receipts"
        observation = Mock(state_digest="stable-writers", valid_until=time.time() + 120)
        with patch.object(migration, "verify_connection_identity"), \
                patch("recovery_evidence.Observation", return_value=observation), \
                patch.dict(os.environ, {"GITHUB_SHA": "a" * 40, "RECOVERY_RECEIPT_DIR": str(receipts)}):
            for action in ("recovery-preflight", "recover"):
                with self.subTest(action=action), self.assertRaisesRegex(
                        migration.MigrationError, "Recovery initialization is ineligible"):
                    migration.migrate("usw2", action, self.url, cli=fixture.CLI)
                self.assertFalse((receipts / "usw2.json").exists())
                self.assertEqual(self.history(), before)
                self.assertEqual(self.sql("SELECT to_regnamespace('migration_recovery') IS NULL"), "t")

    def test_recovery_entrypoint_rejects_unplanned_pending_sources(self):
        self.copy_migrations()
        self.push()
        before = self.history()
        root = self.project / "extra-source"
        shutil.copytree(fixture.ROOT / "supabase", root / "supabase")
        for version in ("20261004000001", "20261003000001"):
            extra = root / "supabase/migrations" / (version + "_extra.sql")
            extra.write_text("CREATE TABLE unplanned_migration(id integer);\n")
            for action in ("recovery-preflight", "recover"):
                with self.subTest(version=version, action=action), \
                        patch.object(migration, "verify_connection_identity"), \
                        self.assertRaisesRegex(migration.MigrationError, "exactly the pinned migration source set"):
                    migration.migrate("staging", action, self.url, root=root, cli=fixture.CLI)
            self.assertEqual(self.history(), before)
            self.assertEqual(self.sql("SELECT to_regclass('unplanned_migration') IS NULL"), "t")
            extra.unlink()

    def test_source_drift_and_retained_report_admission(self):
        root = self.project / "changed-source"
        shutil.copytree(fixture.ROOT / "supabase", root / "supabase")
        path = next((root / "supabase/migrations").glob("20261003010001_*.sql"))
        path.write_text(path.read_text() + "\nSELECT 1;\n")
        with self.assertRaisesRegex(migration.MigrationError, "source hash"):
            recovery.Recovery("usw2", self.runner.url, root, fixture.CLI, time.monotonic() + 60, observation=Mock(valid_until=time.time() + 120))
        # Disable the fixture FK only to inject a queued report without needing
        # an unrelated host's registration protocol.
        self.sql("SET session_replication_role=replica; INSERT INTO legacy_host_storage_report(host_id,report_id,received_at,payload) "
                 "VALUES('fixture-host','00000000-0000-0000-0000-000000000001',now(),'[{\"retained\":{}}]'::jsonb)")
        with self.assertRaisesRegex(migration.MigrationError, "Pending retained reports"):
            self.inspect()


class RecoveryDeadlineTest(unittest.TestCase):
    def test_individual_watchdogs_cannot_extend_overall_deadline(self):
        runner = object.__new__(recovery.Recovery)
        runner.overall_deadline = 280
        runner.observation = Mock()
        for now, expected in ((100, 160), (150, 210), (270, 280)):
            with patch.object(recovery.time, "monotonic", return_value=now):
                self.assertEqual(runner.command_deadline(), expected)
                self.assertEqual(runner.observation.deadline, expected)
        with patch.object(recovery.time, "monotonic", return_value=280), self.assertRaisesRegex(
                migration.MigrationError, "Whole recovery deadline"):
            runner.command_deadline()


if __name__ == "__main__":
    unittest.main(verbosity=2)
