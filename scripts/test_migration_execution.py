"""Verify server cancellation and runner guards using the deployment CLI."""

import contextlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import psycopg

import migrate_database as migration
import snapshot_reference_index as snapshot_index
import test_migration_cli as cli_test


class ProcessCleanupTest(unittest.TestCase):
    def test_watchdog_kills_descendants(self):
        with tempfile.TemporaryDirectory() as temp:
            marker = Path(temp) / "escaped"
            child = f"import time; from pathlib import Path; time.sleep(1); Path({str(marker)!r}).touch()"
            parent = f"import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',{child!r}]); time.sleep(30)"
            with self.assertRaises(subprocess.TimeoutExpired):
                migration.run_cli([sys.executable, "-c", parent], time.monotonic() + .3)
            time.sleep(1.1)
            self.assertFalse(marker.exists(), "watchdog left a child process running")


class MigrationExecutionTest(cli_test.MigrationCLITest):
    test_fresh_database = None

    def setUp(self):
        super().setUp()
        self.root = self.project / "source"
        shutil.copytree(cli_test.ROOT / "supabase/shared-auth-history", self.root / "supabase/shared-auth-history")
        shutil.copytree(cli_test.ROOT / "supabase/shared-auth-migrations", self.root / "supabase/shared-auth-migrations")
        self.source = self.root / "supabase/migrations"
        self.source.mkdir()
        self.url = f"postgresql://postgres@127.0.0.1:{self.port}/{self.database}?sslmode=disable"

    def invoke(self, action="push"):
        with patch.object(migration, "verify_connection_identity"), contextlib.redirect_stdout(io.StringIO()):
            migration.migrate("staging", action, self.url, root=self.root, cli=cli_test.CLI)

    def seed_snapshot_references(self):
        (self.source / "20260101000001_fixture.sql").write_text("""
CREATE TABLE snapshot(id bigint PRIMARY KEY);
CREATE TABLE sandbox(id bigint PRIMARY KEY, snapshot_id bigint REFERENCES snapshot(id) ON DELETE SET NULL,
                     destroyed_at timestamptz);
INSERT INTO snapshot SELECT generate_series(1,100000);
INSERT INTO sandbox SELECT id,id,CASE WHEN id%2=0 THEN now() END FROM snapshot;
ANALYZE sandbox;
""")
        self.invoke()
        shutil.copyfile(cli_test.ROOT / "supabase/migrations" / snapshot_index.FILE,
                        self.source / snapshot_index.FILE)

    def test_snapshot_index_covers_deleted_references_and_preserves_history(self):
        self.seed_snapshot_references()
        query = "EXPLAIN (FORMAT JSON) SELECT id FROM sandbox WHERE snapshot_id=42"
        self.assertIn("Seq Scan", self.sql(query))
        self.invoke("dry-run")
        self.assertEqual(self.sql("SELECT to_regclass('idx_sandbox_snapshot_id') IS NULL"), "t")
        self.invoke()
        plan = json.loads(self.sql(query))
        self.assertIn(snapshot_index.NAME, json.dumps(plan))
        self.assertEqual(self.sql("SELECT destroyed_at IS NOT NULL FROM sandbox WHERE id=42"), "t")
        self.sql("DELETE FROM snapshot WHERE id IN (41,42)")
        self.assertEqual(self.sql("SELECT count(*) FROM sandbox WHERE id IN (41,42) AND snapshot_id IS NULL"), "2")
        before = self.history()
        self.invoke()
        self.assertEqual(self.history(), before)

    def test_snapshot_index_rejects_wrong_partial_predicate(self):
        self.seed_snapshot_references()
        self.sql("CREATE INDEX idx_sandbox_snapshot_id ON sandbox(snapshot_id) "
                 "WHERE snapshot_id IS NOT NULL AND destroyed_at IS NULL")
        with self.assertRaisesRegex(migration.MigrationError, "invalid or mismatched"):
            self.invoke()
        self.assertEqual(self.sql("SELECT count(*) FROM supabase_migrations.schema_migrations"), "1")
        # Direct CLI use must also refuse to record the incorrect index as applied.
        for source in self.source.glob("*.sql"):
            shutil.copyfile(source, self.migrations / source.name)
        self.push(error="snapshot reference index is invalid or mismatched")
        self.assertEqual(self.sql("SELECT count(*) FROM supabase_migrations.schema_migrations"), "1")

    def test_interrupted_snapshot_index_is_not_silently_accepted(self):
        self.seed_snapshot_references()
        with psycopg.connect(self.url) as writer:
            writer.execute("UPDATE sandbox SET destroyed_at=now() WHERE id=42")
            with self.assertRaisesRegex(migration.MigrationError, "preparation failed"):
                self.invoke()
        self.assertEqual(self.sql("SELECT NOT indisvalid FROM pg_index "
                                  "WHERE indexrelid='idx_sandbox_snapshot_id'::regclass"), "t")
        with self.assertRaisesRegex(migration.MigrationError, "invalid or mismatched"):
            self.invoke()
        self.assertEqual(self.sql("SELECT count(*) FROM supabase_migrations.schema_migrations"), "1")
        self.sql("UPDATE sandbox SET destroyed_at=now() WHERE id=43")

    def test_concurrent_snapshot_index_has_a_separate_bounded_budget(self):
        self.seed_snapshot_references()
        # Delay the actual CREATE INDEX statement rather than depending on
        # machine speed or a large fixture to exceed the old 1.9s budget.
        self.sql("""
CREATE FUNCTION delay_index_build() RETURNS event_trigger LANGUAGE plpgsql AS $$
BEGIN
  IF current_query() LIKE 'CREATE INDEX CONCURRENTLY idx_sandbox_snapshot_id %' THEN
    PERFORM pg_sleep(2.2);
  END IF;
END $$;
CREATE EVENT TRIGGER delay_index_build ON ddl_command_start
  WHEN TAG IN ('CREATE INDEX') EXECUTE FUNCTION delay_index_build();
""")
        with patch.object(snapshot_index, "BUILD_TIMEOUT", 2):
            with self.assertRaisesRegex(migration.MigrationError, "preparation failed.*57014"):
                self.invoke()
        self.assertEqual(self.sql("SELECT count(*) FROM supabase_migrations.schema_migrations"), "1")
        self.assertEqual(self.sql("SELECT to_regclass('idx_sandbox_snapshot_id') IS NULL"), "t")
        self.invoke()
        self.assertEqual(self.sql("SELECT indisvalid FROM pg_index "
                                  "WHERE indexrelid='idx_sandbox_snapshot_id'::regclass"), "t")

    def test_read_only_preflight_and_guard_rejection(self):
        self.invoke("preflight")
        self.assertEqual(self.sql("SELECT to_regclass('supabase_migrations.schema_migrations') IS NULL"), "t")
        (self.project / "supabase/roles.sql").write_text(migration.EXECUTION_GUARD)
        (self.migrations / "20990101000001_effect.sql").write_text("CREATE TABLE forbidden_effect(id int);")
        with self.assertRaises(migration.MigrationError):
            migration.cli_run(cli_test.CLI, self.url, self.project,
                              ["db", "push", "--yes", "--include-roles"])
        self.assertEqual(self.sql("SELECT to_regclass('forbidden_effect') IS NULL AND "
                                  "to_regclass('supabase_migrations.schema_migrations') IS NULL"), "t")
        with patch.object(migration, "STARTUP_OPTIONS", "-c transaction_timeout=0 -c lock_timeout=250ms"):
            with self.assertRaises(migration.MigrationError):
                self.invoke("preflight")

    def test_timeout_releases_reader_and_preserves_committed_prefix(self):
        self.sql("CREATE TABLE guard(id int)")
        (self.source / "20990101000001_prefix.sql").write_text("CREATE TABLE committed_prefix(id int);")
        body = """DO $$ BEGIN LOCK TABLE guard IN ACCESS EXCLUSIVE MODE; END $$;
CREATE TABLE rolled_back(id int);
SELECT pg_sleep(CASE WHEN EXISTS(SELECT FROM guard) THEN .01 ELSE .8 END);
SELECT pg_sleep(CASE WHEN EXISTS(SELECT FROM guard) THEN .01 ELSE .8 END);
SELECT pg_sleep(CASE WHEN EXISTS(SELECT FROM guard) THEN .01 ELSE .8 END);
"""
        (self.source / "20990101000002_slow.sql").write_text(body)
        failures = []

        def push():
            try:
                self.invoke()
            except Exception as error:
                failures.append(error)

        worker = threading.Thread(target=push)
        worker.start()
        try:
            for _ in range(100):
                if self.sql("SELECT count(*) FROM pg_locks WHERE relation='guard'::regclass "
                            "AND mode='AccessExclusiveLock' AND granted") == "1":
                    break
                if not worker.is_alive():
                    self.fail(f"migration exited before taking the lock: {failures}")
                time.sleep(.02)
            else:
                self.fail("migration did not acquire the expected lock")
            started = time.monotonic()
            self.assertEqual(self.sql("SELECT count(*) FROM guard"), "0")
            self.assertLess(time.monotonic() - started, 5, "server did not release the blocked reader")
        finally:
            worker.join(timeout=10)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], migration.MigrationError)
        self.assertEqual(self.sql("SELECT to_regclass('committed_prefix') IS NOT NULL AND "
                                  "to_regclass('rolled_back') IS NULL"), "t")
        self.assertEqual(self.sql("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() "
                                  "AND pid<>pg_backend_pid() AND backend_type='client backend'"), "0")
        before = self.history()
        self.assertEqual(self.sql("SELECT count(*) FROM supabase_migrations.schema_migrations"), "1")
        self.sql("INSERT INTO guard VALUES(1)")
        self.invoke()
        self.assertEqual(self.sql("SELECT row_to_json(m) FROM supabase_migrations.schema_migrations m "
                                  "WHERE version='20990101000001'"), before)
        self.assertEqual(self.sql("SELECT statements[2] FROM supabase_migrations.schema_migrations "
                                  "WHERE version='20990101000002'"), "CREATE TABLE rolled_back(id int)")
        self.assertEqual(self.sql("SELECT count(*) FROM supabase_migrations.schema_migrations"), "2")
        history = self.history()
        self.invoke()
        self.assertEqual(self.history(), history)


if __name__ == "__main__":
    unittest.main(verbosity=2)
