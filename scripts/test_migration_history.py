"""Validate ordinary migrations against canonical and completed recovery history."""

import shutil
import time
import unittest
from unittest.mock import Mock, patch

import migrate_database as migration
import retained_storage_recovery as recovery
import test_migration_cli as fixture


class MigrationHistoryTest(fixture.MigrationCLITest):
    test_fresh_database = None

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
                                        fixture.CLI, time.monotonic() + 60)

    def test_west_ordinary_empty_and_partial_ledgers_are_refused(self):
        for through in ("20261003010000", "20261003010002"):
            self.copy_migrations(through)
            self.push()
            before = self.history()
            with self.assertRaises(migration.MigrationError):
                recovery.ordinary_guard("usw2", self.runner.url, fixture.ROOT, fixture.CLI, self.runner.deadline)
            self.assertEqual(self.history(), before)

    def test_canonical_west_ordinary_rejects_catalog_and_dispatch_drift(self):
        self.copy_migrations(recovery.LAST)
        self.push()
        guard = recovery.ordinary_guard("usw2", self.runner.url, fixture.ROOT, fixture.CLI, self.runner.deadline)
        self.sql("ALTER TABLE sandbox_storage_interval ADD CONSTRAINT extra_check CHECK(true)")
        with self.assertRaisesRegex(migration.MigrationError, "catalog"):
            recovery.ordinary_guard("usw2", self.runner.url, fixture.ROOT, fixture.CLI, self.runner.deadline)
        (self.migrations / "20261004000001_future.sql").write_text("CREATE TABLE should_not_exist(id integer);")
        (self.project / "supabase/roles.sql").write_text(migration.EXECUTION_GUARD + guard)
        with self.assertRaises(migration.MigrationError):
            migration.cli_run(fixture.CLI, self.runner.url, self.project,
                              ["db", "push", "--yes", "--include-roles"], self.runner.deadline)
        self.sql("ALTER TABLE sandbox_storage_interval DROP CONSTRAINT extra_check; CREATE SCHEMA migration_recovery")
        with self.assertRaisesRegex(migration.MigrationError, "Unrecognized recovery"):
            recovery.ordinary_guard("usw2", self.runner.url, fixture.ROOT, fixture.CLI, self.runner.deadline)

    def test_canonical_guard_does_not_adopt_concurrent_unvalidated_history(self):
        self.copy_migrations()
        self.push()
        original = recovery.Recovery.catalog
        def changed_after_history(runner, conn):
            catalog = original(runner, conn)
            self.sql("UPDATE supabase_migrations.schema_migrations SET statements=ARRAY['SELECT 1'] WHERE version='20261003010001'")
            return catalog
        with patch.object(recovery.Recovery, "catalog", changed_after_history):
            guard = recovery.ordinary_guard("usw2", self.runner.url, fixture.ROOT, fixture.CLI, self.runner.deadline)
        (self.migrations / "20261004000001_future.sql").write_text("CREATE TABLE should_not_exist(id integer);")
        (self.project / "supabase/roles.sql").write_text(migration.EXECUTION_GUARD + guard)
        with self.assertRaises(migration.MigrationError):
            migration.cli_run(fixture.CLI, self.runner.url, self.project,
                              ["db", "push", "--yes", "--include-roles"], self.runner.deadline)
        self.assertEqual(self.sql("SELECT to_regclass('should_not_exist') IS NULL"), "t")

    def test_canonical_uuid_default_qualification_preserves_function_identity(self):
        self.copy_migrations(recovery.LAST)
        self.push()
        self.sql("CREATE SCHEMA extensions; ALTER EXTENSION pgcrypto SET SCHEMA extensions")
        guard = recovery.ordinary_guard("usw2", self.runner.url, fixture.ROOT, fixture.CLI, self.runner.deadline)
        self.assertIn("pg_try_advisory_lock", guard)
        self.sql("CREATE FUNCTION public.gen_random_uuid() RETURNS uuid LANGUAGE sql AS 'SELECT pg_catalog.gen_random_uuid()'; "
                 "ALTER TABLE sandbox ALTER COLUMN id SET DEFAULT public.gen_random_uuid()")
        with self.assertRaisesRegex(migration.MigrationError, "catalog"):
            recovery.ordinary_guard("usw2", self.runner.url, fixture.ROOT, fixture.CLI, self.runner.deadline)

    def test_completed_recovery_history_allows_ordinary_migrations(self):
        root = self.project / "pinned-recovery-root"
        shutil.copytree(fixture.ROOT / "supabase", root / "supabase")
        for path in (root / "supabase/migrations").glob("*.sql"):
            if path.name not in self.runner.manifest["sources"]:
                path.unlink()
        runner = recovery.Recovery("usw2", self.runner.url, root, fixture.CLI,
                                   time.monotonic() + 60,
                                   observation=Mock(valid_until=time.time() + 120))
        with runner.connection() as conn:
            runner.initialize(conn, runner.inspect(conn))
            approved = runner.inspect(conn)
        with self.assertRaisesRegex(migration.MigrationError, "incomplete"):
            recovery.ordinary_guard("usw2", runner.url, root, fixture.CLI, runner.deadline)
        runner.run(self.project, approved)
        self.runner.deadline = time.monotonic() + 60
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
