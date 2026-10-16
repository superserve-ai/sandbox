"""Exercise shared schema/history atomicity and regional CLI compatibility."""

import contextlib
import io
from unittest.mock import patch
import unittest

import psycopg

import migrate_database as regional
import migrate_shared_auth as shared
import test_migration_cli as cli_test


class SharedAuthMigrationTest(cli_test.MigrationCLITest):
    test_fresh_database = None

    def setUp(self):
        super().setUp()
        def cleanup_database():
            result = cli_test.run("docker", "exec", self.container, "psql", "-U", "postgres", "-d", "postgres",
                                 "-v", "ON_ERROR_STOP=1", "-c", f"DROP DATABASE {self.database} WITH (FORCE)")
            self.assertEqual(result.returncode, 0, result.stdout)
            result = cli_test.run("docker", "exec", self.container, "psql", "-U", "postgres", "-d", "postgres",
                                 "-c", "DROP ROLE IF EXISTS promotion_evidence_proxy")
            self.assertEqual(result.returncode, 0, result.stdout)
        self.addCleanup(cleanup_database)
        for role in shared.ROLES[:-1]:
            self.sql(f"DO $$ BEGIN IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='{role}') "
                     f"THEN CREATE ROLE {role}; END IF; END $$;")
        self.copy_migrations("20261002155219")
        self.push()
        self.sql("CREATE SCHEMA auth; CREATE TABLE auth.users(id uuid PRIMARY KEY,created_at timestamptz);")
        aggregate = regional.verified_aggregate(cli_test.ROOT).decode()
        self.sql(aggregate + f"\nINSERT INTO supabase_migrations.schema_migrations(version,name,statements) "
                 f"VALUES('{regional.VERSION}','{regional.NAME}',ARRAY[$historical${aggregate}$historical$]);")
        self.url = f"postgresql://postgres@127.0.0.1:{self.port}/{self.database}?sslmode=disable"
        self.conn = psycopg.connect(self.url, autocommit=True, options=shared.OPTIONS)
        self.addCleanup(self.conn.close)
        self.source = shared.source()
        self.revision = "a" * 40

    def apply(self, execute=True):
        return shared.apply(self.conn, "use4", self.revision, self.source, execute)

    def regional_push(self, root=cli_test.ROOT):
        with patch.object(regional, "verify_connection_identity"), contextlib.redirect_stdout(io.StringIO()):
            regional.migrate("use4", "push", self.url, root=root, cli=cli_test.CLI)

    def test_apply_retry_and_regional_deployment_preserve_history(self):
        self.regional_push()
        before = self.history()
        self.assertEqual(self.apply(False)["state"], "pending")
        self.assertEqual(self.sql("SELECT to_regnamespace('shared_auth_migrations') IS NULL"), "t")
        self.assertEqual(self.apply()["state"], "applied")
        receipt = self.sql(f"SELECT row_to_json(m) FROM {shared.LEDGER} m")
        self.assertEqual(self.apply()["state"], "applied")
        self.assertEqual(self.apply(False)["state"], "applied")
        self.assertEqual(self.sql(f"SELECT row_to_json(m) FROM {shared.LEDGER} m"), receipt)
        self.assertEqual(self.history(), before)
        self.regional_push()
        self.assertEqual(self.history(), before)
        self.assertEqual(self.sql(f"SELECT count(*) FROM {shared.TABLE}"), "0")

    def test_failed_privilege_verification_rolls_back_schema_and_ledger(self):
        self.sql("ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public "
                 "GRANT SELECT ON TABLES TO promotion_evidence_proxy;")
        before = self.history()
        with self.assertRaisesRegex(shared.SharedMigrationError, "table_privileges"):
            self.apply()
        self.assertFalse(shared.objects_present(self.conn))
        self.assertFalse(shared.ledger_exists(self.conn))
        self.assertEqual(self.history(), before)

    def test_supabase_default_grants_are_narrowed_and_recorded(self):
        self.sql("ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public "
                 "GRANT ALL ON TABLES TO anon,authenticated,service_role; "
                 "ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public "
                 "GRANT ALL ON FUNCTIONS TO anon,authenticated,service_role;")
        self.assertEqual(self.apply()["state"], "applied")
        shared.verify_permissions(self.conn)
        original, applied = self.conn.execute(f"SELECT source_sql,applied_sql FROM {shared.LEDGER}").fetchone()
        self.assertEqual(original, self.source)
        self.assertEqual(applied, self.source + shared.ACL_SQL)
        self.assertEqual(self.apply()["state"], "applied")

    def test_isolated_staging_without_historical_aggregate(self):
        self.sql(f"DELETE FROM supabase_migrations.schema_migrations WHERE version='{regional.VERSION}'")
        before = self.history()
        self.assertEqual(shared.apply(self.conn, "staging", self.revision, self.source, True)["state"], "applied")
        self.assertEqual(self.history(), before)
        with patch.object(regional, "verify_connection_identity"), contextlib.redirect_stdout(io.StringIO()):
            regional.migrate("staging", "push", self.url, cli=cli_test.CLI)
        self.assertEqual(shared.apply(self.conn, "staging", self.revision, self.source)["state"], "applied")

    def test_unrecorded_schema_is_not_adopted(self):
        self.sql(self.source)
        with self.assertRaisesRegex(shared.SharedMigrationError, "schema_without_shared_history"):
            self.apply()
        self.assertFalse(shared.ledger_exists(self.conn))

    def test_history_and_catalog_drift_stop_without_repair(self):
        self.apply()
        self.sql(f"UPDATE {shared.LEDGER} SET source_sha256='wrong'")
        with self.assertRaisesRegex(shared.SharedMigrationError, "history_mismatch"):
            self.apply()
        self.sql(f"UPDATE {shared.LEDGER} SET source_sha256='{shared.SOURCE_HASH}'")
        self.sql("ALTER TABLE public.yc_company_activation_authority DISABLE TRIGGER yc_company_activation_authority_guard")
        with self.assertRaisesRegex(shared.SharedMigrationError, "catalog_mismatch"):
            self.apply()

    def test_lock_contention_and_source_mismatch_leave_no_changes(self):
        with psycopg.connect(self.url, autocommit=True) as other:
            with other.transaction():
                other.execute("SELECT pg_advisory_xact_lock(%s)", (shared.MUTEX,))
                with self.assertRaisesRegex(shared.SharedMigrationError, "busy"):
                    self.apply()
        with self.assertRaisesRegex(shared.SharedMigrationError, "source_hash_mismatch"):
            shared.apply(self.conn, "use4", self.revision, self.source + "\n", True)
        self.assertFalse(shared.objects_present(self.conn))
        self.assertFalse(shared.ledger_exists(self.conn))


if __name__ == "__main__":
    unittest.main(verbosity=2)
