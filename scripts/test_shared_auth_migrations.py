"""Exercise shared schema/history atomicity and regional CLI compatibility."""

import contextlib
import io
import time
from unittest.mock import patch
import unittest

import psycopg

import migrate_database as regional
import migrate_shared_auth as shared
import test_migration_cli as cli_test


class MeasuredConnection:
    def __init__(self, conn, delay=0, after_execute=None):
        self.conn = conn
        self.delay = delay
        self.after_execute = after_execute
        self.calls = 0
        self.transactions = 0

    def execute(self, sql, *args):
        self.calls += 1
        if self.delay:
            time.sleep(self.delay)
        result = self.conn.execute(sql, *args)
        if self.after_execute:
            self.after_execute(sql)
        return result

    def transaction(self):
        self.transactions += 1
        return self.conn.transaction()


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
        self.sql("CREATE SCHEMA auth; CREATE TABLE auth.users(id uuid PRIMARY KEY,created_at timestamptz,"
                 "email text,email_confirmed_at timestamptz,deleted_at timestamptz);")
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

    def apply_claims(self, execute=True):
        return shared.apply(self.conn, "use4", self.revision, shared.claim_source(), execute, "claims")

    def regional_push(self, root=cli_test.ROOT):
        with patch.object(regional, "verify_connection_identity"), contextlib.redirect_stdout(io.StringIO()):
            regional.migrate("use4", "push", self.url, root=root, cli=cli_test.CLI)

    def apply_approvals(self, execute=True):
        return shared.apply(self.conn, "use4", self.revision, shared.approval_source(), execute, "approvals")

    def apply_acceptances(self, execute=True):
        return shared.apply(self.conn, "use4", self.revision, shared.acceptance_source(), execute, "acceptances")

    def test_acceptance_atomicity_security_and_receipt_compatibility(self):
        with self.assertRaisesRegex(shared.SharedMigrationError, "approvals_migration_required"):
            self.apply_acceptances()
        self.apply()
        self.apply_claims()
        self.apply_approvals()
        prior = self.sql(f"SELECT row_to_json(m) FROM {shared.LEDGER} m ORDER BY version")
        history = self.history()
        with patch.object(shared, "acceptance_catalog", side_effect=shared.SharedMigrationError("snapshot_failure")):
            with self.assertRaisesRegex(shared.SharedMigrationError, "snapshot_failure"):
                self.apply_acceptances()
        self.assertFalse(shared.acceptance_objects_present(self.conn))
        self.assertEqual(self.sql(f"SELECT row_to_json(m) FROM {shared.LEDGER} m ORDER BY version"), prior)
        self.apply_acceptances()
        self.assertEqual(self.sql(f"SELECT row_to_json(m) FROM {shared.LEDGER} m WHERE version<>'{shared.ACCEPTANCE_VERSION}' ORDER BY version"), prior)
        self.assertEqual(self.history(), history)
        self.assertEqual(self.apply_acceptances(False)["state"], "applied")
        for sql in (
            "GRANT SELECT ON public.yc_offer_acceptance_authority TO authenticated",
            "GRANT EXECUTE ON FUNCTION public.yc_preferred_staff_rpc(text,jsonb) TO service_role",
            "ALTER TABLE public.yc_preferred_identity_review DISABLE ROW LEVEL SECURITY",
            "GRANT SELECT ON public.yc_financial_authorization TO authenticated",
            "GRANT EXECUTE ON FUNCTION public.yc_financial_touch(text) TO service_role",
            "ALTER TABLE public.yc_financial_invalidation DISABLE ROW LEVEL SECURITY",
        ):
            with self.conn.transaction(force_rollback=True):
                self.conn.execute(sql)
                with self.assertRaisesRegex(shared.SharedMigrationError, "privileges_mismatch"):
                    self.apply_acceptances(False)

    def test_acceptance_hardening_preserves_exact_predecessor_receipts(self):
        self.apply()
        self.apply_claims()
        self.apply_approvals()
        before = self.sql(f"SELECT row_to_json(m) FROM {shared.LEDGER} m ORDER BY version")
        self.apply_acceptances()
        self.assertEqual(self.sql(f"SELECT row_to_json(m) FROM {shared.LEDGER} m WHERE version<>'{shared.ACCEPTANCE_VERSION}' ORDER BY version"), before)
        for helper in ("authority", "claims", "approvals", "acceptances"):
            source = {"authority": shared.source, "claims": shared.claim_source,
                      "approvals": shared.approval_source, "acceptances": shared.acceptance_source}[helper]()
            self.assertEqual(shared.inspect(self.conn, source, helper), "applied")
        # Compatibility ignores only the intended new path suffix in old
        # receipts. The new receipt must still reject changes to any old body,
        # privileges or search_path, including a rollback to the unsafe path.
        for statement in (
            "ALTER FUNCTION public.yc_claim_rpc(text,jsonb) SET search_path=pg_catalog,public,auth",
            "ALTER FUNCTION public.lock_yc_activation_authority(uuid,uuid,text) SET search_path=pg_catalog,public",
            "ALTER FUNCTION public.read_yc_activation_authority(text,uuid) SET search_path=pg_catalog,public,pg_temp",
            "ALTER FUNCTION public.yc_staff_claim_rpc(text,jsonb) SET statement_timeout='1s'",
        ):
            with self.conn.transaction(force_rollback=True):
                self.conn.execute(statement)
                with self.assertRaisesRegex(shared.SharedMigrationError, "shared_catalog_mismatch"):
                    shared.inspect(self.conn, shared.acceptance_source(), "acceptances")

    def test_approval_requires_claims_and_preserves_receipts(self):
        self.assertEqual(self.apply_approvals(False)["state"], "pending")
        with self.assertRaisesRegex(shared.SharedMigrationError, "claims_migration_required"):
            self.apply_approvals()
        self.apply()
        with self.assertRaisesRegex(shared.SharedMigrationError, "claims_migration_required"):
            self.apply_approvals()
        self.apply_claims()
        before = self.history()
        prior = self.sql(f"SELECT row_to_json(m) FROM {shared.LEDGER} m ORDER BY version")
        self.assertEqual(self.apply_approvals(False)["state"], "pending")
        self.assertEqual(self.apply_approvals()["state"], "applied")
        self.assertEqual(self.sql(f"SELECT row_to_json(m) FROM {shared.LEDGER} m WHERE version<>'{shared.APPROVAL_VERSION}' ORDER BY version"), prior)
        receipt = self.sql(f"SELECT row_to_json(m) FROM {shared.LEDGER} m ORDER BY version")
        self.assertEqual(self.apply_approvals()["state"], "applied")
        self.assertEqual(self.apply_claims(False)["state"], "applied")
        self.assertEqual(self.apply(False)["state"], "applied")
        self.assertEqual(self.history(), before)
        self.assertEqual(self.sql(f"SELECT row_to_json(m) FROM {shared.LEDGER} m ORDER BY version"), receipt)

    def test_approval_failure_and_drift_preserve_history(self):
        self.apply()
        self.apply_claims()
        prior = self.sql(f"SELECT row_to_json(m) FROM {shared.LEDGER} m ORDER BY version")
        with patch.object(shared, "approval_catalog", side_effect=shared.SharedMigrationError("injected_snapshot_failure")):
            with self.assertRaisesRegex(shared.SharedMigrationError, "injected_snapshot_failure"):
                self.apply_approvals()
        self.assertFalse(shared.approval_objects_present(self.conn))
        self.assertEqual(self.sql(f"SELECT row_to_json(m) FROM {shared.LEDGER} m ORDER BY version"), prior)
        self.apply_approvals()
        for sql in (
            "ALTER TABLE public.yc_claim ADD COLUMN unexpected text",
            "ALTER TABLE public.yc_claim ALTER COLUMN acceptance_required SET DEFAULT true",
            "DROP INDEX public.yc_claim_approval_mail_pending",
            "ALTER FUNCTION public.yc_claim_view(public.yc_claim) VOLATILE",
            "ALTER FUNCTION public.yc_claim_rpc(text,jsonb) STABLE",
            "CREATE OR REPLACE FUNCTION public.lock_yc_activation_authority(p_approval uuid,p_team uuid,p_region text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$ BEGIN RETURN true; END $$",
            "ALTER FUNCTION public.reserve_yc_activation_authority(text,uuid,text,uuid,text,text,uuid) STABLE",
            "ALTER FUNCTION public.revoke_yc_activation_authority(uuid,uuid,uuid) STABLE",
        ):
            with self.conn.transaction(force_rollback=True):
                self.conn.execute(sql)
                with self.assertRaisesRegex(shared.SharedMigrationError, "catalog_mismatch"):
                    self.apply_approvals(False)
        with self.conn.transaction(force_rollback=True):
            self.conn.execute("GRANT SELECT (approved_email) ON public.yc_claim_approval_mail TO service_role")
            with self.assertRaisesRegex(shared.SharedMigrationError, "approval_table_privileges"):
                self.apply_approvals(False)
        with self.conn.transaction(force_rollback=True):
            self.conn.execute("GRANT EXECUTE ON FUNCTION public.lock_yc_activation_authority(uuid,uuid,text) TO authenticated")
            with self.assertRaisesRegex(shared.SharedMigrationError, "privileges_mismatch"):
                self.apply_approvals(False)
        self.assertEqual(self.apply_approvals(False)["state"], "applied")

    def test_approval_source_grants_and_unrecorded_schema(self):
        self.apply()
        self.apply_claims()
        with self.assertRaisesRegex(shared.SharedMigrationError, "source_hash_mismatch"):
            shared.apply(self.conn, "use4", self.revision, shared.approval_source() + "\n", True, "approvals")
        with self.conn.transaction(force_rollback=True):
            self.conn.execute(shared.approval_execution(shared.approval_source()))
            with self.assertRaises(psycopg.errors.DuplicateColumn):
                self.apply_approvals()
        self.sql("ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public "
                 "GRANT ALL ON TABLES TO anon,authenticated,service_role,promotion_evidence_proxy; "
                 "ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public "
                 "GRANT ALL ON FUNCTIONS TO anon,authenticated,service_role,promotion_evidence_proxy;")
        self.apply_approvals()
        shared.verify_approval_permissions(self.conn)

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
        with self.assertRaisesRegex(shared.SharedMigrationError, "migration_privileges"):
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
        with self.assertRaises(psycopg.errors.DuplicateTable):
            self.apply()
        self.assertFalse(shared.ledger_exists(self.conn))

    def test_history_and_catalog_drift_stop_without_repair(self):
        self.apply()
        self.sql(f"UPDATE {shared.LEDGER} SET source_sha256='wrong'")
        with self.assertRaisesRegex(shared.SharedMigrationError, "history_mismatch"):
            self.apply()
        self.sql(f"UPDATE {shared.LEDGER} SET source_sha256='{shared.SOURCE_HASH}'")
        self.sql("ALTER TABLE public.yc_company_activation_authority DISABLE TRIGGER yc_company_activation_authority_guard")
        self.assertEqual(self.apply()["state"], "applied")
        with self.assertRaisesRegex(shared.SharedMigrationError, "catalog_mismatch"):
            self.apply(False)

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

    def test_claims_require_authority_without_applying_it_implicitly(self):
        self.assertEqual(self.apply_claims(False)["state"], "pending")
        with self.assertRaisesRegex(shared.SharedMigrationError, "authority_migration_required"):
            self.apply_claims()
        self.assertFalse(shared.objects_present(self.conn))
        self.assertFalse(shared.claim_objects_present(self.conn))
        self.assertFalse(shared.ledger_exists(self.conn))

    def test_claim_apply_retry_and_authority_inspection_preserve_both_receipts(self):
        self.regional_push()
        self.apply()
        authority = self.sql(f"SELECT row_to_json(m) FROM {shared.LEDGER} m WHERE version='{shared.VERSION}'")
        before = self.history()
        self.assertEqual(self.apply_claims()["state"], "applied")
        original, executed = self.conn.execute(f"SELECT source_sql,applied_sql FROM {shared.LEDGER} WHERE version=%s",
                                               (shared.CLAIM_VERSION,)).fetchone()
        self.assertEqual(original, shared.claim_source())
        self.assertEqual(executed, shared.claim_execution(original))
        receipt = self.sql(f"SELECT row_to_json(m) FROM {shared.LEDGER} m ORDER BY version")
        self.assertEqual(self.apply_claims()["state"], "applied")
        self.assertEqual(self.apply_claims(False)["state"], "applied")
        self.assertEqual(self.apply()["state"], "applied")
        self.assertEqual(self.sql(f"SELECT row_to_json(m) FROM {shared.LEDGER} m ORDER BY version"), receipt)
        self.assertEqual(self.sql(f"SELECT row_to_json(m) FROM {shared.LEDGER} m WHERE version='{shared.VERSION}'"), authority)
        self.assertEqual(self.history(), before)
        self.regional_push()
        self.assertEqual(self.history(), before)
        self.assertEqual(self.apply_claims(False)["state"], "applied")
        self.assertEqual(self.sql("SELECT count(*) FROM public.yc_claim"), "0")

    def test_claim_failure_after_schema_creation_rolls_back_trigger_and_receipt(self):
        self.apply()
        receipt = self.sql(f"SELECT row_to_json(m) FROM {shared.LEDGER} m")
        with patch.object(shared, "claim_catalog", side_effect=shared.SharedMigrationError("injected_snapshot_failure")):
            with self.assertRaisesRegex(shared.SharedMigrationError, "injected_snapshot_failure"):
                self.apply_claims()
        self.assertFalse(shared.claim_objects_present(self.conn))
        self.assertEqual(self.sql(f"SELECT row_to_json(m) FROM {shared.LEDGER} m"), receipt)
        self.assertEqual(self.apply(False)["state"], "applied")

    def test_claim_default_grants_and_lifecycle_trigger_are_restricted(self):
        self.apply()
        self.sql("ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public "
                 "GRANT ALL ON TABLES TO anon,authenticated,service_role; "
                 "ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public "
                 "GRANT ALL ON FUNCTIONS TO anon,authenticated,service_role,promotion_evidence_proxy;")
        self.apply_claims()
        shared.verify_claim_permissions(self.conn)
        self.sql("INSERT INTO auth.users(id,email,created_at) VALUES(gen_random_uuid(),'before@example.test',now());"
                 "UPDATE auth.users SET email='after@example.test';")
        self.assertEqual(self.sql("SELECT count(*)>0 FROM public.yc_claim_identity_history"), "t")
        self.assertEqual(self.apply_claims(False)["state"], "applied")

    def test_claim_trigger_and_index_drift_are_explicit_audits(self):
        self.apply()
        self.apply_claims()
        self.sql("ALTER TABLE auth.users DISABLE TRIGGER yc_claim_auth_lifecycle")
        self.assertEqual(self.apply_claims()["state"], "applied")
        with self.assertRaisesRegex(shared.SharedMigrationError, "claim_auth_trigger_mismatch"):
            self.apply_claims(False)
        self.sql("ALTER TABLE auth.users ENABLE TRIGGER yc_claim_auth_lifecycle; DROP INDEX public.yc_claim_mail_due;")
        with self.assertRaisesRegex(shared.SharedMigrationError, "shared_catalog_mismatch"):
            self.apply_claims(False)

    def test_claim_column_grants_are_explicit_audits(self):
        self.apply()
        self.apply_claims()
        receipt = self.sql(f"SELECT row_to_json(m) FROM {shared.LEDGER} m ORDER BY version")
        self.sql("GRANT SELECT (confirmation_token) ON public.yc_claim_mail TO service_role")
        self.assertEqual(self.sql("SELECT has_table_privilege('service_role','public.yc_claim_mail','SELECT')"), "f")
        self.assertEqual(self.apply_claims()["state"], "applied")
        with self.assertRaisesRegex(shared.SharedMigrationError, "claim_column_privileges_mismatch"):
            self.apply_claims(False)
        self.assertEqual(self.sql(f"SELECT row_to_json(m) FROM {shared.LEDGER} m ORDER BY version"), receipt)

    def test_unrecorded_claim_schema_is_not_adopted(self):
        self.apply()
        self.sql(shared.claim_source())
        with self.assertRaises(psycopg.errors.DuplicateTable):
            self.apply_claims()
        self.assertEqual(self.sql(f"SELECT count(*) FROM {shared.LEDGER}"), "1")

    def test_unknown_history_and_missing_claim_dependency_fail_closed(self):
        self.apply()
        self.apply_claims()
        self.sql(f"UPDATE {shared.LEDGER} SET version='unknown' WHERE version='{shared.CLAIM_VERSION}'")
        with self.assertRaisesRegex(shared.SharedMigrationError, "unknown_shared_history"):
            self.apply()
        self.sql(f"UPDATE {shared.LEDGER} SET version='{shared.CLAIM_VERSION}' WHERE version='unknown';"
                 f"DELETE FROM {shared.LEDGER} WHERE version='{shared.VERSION}';")
        with self.assertRaisesRegex(shared.SharedMigrationError, "claim_authority_history_missing"):
            self.apply_claims()

    def test_claim_source_changes_are_rejected_before_any_write(self):
        with self.assertRaisesRegex(shared.SharedMigrationError, "source_hash_mismatch"):
            shared.apply(self.conn, "use4", self.revision, shared.claim_source() + "\n", True, "claims")
        self.assertFalse(shared.ledger_exists(self.conn))

    def check_query_budgets(self, target):
        migrations = (("authority", shared.source, 11), ("claims", shared.claim_source, 17),
                      ("approvals", shared.approval_source, 21), ("acceptances", shared.acceptance_source, 17))
        before = self.history()
        with patch.object(shared, "inspect", side_effect=AssertionError("implicit audit")):
            for migration, source, budget in migrations:
                measured = MeasuredConnection(self.conn, delay=0.055)
                started = time.monotonic()
                self.assertEqual(shared.apply(measured, target, self.revision, source(), True, migration)["state"], "applied")
                self.assertEqual(measured.calls, budget, migration)
                self.assertEqual(measured.transactions, 1)
                self.assertLess(time.monotonic() - started, 20)
        receipt = self.sql(f"SELECT row_to_json(m) FROM {shared.LEDGER} m ORDER BY version")
        with contextlib.ExitStack() as stack:
            for function in ("inspect", "ledger_exists", "catalog", "claim_catalog", "approval_catalog", "acceptance_catalog",
                             "ordinary_history", "verify_changed_permissions", "verify_permissions",
                             "verify_claim_permissions", "verify_approval_permissions"):
                stack.enter_context(patch.object(shared, function, side_effect=AssertionError("no-op audit")))
            other = stack.enter_context(psycopg.connect(self.url, autocommit=True))
            stack.enter_context(other.transaction())
            other.execute("SELECT pg_advisory_xact_lock(%s)", (shared.MUTEX,))
            measured = MeasuredConnection(self.conn, delay=0.1)
            started = time.monotonic()
            for migration, source, _ in migrations:
                result = shared.apply(measured, target, self.revision, source(), True, migration)
                self.assertEqual(result["state"], "applied")
                self.assertTrue(result["regional_history_unchanged"])
            self.assertEqual(measured.calls, 8)
            self.assertEqual(measured.transactions, 0)
            self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(self.history(), before)
        self.assertEqual(self.sql(f"SELECT row_to_json(m) FROM {shared.LEDGER} m ORDER BY version"), receipt)
        self.assertEqual(shared.apply(self.conn, target, self.revision, shared.approval_source(), False, "approvals")["state"], "applied")

    def test_use4_latency_and_query_budgets(self):
        self.check_query_budgets("use4")

    def test_staging_latency_and_query_budgets(self):
        self.sql(f"DELETE FROM supabase_migrations.schema_migrations WHERE version='{regional.VERSION}'")
        self.check_query_budgets("staging")

    def test_locked_reread_skips_concurrently_committed_migration(self):
        for migration in ("authority", "claims", "approvals"):
            source = {"authority": shared.source, "claims": shared.claim_source, "approvals": shared.approval_source}[migration]()
            with psycopg.connect(self.url, autocommit=True, options=shared.OPTIONS) as other:
                fired = False
                def concurrent_apply(sql):
                    nonlocal fired
                    if not fired and (migration == "authority" or "SELECT version,name,source_sql" in sql):
                        fired = True
                        shared.apply(other, "use4", self.revision, source, True, migration)
                measured = MeasuredConnection(self.conn, after_execute=concurrent_apply)
                self.assertEqual(shared.apply(measured, "use4", self.revision, source, True, migration)["state"], "applied")
                self.assertTrue(fired)
                self.assertEqual(measured.calls, 4)
                self.assertEqual(measured.transactions, 1)
        self.assertEqual(self.sql(f"SELECT count(*) FROM {shared.LEDGER}"), "3")

    def test_locked_reread_rejects_changed_predecessor_receipt(self):
        self.apply()
        self.apply_claims()
        with psycopg.connect(self.url, autocommit=True) as other:
            fired = False
            def change_receipt(sql):
                nonlocal fired
                if not fired and "SELECT version,name,source_sql" in sql:
                    fired = True
                    other.execute(f"UPDATE {shared.LEDGER} SET applied_sql='changed' WHERE version=%s", (shared.VERSION,))
            measured = MeasuredConnection(self.conn, after_execute=change_receipt)
            with self.assertRaisesRegex(shared.SharedMigrationError, "shared_history_mismatch"):
                shared.apply(measured, "use4", self.revision, shared.approval_source(), True, "approvals")
        self.assertFalse(shared.approval_objects_present(self.conn))

    def test_receipt_integrity_and_private_writer_boundary(self):
        self.apply()
        for column in ("name", "source_sql", "applied_sql", "source_sha256", "revision"):
            with self.conn.transaction(force_rollback=True):
                self.conn.execute(f"UPDATE {shared.LEDGER} SET {column}='changed'")
                with self.assertRaisesRegex(shared.SharedMigrationError, "shared_history_mismatch"):
                    self.apply()
        for role in shared.ROLES:
            with self.conn.transaction(force_rollback=True):
                self.conn.execute(f"SET LOCAL ROLE {role}")
                with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                    self.conn.execute(f"UPDATE {shared.LEDGER} SET source_sha256='forged'")
        with self.conn.transaction(force_rollback=True):
            self.conn.execute(f"ALTER TABLE {shared.LEDGER} RENAME COLUMN applied_sql TO missing_column")
            with self.assertRaises(psycopg.errors.UndefinedColumn):
                self.apply()

    def test_partial_ledger_is_not_repaired(self):
        self.sql("CREATE SCHEMA shared_auth_migrations")
        with self.assertRaisesRegex(shared.SharedMigrationError, "partial_shared_ledger"):
            self.apply()
        self.assertEqual(self.sql(f"SELECT to_regclass('{shared.LEDGER}') IS NULL"), "t")

    def test_changed_function_permissions_fail_before_receipt_commit(self):
        self.apply()
        self.apply_claims()
        self.sql("GRANT EXECUTE ON FUNCTION public.lock_yc_activation_authority(uuid,uuid,text) TO anon")
        with self.assertRaisesRegex(shared.SharedMigrationError, "migration_privileges_mismatch"):
            self.apply_approvals()
        self.assertFalse(shared.approval_objects_present(self.conn))
        self.assertEqual(self.sql(f"SELECT count(*) FROM {shared.LEDGER}"), "2")

    def test_altered_claim_table_permissions_fail_before_receipt_commit(self):
        self.apply()
        self.apply_claims()
        self.sql("GRANT SELECT ON public.yc_claim TO anon")
        before = self.history()
        with self.assertRaisesRegex(shared.SharedMigrationError, "migration_privileges_mismatch"):
            self.apply_approvals()
        self.assertFalse(shared.approval_objects_present(self.conn))
        self.assertEqual(self.sql(f"SELECT count(*) FROM {shared.LEDGER}"), "2")
        self.assertEqual(self.history(), before)

    def test_new_ledger_rejects_inherited_default_access(self):
        self.sql("CREATE ROLE migration_ledger_writer; GRANT migration_ledger_writer TO service_role; "
                 "ALTER ROLE service_role BYPASSRLS; "
                 "ALTER DEFAULT PRIVILEGES FOR ROLE postgres GRANT USAGE ON SCHEMAS TO migration_ledger_writer; "
                 "ALTER DEFAULT PRIVILEGES FOR ROLE postgres GRANT SELECT,INSERT,UPDATE ON TABLES TO migration_ledger_writer;")
        self.addCleanup(self.sql, "ALTER DEFAULT PRIVILEGES FOR ROLE postgres REVOKE USAGE ON SCHEMAS FROM migration_ledger_writer; "
                        "ALTER DEFAULT PRIVILEGES FOR ROLE postgres REVOKE SELECT,INSERT,UPDATE ON TABLES FROM migration_ledger_writer; "
                        "DROP OWNED BY migration_ledger_writer; DROP ROLE migration_ledger_writer; "
                        "ALTER ROLE service_role NOBYPASSRLS;")
        with self.assertRaisesRegex(shared.SharedMigrationError, "migration_privileges_mismatch"):
            self.apply()
        self.assertFalse(shared.receipt_ledger_exists(self.conn))
        self.assertFalse(shared.objects_present(self.conn))

    def test_shared_version_in_regional_history_blocks_pending_apply(self):
        for version in (shared.VERSION, shared.CLAIM_VERSION, shared.APPROVAL_VERSION):
            with self.conn.transaction(force_rollback=True):
                self.conn.execute("INSERT INTO supabase_migrations.schema_migrations(version,name,statements) VALUES(%s,'unexpected',ARRAY[]::text[])",
                                  (version,))
                with self.assertRaisesRegex(shared.SharedMigrationError, "shared_version_in_regional_history"):
                    self.apply()
                self.assertFalse(shared.receipt_ledger_exists(self.conn))

    def test_commit_acknowledgement_loss_requires_inspection(self):
        class LostAcknowledgement(MeasuredConnection):
            @contextlib.contextmanager
            def transaction(self):
                with self.conn.transaction():
                    yield
                raise psycopg.OperationalError("injected lost commit acknowledgement")
        with self.assertRaises(psycopg.OperationalError):
            shared.apply(LostAcknowledgement(self.conn), "use4", self.revision, self.source, True)
        self.assertEqual(self.apply(False)["state"], "applied")
        measured = MeasuredConnection(self.conn)
        self.assertEqual(shared.apply(measured, "use4", self.revision, self.source, True)["state"], "applied")
        self.assertEqual(measured.calls, 2)

    def test_real_ddl_lock_and_transaction_timeouts_leave_approvals_pending(self):
        self.apply()
        self.apply_claims()
        prior = self.sql(f"SELECT row_to_json(m) FROM {shared.LEDGER} m ORDER BY version")
        with psycopg.connect(self.url, autocommit=True) as other:
            with other.transaction():
                other.execute("LOCK TABLE public.yc_claim IN ACCESS SHARE MODE")
                with self.assertRaises(psycopg.errors.LockNotAvailable):
                    self.apply_approvals()
        self.conn.execute("SET transaction_timeout='200ms'")
        def after_ddl(sql):
            if sql == shared.approval_execution(shared.approval_source()):
                time.sleep(0.3)
        with self.assertRaises(psycopg.errors.TransactionTimeout):
            shared.apply(MeasuredConnection(self.conn, after_execute=after_ddl), "use4", self.revision,
                         shared.approval_source(), True, "approvals")
        with psycopg.connect(self.url, autocommit=True, options=shared.OPTIONS) as fresh:
            result = shared.apply(fresh, "use4", self.revision, shared.approval_source(), False, "approvals")
            self.assertEqual(result["state"], "pending")
            self.assertFalse(shared.approval_objects_present(fresh))
        self.assertEqual(self.sql(f"SELECT row_to_json(m) FROM {shared.LEDGER} m ORDER BY version"), prior)


if __name__ == "__main__":
    unittest.main(verbosity=2)
