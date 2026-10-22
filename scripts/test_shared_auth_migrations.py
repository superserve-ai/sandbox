"""Exercise shared schema/history atomicity and regional CLI compatibility."""

import contextlib
import io
import shutil
import time
from unittest.mock import patch
import unittest

import psycopg

import migrate_database as regional
import migrate_shared_auth as shared
import test_migration_cli as cli_test
import test_yc_claim_mail_migration as mail_test


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


class ClaimMailMigrationTest(mail_test.ClaimMailMigrationTest, cli_test.MigrationCLITest):
    test_fresh_database = None

    @classmethod
    def setUpClass(cls):
        cli_test.MigrationCLITest.setUpClass.__func__(cls)
        cls.dsn = f"postgresql://postgres@127.0.0.1:{cls.port}/postgres?sslmode=disable"


class DevboxClaimMailMigrationTest(cli_test.MigrationCLITest):
    test_fresh_database = None

    def test_installed_baseline_inspect_apply_inspect_replay_and_drift(self):
        # Reproduce the installer's actual CLI-written ordered history, including
        # the regional migrations. A single aggregate string is a different ledger.
        self.sql("CREATE SCHEMA auth; CREATE TABLE auth.users(id uuid PRIMARY KEY,created_at timestamptz,"
                 "email text,email_confirmed_at timestamptz,deleted_at timestamptz);")
        for role in shared.ROLES[:-1]:
            self.sql(f"CREATE ROLE {role}")
        regional.verified_aggregate(cli_test.ROOT)
        self.copy_migrations()
        for source in (cli_test.ROOT / "supabase/shared-auth-history").glob("*.sql"):
            shutil.copyfile(source, self.migrations / source.name)
        self.assertEqual(cli_test.run(cli_test.CLI, "--version").stdout.splitlines()[0], regional.CLI_VERSION)
        self.push()
        url = f"postgresql://postgres@127.0.0.1:{self.port}/{self.database}?sslmode=disable"
        with psycopg.connect(url, autocommit=True, options=shared.OPTIONS) as conn:
            fixture = mail_test.ClaimMailMigrationTest()
            fixture.conn, fixture.revision = conn, "a" * 40
            fixture.apply("authority", shared.source())
            fixture.apply("claims", shared.claim_source())
            fixture.later_migrations()
            conn.execute("INSERT INTO auth.users(id,email) VALUES(gen_random_uuid(),'existing@example.test')")
            users = conn.execute("SELECT * FROM auth.users").fetchall()
            before = shared.ordinary_history(conn)
            original = fixture.history()
            self.assertEqual(len(next(r[2] for r in before if r[0] == regional.VERSION)), 23)
            system, oid, port = conn.execute("SELECT system_identifier::text, "
                "(SELECT oid::text FROM pg_database WHERE datname=current_database()),inet_server_port() "
                "FROM pg_control_system()").fetchone()
            binding = dict(system_identifier=system, database_oid=oid, server_port=port, database_name=self.database)
            def run(execute=False):
                return shared.apply_bound_devbox_claim_mail(conn, fixture.revision, **binding, execute=execute)
            def assert_drift_rejected():
                for mutation in ("statements[2:cardinality(statements)]",
                                 "ARRAY(SELECT s FROM unnest(statements) WITH ORDINALITY AS t(s,n) ORDER BY n DESC)",
                                 "array_append(statements, 'SELECT 1')"):
                    conn.execute(f"UPDATE supabase_migrations.schema_migrations SET statements={mutation} WHERE version=%s",
                                 (regional.VERSION,))
                    for execute in (False, True):
                        with self.assertRaisesRegex(shared.SharedMigrationError, "historical_aggregate_mismatch"):
                            run(execute)
                    self.assertEqual(fixture.history(), receipts)
                    conn.execute("UPDATE supabase_migrations.schema_migrations SET statements=%s WHERE version=%s",
                                 (next(r[2] for r in before if r[0] == regional.VERSION), regional.VERSION))
            receipts = original
            assert_drift_rejected()
            with self.assertRaisesRegex(shared.SharedMigrationError, "unexpected_historical_aggregate"):
                shared.prerequisites(conn, "staging")
            with self.assertRaisesRegex(shared.SharedMigrationError, "historical_aggregate_mismatch"):
                shared.prerequisites(conn, "use4")
            self.assertEqual(run()["state"], "pending")
            # A second executor can change history after the unlocked precheck.
            # The writer must reject that new baseline after acquiring its lock.
            rpc_before = shared.mail_lease_catalog(conn)
            real_prerequisites = shared.prerequisites
            prechecked = False
            with psycopg.connect(url, autocommit=True) as other:
                def change_after_precheck(connection, target):
                    nonlocal prechecked
                    result = real_prerequisites(connection, target)
                    if not prechecked:
                        prechecked = True
                        other.execute("UPDATE supabase_migrations.schema_migrations "
                                      "SET statements=array_append(statements, 'SELECT 1') WHERE version=%s",
                                      (regional.VERSION,))
                    return result
                with patch.object(shared, "prerequisites", side_effect=change_after_precheck):
                    with self.assertRaisesRegex(shared.SharedMigrationError, "historical_aggregate_mismatch"):
                        run(True)
            self.assertTrue(prechecked)
            self.assertEqual(fixture.history(), original)
            self.assertEqual(shared.mail_lease_catalog(conn), rpc_before)
            conn.execute("UPDATE supabase_migrations.schema_migrations SET statements=%s WHERE version=%s",
                         (next(r[2] for r in before if r[0] == regional.VERSION), regional.VERSION))
            self.assertEqual(run(True)["state"], "applied")
            self.assertEqual(run()["state"], "applied")
            receipts = fixture.history()
            self.assertEqual(run(True)["state"], "applied")
            self.assertEqual(fixture.history(), receipts)
            assert_drift_rejected()
            self.assertEqual([r for r in receipts if r[0] != shared.MAIL_LEASE_VERSION], original)
            self.assertEqual(shared.ordinary_history(conn), before)
            self.assertEqual(conn.execute("SELECT * FROM auth.users").fetchall(), users)


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
                      ("approvals", shared.approval_source, 21))
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
            for function in ("inspect", "ledger_exists", "catalog", "claim_catalog", "approval_catalog",
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
            self.assertEqual(measured.calls, 6)
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
        for version in (shared.VERSION, shared.CLAIM_VERSION, shared.APPROVAL_VERSION, shared.ACCEPTANCE_VERSION):
            with self.conn.transaction(force_rollback=True):
                self.conn.execute("INSERT INTO supabase_migrations.schema_migrations(version,name,statements) VALUES(%s,'unexpected',ARRAY[]::text[])",
                                  (version,))
                with self.assertRaisesRegex(shared.SharedMigrationError, "shared_version_in_regional_history"):
                    self.apply()
                self.assertFalse(shared.receipt_ledger_exists(self.conn))

    def install_acceptance_fixture(self):
        self.apply()
        self.apply_claims()
        self.apply_approvals()
        sql = shared.acceptance_source()
        executed = shared.acceptance_execution(sql)
        with self.conn.transaction():
            self.conn.execute(executed)
            shared.verify_acceptance_permissions(self.conn)
            self.conn.execute(f"INSERT INTO {shared.LEDGER} "
                "(version,name,source_sql,applied_sql,source_sha256,catalog,revision) VALUES(%s,%s,%s,%s,%s,%s,%s)",
                (shared.ACCEPTANCE_VERSION, shared.ACCEPTANCE_NAME, sql, executed, shared.ACCEPTANCE_HASH,
                 shared.Jsonb(shared.acceptance_catalog(self.conn)), self.revision))

    def test_optional_acceptance_receipt_preserves_deployment_and_inspection(self):
        self.apply()
        self.apply_claims()
        self.apply_approvals()
        self.assertNotIn(shared.ACCEPTANCE_VERSION, shared.receipt_versions(self.conn))
        self.assertFalse(shared.acceptance_objects_present(self.conn))
        with self.assertRaisesRegex(shared.SharedMigrationError, "unsupported_shared_migration"):
            shared.apply(self.conn, "use4", self.revision, shared.acceptance_source(), True, "acceptances")
        self.install_acceptance_fixture()
        prior = self.sql(f"SELECT row_to_json(m) FROM {shared.LEDGER} m ORDER BY version")
        history = self.history()
        for migration, source in (("authority", shared.source), ("claims", shared.claim_source),
                                  ("approvals", shared.approval_source)):
            measured = MeasuredConnection(self.conn)
            self.assertEqual(shared.apply(measured, "use4", self.revision, source(), True, migration)["state"], "applied")
            self.assertEqual(measured.calls, 2)
            self.assertEqual(measured.transactions, 0)
            self.assertEqual(shared.apply(self.conn, "use4", self.revision, source(), False, migration)["state"], "applied")
        self.assertEqual(self.sql(f"SELECT row_to_json(m) FROM {shared.LEDGER} m ORDER BY version"), prior)
        self.assertEqual(self.history(), history)

    def test_optional_acceptance_receipt_rejects_tampering_and_missing_predecessor(self):
        self.install_acceptance_fixture()
        for column, value in (("name", "unexpected"), ("source_sql", "changed"),
                              ("applied_sql", "changed"), ("source_sha256", "0" * 64), ("revision", "main")):
            with self.subTest(column=column), self.conn.transaction(force_rollback=True):
                self.conn.execute(f"UPDATE {shared.LEDGER} SET {column}=%s WHERE version=%s", (value, shared.ACCEPTANCE_VERSION))
                with self.assertRaisesRegex(shared.SharedMigrationError, "shared_history_mismatch"):
                    self.apply()
        with self.conn.transaction(force_rollback=True):
            self.conn.execute(f"DELETE FROM {shared.LEDGER} WHERE version=%s", (shared.APPROVAL_VERSION,))
            with self.assertRaisesRegex(shared.SharedMigrationError, "acceptance_approval_history_missing"):
                self.apply()

    def test_optional_acceptance_inspection_rejects_schema_drift(self):
        self.install_acceptance_fixture()
        for sql in ("ALTER TABLE auth.users DISABLE TRIGGER yc_financial_auth_writer",
                    "GRANT EXECUTE ON FUNCTION public.yc_offer_acceptance_rpc(text,jsonb) TO authenticated",
                    "ALTER FUNCTION public.yc_claim_rpc(text,jsonb) SET search_path TO public"):
            with self.subTest(sql=sql), self.conn.transaction(force_rollback=True):
                self.conn.execute(sql)
                with self.assertRaises(shared.SharedMigrationError):
                    self.apply(False)

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
