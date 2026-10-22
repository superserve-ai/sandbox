"""Run the claim-mail upgrade against a disposable local PostgreSQL database.

Set YC_CLAIM_TEST_DATABASE_URL to a PostgreSQL 17+ administrator URL using
the literal loopback host 127.0.0.1 or ::1, matching the operator connection guard.
Each test creates and drops its own database; existing databases are not reset.
"""

import os
import unittest
import uuid
from types import SimpleNamespace
from unittest.mock import Mock, patch

import psycopg
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from psycopg.types.json import Jsonb

import migrate_shared_auth as shared


class ClaimMailMigrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dsn = os.environ.get("YC_CLAIM_TEST_DATABASE_URL")
        if not cls.dsn:
            raise unittest.SkipTest("local PostgreSQL URL required")

    def setUp(self):
        dsn = type(self).dsn
        self.assertIn(conninfo_to_dict(dsn).get("host"), ("127.0.0.1", "::1"))
        self.admin = psycopg.connect(dsn, autocommit=True)
        self.addCleanup(self.admin.close)
        self.database = "claim_mail_" + uuid.uuid4().hex
        self.admin.execute(psycopg.sql.SQL("CREATE DATABASE {}").format(psycopg.sql.Identifier(self.database)))
        self.addCleanup(lambda: self.admin.execute(psycopg.sql.SQL("DROP DATABASE {} WITH (FORCE)").format(
            psycopg.sql.Identifier(self.database))))
        self.dsn = make_conninfo(dsn, dbname=self.database)
        self.conn = psycopg.connect(self.dsn, autocommit=True, options=shared.OPTIONS)
        self.addCleanup(self.conn.close)
        for role in shared.ROLES:
            if not self.admin.execute("SELECT 1 FROM pg_roles WHERE rolname=%s", (role,)).fetchone():
                self.admin.execute(psycopg.sql.SQL("CREATE ROLE {}").format(psycopg.sql.Identifier(role)))
        self.conn.execute("""
            CREATE SCHEMA auth;
            CREATE TABLE auth.users(id uuid PRIMARY KEY, email text,
                email_confirmed_at timestamptz, deleted_at timestamptz,
                created_at timestamptz NOT NULL DEFAULT now());
            CREATE TABLE public.signup_device_attempt(id uuid);
            CREATE SCHEMA supabase_migrations;
            CREATE TABLE supabase_migrations.schema_migrations(version text PRIMARY KEY,name text,statements text[]);
        """)
        self.revision = "a" * 40
        self.apply("authority", shared.source())
        self.apply("claims", shared.claim_source())

    def apply(self, name="claim-mail", source=None, execute=True):
        return shared.apply(self.conn, "staging", self.revision,
                            source if source is not None else shared.mail_lease_source(), execute, name)

    def later_migrations(self):
        self.apply("approvals", shared.approval_source())
        # The production CLI recognizes acceptance receipts but intentionally
        # leaves acceptance preparation to its separately reviewed executor.
        source = shared.acceptance_source()
        executed = shared.acceptance_execution(source)
        with self.conn.transaction():
            self.conn.execute(executed)
            shared.verify_acceptance_permissions(self.conn)
            self.conn.execute(f"INSERT INTO {shared.LEDGER} "
                              "(version,name,source_sql,applied_sql,source_sha256,catalog,revision) "
                              "VALUES(%s,%s,%s,%s,%s,%s,%s)",
                              (shared.ACCEPTANCE_VERSION, shared.ACCEPTANCE_NAME, source, executed,
                               shared.ACCEPTANCE_HASH, Jsonb(shared.acceptance_catalog(self.conn)), self.revision))

    def history(self):
        return self.conn.execute(f"SELECT * FROM {shared.LEDGER} ORDER BY version").fetchall()

    def rpc(self, op, payload, conn=None):
        conn = conn or self.conn
        try:
            with conn.transaction():
                conn.execute("SET LOCAL ROLE promotion_evidence_proxy")
                return conn.execute("SELECT public.yc_claim_rpc(%s,%s)", (op, Jsonb(payload))).fetchone()[0]
        finally:
            conn.execute("RESET ROLE")

    def claim(self, **changes):
        identity = uuid.uuid4().hex
        claim = self.rpc("submit", {
            "submitted_email": f"founder-{identity}@example.test", "founder_email": f"founder-{identity}@example.test",
            "verification_reference": identity * 2, "company_identity": identity,
            "evidence": {"verified": True, "name": "Synthetic Founder"},
            "state": "awaiting_confirmation", "reason": "email_match",
            "confirmation_token": "a" * 43, "token_hash": identity * 2,
        })
        for column, expression in changes.items():
            self.conn.execute(psycopg.sql.SQL("UPDATE public.yc_claim SET {}=" + expression + " WHERE id=%s").format(
                psycopg.sql.Identifier(column)), (claim["id"],))
        return claim["id"]

    def lease(self, conn=None):
        return self.rpc("mail-lease", {"lease_id": str(uuid.uuid4())}, conn)

    def test_bound_devbox_entry_rejects_wrong_identity_and_preserves_cli_targets(self):
        system, oid, port = self.conn.execute("SELECT system_identifier::text, "
            "(SELECT oid::text FROM pg_database WHERE datname=current_database()),inet_server_port() "
            "FROM pg_control_system()").fetchone()
        binding = dict(system_identifier=system, database_oid=oid, server_port=port, database_name=self.database)
        before = self.history()
        # libpq uses hostaddr as the active peer even when host is loopback.
        for host, hostaddr in (("127.0.0.1", "192.0.2.1"), ("::1", "2001:db8::1"),
                               ("127.0.0.1", "")):
            remote = SimpleNamespace(autocommit=True, info=SimpleNamespace(
                transaction_status=shared.TransactionStatus.IDLE, host=host, hostaddr=hostaddr),
                execute=Mock(side_effect=AssertionError("must reject before database query")))
            for execute in (False, True):
                with self.assertRaisesRegex(shared.SharedMigrationError, "local_connection_required"):
                    shared.apply_bound_devbox_claim_mail(remote, self.revision, **binding, execute=execute)
            remote.execute.assert_not_called()
        with psycopg.connect(self.dsn) as transactional:
            with self.assertRaisesRegex(shared.SharedMigrationError, "idle_autocommit_connection_required"):
                shared.apply_bound_devbox_claim_mail(transactional, self.revision, **binding)
        with self.conn.transaction():
            with self.assertRaisesRegex(shared.SharedMigrationError, "idle_autocommit_connection_required"):
                shared.apply_bound_devbox_claim_mail(self.conn, self.revision, **binding)
        for field, wrong in (("system_identifier", "0"), ("database_oid", "0"), ("server_port", 1), ("database_name", "wrong")):
            with self.subTest(field=field), self.assertRaisesRegex(shared.SharedMigrationError, "database_identity_mismatch"):
                shared.apply_bound_devbox_claim_mail(self.conn, self.revision, **(binding | {field: wrong}), execute=True)
        with self.assertRaisesRegex(shared.SharedMigrationError, "unsupported_auth_target"):
            shared.apply(self.conn, "devbox", self.revision, shared.mail_lease_source(), True, "claim-mail")
        self.assertEqual(self.history(), before)
        for execute in (False, True):
            with self.assertRaisesRegex(shared.SharedMigrationError, "historical_aggregate_mismatch"):
                shared.apply_bound_devbox_claim_mail(self.conn, self.revision, **binding, execute=execute)
        self.assertEqual(self.history(), before)

    def test_missing_baseline_and_unknown_history_are_rejected(self):
        before = self.history()
        with self.conn.transaction(force_rollback=True):
            self.conn.execute(f"DELETE FROM {shared.LEDGER} WHERE version=%s", (shared.CLAIM_VERSION,))
            with self.assertRaisesRegex(shared.SharedMigrationError, "claims_migration_required"):
                self.apply()
        with self.conn.transaction(force_rollback=True):
            self.conn.execute(f"UPDATE {shared.LEDGER} SET version='20990101000000' WHERE version=%s", (shared.CLAIM_VERSION,))
            with self.assertRaisesRegex(shared.SharedMigrationError, "unknown_shared_history"):
                self.apply()
        with self.conn.transaction(force_rollback=True):
            self.conn.execute("ALTER FUNCTION public.yc_claim_rpc(text,jsonb) SECURITY INVOKER")
            with self.assertRaisesRegex(shared.SharedMigrationError, "mail_lease_predecessor_mismatch"):
                self.apply()
        self.assertEqual(self.history(), before)

    def test_reproduces_both_collisions_then_scrubs_and_leases(self):
        expired = self.claim(token_expires_at="clock_timestamp()-interval '1 hour'")
        eligible = self.claim()
        with self.assertRaises(psycopg.errors.AmbiguousColumn):
            self.lease()
        # Correct only the scrub query in a rolled-back transaction to prove
        # the second query independently fails, rather than masking that defect.
        with self.conn.transaction(force_rollback=True):
            definition = self.conn.execute("SELECT pg_get_functiondef('public.yc_claim_rpc(text,jsonb)'::regprocedure)").fetchone()[0]
            definition = definition.replace("JOIN yc_claim c ON c.id=q.claim_id", "JOIN yc_claim expired_claim ON expired_claim.id=q.claim_id", 1)
            definition = definition.replace("AND c.token_expires_at<=v_now", "AND expired_claim.token_expires_at<=v_now", 1)
            self.conn.execute(definition)
            with self.assertRaises(psycopg.errors.AmbiguousColumn):
                self.lease()
        self.apply()
        leased = self.lease()
        self.assertEqual(leased["claim_id"], eligible)
        self.assertEqual(leased["token"], "a" * 43)
        self.assertIsNone(self.conn.execute("SELECT confirmation_token FROM public.yc_claim_mail WHERE claim_id=%s", (expired,)).fetchone()[0])
        self.assertEqual(self.conn.execute("SELECT attempts,lease_until>clock_timestamp() FROM public.yc_claim_mail WHERE claim_id=%s", (eligible,)).fetchone(), (1, True))
        self.assertEqual(self.lease(), {})

    def test_eligibility_and_skip_locked_are_preserved(self):
        self.apply()
        self.claim(token_expires_at="clock_timestamp()+interval '2 minutes'")
        self.claim(state="'manual_review'")
        exhausted = self.claim()
        self.conn.execute("UPDATE public.yc_claim_mail SET attempts=8 WHERE claim_id=%s", (exhausted,))
        future = self.claim()
        self.conn.execute("UPDATE public.yc_claim_mail SET next_attempt_at=clock_timestamp()+interval '1 hour' WHERE claim_id=%s", (future,))
        locked, eligible = self.claim(), self.claim()
        with psycopg.connect(self.dsn) as other:
            other.execute("SELECT 1 FROM public.yc_claim_mail WHERE claim_id=%s FOR UPDATE", (locked,))
            self.assertEqual(self.lease()["claim_id"], eligible)
            self.assertEqual(self.lease(), {})
        self.assertEqual(self.lease()["claim_id"], locked)
        self.assertEqual(self.lease(), {})

    def test_receipts_and_function_attributes_survive_both_orders(self):
        for acceptance_first in (True, False):
            with self.subTest(acceptance_first=acceptance_first), self.conn.transaction(force_rollback=True):
                if acceptance_first:
                    self.later_migrations()
                self.conn.execute("INSERT INTO auth.users(id,email) VALUES(%s,'existing@example.test')", (uuid.uuid4(),))
                existing_users = self.conn.execute("SELECT * FROM auth.users").fetchall()
                previous = self.history()
                attributes = self.conn.execute("SELECT oid,proowner,proacl,proconfig,prosecdef,provolatile "
                                               "FROM pg_proc WHERE oid='public.yc_claim_rpc(text,jsonb)'::regprocedure").fetchone()
                self.assertEqual(self.apply(execute=False)["state"], "pending")
                self.apply()
                self.assertEqual(self.conn.execute("SELECT oid,proowner,proacl,proconfig,prosecdef,provolatile "
                                                   "FROM pg_proc WHERE oid='public.yc_claim_rpc(text,jsonb)'::regprocedure").fetchone(), attributes)
                self.assertEqual([r for r in self.history() if r[0] != shared.MAIL_LEASE_VERSION], previous)
                self.assertEqual(self.conn.execute("SELECT * FROM auth.users").fetchall(), existing_users)
                receipt = self.history()
                with patch.object(shared, "mail_lease_catalog", side_effect=AssertionError("replay catalog lookup")):
                    self.assertEqual(self.apply()["state"], "applied")
                self.assertEqual(self.history(), receipt)
                if not acceptance_first:
                    self.later_migrations()
                for name, source in (("authority", shared.source()), ("claims", shared.claim_source()),
                                     ("approvals", shared.approval_source()), ("acceptances", shared.acceptance_source()),
                                     ("claim-mail", shared.mail_lease_source())):
                    self.assertEqual(shared.inspect(self.conn, source, name), "applied")
                self.assertEqual(self.lease(), {})
                with self.conn.transaction(force_rollback=True):
                    self.conn.execute("ALTER FUNCTION public.yc_claim_rpc(text,jsonb) STABLE")
                    with self.assertRaisesRegex(shared.SharedMigrationError, "catalog_mismatch"):
                        shared.inspect(self.conn, shared.mail_lease_source(), "claim-mail")

    def test_failure_rolls_back_function_and_receipt_and_rejects_unknown_body(self):
        before = self.history()
        definition = self.conn.execute("SELECT pg_get_functiondef('public.yc_claim_rpc(text,jsonb)'::regprocedure)").fetchone()[0]
        original_catalog = shared.mail_lease_catalog
        calls = 0
        def fail_snapshot(conn):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError("injected snapshot failure")
            return original_catalog(conn)
        with patch.object(shared, "mail_lease_catalog", side_effect=fail_snapshot):
            with self.assertRaisesRegex(RuntimeError, "injected snapshot failure"):
                self.apply()
        self.assertEqual(self.history(), before)
        self.assertEqual(self.conn.execute("SELECT pg_get_functiondef('public.yc_claim_rpc(text,jsonb)'::regprocedure)").fetchone()[0], definition)
        with self.conn.transaction(force_rollback=True):
            self.conn.execute(definition.replace("v_now timestamptz", "-- Unexpected later edit\n v_now timestamptz", 1))
            with self.assertRaisesRegex(shared.SharedMigrationError, "mail_lease_predecessor_mismatch"):
                self.apply()
            with self.assertRaisesRegex(psycopg.errors.RaiseException, "unexpected claim RPC body"):
                with self.conn.transaction():
                    self.conn.execute(shared.mail_lease_execution(shared.mail_lease_source()))
        self.assertEqual(self.history(), before)
        self.apply()
        self.assertEqual(self.apply(execute=False)["state"], "applied")


if __name__ == "__main__":
    unittest.main(verbosity=2)
