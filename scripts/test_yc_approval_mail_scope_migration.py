"""Exercise scoped approval delivery on a disposable loopback PostgreSQL database."""

import unittest
import uuid
from unittest.mock import patch

import psycopg
from psycopg.types.json import Jsonb

import migrate_shared_auth as shared
import test_yc_claim_mail_migration as claim_test


class ApprovalMailScopeMigrationTest(unittest.TestCase):
    setUpClass = classmethod(claim_test.ClaimMailMigrationTest.setUpClass.__func__)
    apply = claim_test.ClaimMailMigrationTest.apply
    rpc = claim_test.ClaimMailMigrationTest.rpc
    claim = claim_test.ClaimMailMigrationTest.claim
    history = claim_test.ClaimMailMigrationTest.history
    later_migrations = claim_test.ClaimMailMigrationTest.later_migrations

    def setUp(self):
        claim_test.ClaimMailMigrationTest.setUp(self)
        self.later_migrations()
        self.apply()

    def scope(self, execute=True):
        return self.apply("approval-mail-scope", shared.approval_scope_source(), execute)

    def mail(self, op, payload, conn=None):
        conn = conn or self.conn
        try:
            with conn.transaction():
                conn.execute("SET LOCAL ROLE promotion_evidence_proxy")
                return conn.execute("SELECT public.yc_claim_approval_mail_rpc(%s,%s)", (op, Jsonb(payload))).fetchone()[0]
        finally:
            conn.execute("RESET ROLE")

    def approved(self):
        identity = uuid.uuid4().hex
        email = f"customer-{identity}@example.test"
        claim = self.rpc("submit", {
            "submitted_email": email, "founder_email": f"founder-{identity}@example.test",
            "verification_reference": identity * 2, "company_identity": f"https://www.ycombinator.com/companies/example-{identity}",
            "evidence": {"verified": True}, "state": "manual_review", "reason": "email_mismatch",
        })
        user, team = uuid.uuid4(), uuid.uuid4()
        created = self.conn.execute("INSERT INTO auth.users(id,email,email_confirmed_at) VALUES(%s,%s,clock_timestamp()) RETURNING created_at", (user, email)).fetchone()[0]
        payload = {"id": claim["id"], "user_id": str(user), "team_id": str(team), "home_region": "use",
                   "team_created_at": created.isoformat(), "team_eligible": True, "actor_id": str(uuid.uuid4()),
                   "request_id": str(uuid.uuid4()), "expected_revision": claim["revision"],
                   "reason": "Synthetic approval", "evidence_reference": "synthetic-review"}
        for op in ("prepare-approve", "approve"):
            with self.conn.transaction():
                self.conn.execute("SET LOCAL ROLE promotion_evidence_proxy")
                self.conn.execute("SELECT public.yc_staff_claim_rpc(%s,%s)", (op, Jsonb(payload)))
        return claim["id"]

    def rows(self, table="yc_claim_approval_mail"):
        return self.conn.execute(psycopg.sql.SQL("SELECT * FROM public.{} ORDER BY claim_id").format(
            psycopg.sql.Identifier(table))).fetchall()

    def lease(self, claim, conn=None):
        return self.mail("lease-for-claim", {"claim_id": claim, "lease_id": str(uuid.uuid4())}, conn)

    def test_old_database_rejects_new_operation_without_writes(self):
        selected = self.approved()
        self.approved()
        self.claim(token_expires_at="clock_timestamp()-interval '1 hour'")
        before, tokens = self.rows(), self.rows("yc_claim_mail")
        with self.assertRaisesRegex(psycopg.errors.InvalidParameterValue, "unknown mail operation"):
            self.lease(selected)
        self.assertEqual(self.rows(), before)
        self.assertEqual(self.rows("yc_claim_mail"), tokens)

    def test_mixed_queue_scope_precedes_mutation_and_row_locking(self):
        self.scope()
        unrelated, selected = self.approved(), self.approved()
        self.claim(token_expires_at="clock_timestamp()-interval '1 hour'")
        before = self.conn.execute("SELECT * FROM yc_claim_approval_mail WHERE claim_id=%s", (unrelated,)).fetchone()
        tokens = self.rows("yc_claim_mail")
        with psycopg.connect(self.dsn) as holder, psycopg.connect(self.dsn) as probe:
            # Hold the selected lease open, so a second connection detects even
            # transient row locks on unrelated records with NOWAIT.
            with holder.transaction():
                self.assertEqual(self.lease(selected, holder)["claim_id"], selected)
                probe.execute("SELECT * FROM yc_claim_approval_mail WHERE claim_id=%s FOR UPDATE NOWAIT", (unrelated,))
                probe.execute("SELECT * FROM yc_claim_mail FOR UPDATE NOWAIT")
                self.assertEqual(self.lease(selected), {})
                self.assertEqual(self.lease(str(uuid.uuid4())), {})
        self.assertEqual(self.conn.execute("SELECT * FROM yc_claim_approval_mail WHERE claim_id=%s", (unrelated,)).fetchone(), before)
        self.assertEqual(self.rows("yc_claim_mail"), tokens)
        self.assertEqual(self.conn.execute("SELECT attempts,last_error FROM yc_claim_approval_mail WHERE claim_id=%s", (selected,)).fetchone(), (1, "delivery_unknown"))
        self.assertEqual(self.mail("lease", {"lease_id": str(uuid.uuid4()), "claim_id": "ignored-by-ordinary-mode"})["claim_id"], unrelated)

    def test_invalid_scope_never_leases_and_ineligible_fixture_never_falls_back(self):
        self.scope()
        selected = self.approved()
        self.approved()
        valid = {"claim_id": selected, "lease_id": str(uuid.uuid4())}
        before = self.rows()
        for field in ("claim_id", "lease_id"):
            for value in (None, "", "bad", str(uuid.UUID(int=0))):
                with self.subTest(field=field, value=value), self.assertRaises(psycopg.DataError):
                    self.mail("lease-for-claim", valid | {field: value})
        for payload in (None, [], {}, {"lease_id": valid["lease_id"]}, {"claim_id": selected}):
            with self.subTest(payload=payload), self.assertRaises(psycopg.DataError):
                self.mail("lease-for-claim", payload)
        self.assertEqual(self.rows(), before)
        for condition in ("attempts=8", "last_error='delivery_unknown'", "last_error='delivery_rejected'",
                          "next_attempt_at=clock_timestamp()+interval '1 hour'", "lease_until=clock_timestamp()+interval '1 hour'"):
            with self.subTest(condition=condition), self.conn.transaction(force_rollback=True):
                self.conn.execute("UPDATE yc_claim_approval_mail SET " + condition + " WHERE claim_id=%s", (selected,))
                self.assertEqual(self.lease(selected), {})
        with self.conn.transaction(force_rollback=True):
            self.conn.execute("UPDATE yc_claim_approval_mail SET approved_email='different@example.test' WHERE claim_id=%s", (selected,))
            self.assertEqual(self.lease(selected), {})
        self.assertEqual(self.rows(), before)

    def test_finish_requires_exact_message_lease_and_unexpired_reservation(self):
        self.scope()
        selected, unrelated = self.approved(), self.approved()
        lease = str(uuid.uuid4())
        job = self.mail("lease-for-claim", {"claim_id": selected, "lease_id": lease})
        finish = {"id": selected, "message_id": job["message_id"], "lease_id": lease, "success": True}
        before = self.rows()
        for field, value in (("id", unrelated), ("message_id", str(uuid.uuid4())), ("lease_id", str(uuid.uuid4()))):
            self.mail("finish", finish | {field: value})
            self.assertEqual(self.rows(), before)
        with self.conn.transaction(force_rollback=True):
            self.conn.execute("UPDATE yc_claim_approval_mail SET lease_until=clock_timestamp()-interval '1 second' WHERE claim_id=%s", (selected,))
            self.mail("finish", finish)
            self.assertIsNone(self.conn.execute("SELECT sent_at FROM yc_claim_approval_mail WHERE claim_id=%s", (selected,)).fetchone()[0])
            self.assertEqual(self.lease(selected), {})
        self.mail("finish", finish)
        self.assertEqual(self.conn.execute("SELECT sent_at IS NOT NULL,lease_id,last_error FROM yc_claim_approval_mail WHERE claim_id=%s", (selected,)).fetchone(), (True, None, None))

    def test_receipts_catalog_attributes_and_replay_preserve_history(self):
        original = self.history()
        regional = shared.ordinary_history(self.conn)
        attributes = self.conn.execute("SELECT oid,proowner,proacl,proconfig,prosecdef,provolatile FROM pg_proc WHERE oid='public.yc_claim_approval_mail_rpc(text,jsonb)'::regprocedure").fetchone()
        self.assertEqual(self.scope(False)["state"], "pending")
        self.scope()
        self.assertEqual(self.conn.execute("SELECT oid,proowner,proacl,proconfig,prosecdef,provolatile FROM pg_proc WHERE oid='public.yc_claim_approval_mail_rpc(text,jsonb)'::regprocedure").fetchone(), attributes)
        self.assertEqual([r for r in self.history() if r[0] != shared.APPROVAL_SCOPE_VERSION], original)
        self.assertEqual(shared.ordinary_history(self.conn), regional)
        self.assertIn(shared.APPROVAL_SCOPE_VERSION, shared.receipt_versions(self.conn))
        for name, source in (("authority", shared.source), ("claims", shared.claim_source), ("approvals", shared.approval_source),
                             ("acceptances", shared.acceptance_source), ("claim-mail", shared.mail_lease_source),
                             ("approval-mail-scope", shared.approval_scope_source)):
            self.assertEqual(shared.inspect(self.conn, source(), name), "applied")
        receipts = self.history()
        with patch.object(shared, "approval_scope_catalog", side_effect=AssertionError("replay catalog lookup")):
            self.assertEqual(self.scope()["state"], "applied")
        self.assertEqual(self.history(), receipts)
        for mutation in ("ALTER FUNCTION public.yc_claim_approval_mail_rpc(text,jsonb) SECURITY INVOKER",
                         "GRANT EXECUTE ON FUNCTION public.yc_claim_approval_mail_rpc(text,jsonb) TO authenticated"):
            with self.subTest(mutation=mutation), self.conn.transaction(force_rollback=True):
                self.conn.execute(mutation)
                with self.assertRaises(shared.SharedMigrationError):
                    self.scope(False)

    def test_predecessor_and_atomic_failure_reject_drift(self):
        before, catalog = self.history(), shared.approval_scope_catalog(self.conn)
        original_snapshot = shared.approval_scope_catalog
        calls = 0
        def fail_snapshot(conn):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError("injected snapshot failure")
            return original_snapshot(conn)
        with patch.object(shared, "approval_scope_catalog", side_effect=fail_snapshot):
            with self.assertRaisesRegex(RuntimeError, "injected snapshot failure"):
                self.scope()
        self.assertEqual(self.history(), before)
        self.assertEqual(shared.approval_scope_catalog(self.conn), catalog)
        with self.conn.transaction(force_rollback=True):
            self.conn.execute("ALTER FUNCTION public.yc_claim_approval_mail_rpc(text,jsonb) SECURITY INVOKER")
            with self.assertRaisesRegex(shared.SharedMigrationError, "approval_scope_predecessor_mismatch"):
                self.scope()
        with self.conn.transaction(force_rollback=True):
            self.conn.execute(f"DELETE FROM {shared.LEDGER} WHERE version=%s", (shared.ACCEPTANCE_VERSION,))
            with self.assertRaisesRegex(shared.SharedMigrationError, "acceptances_migration_required"):
                self.scope()
        self.assertEqual(self.history(), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
