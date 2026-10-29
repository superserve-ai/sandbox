import contextlib
import io
import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
from unittest.mock import patch

import event_credit

ACCOUNT = "acct_example"
TEAM = "00000000-0000-4000-8000-000000000006"
CUSTOMER = "cus_example"
OLD_CUSTOMER = "cus_example_old"
LABEL = "event-example"


def response(body):
    return contextlib.nullcontext(io.BytesIO(json.dumps(body).encode()))


class FakeStripe:
    def __init__(self, list_barrier=None, searchable=()):
        self.grants, self.keys, self.posts = {}, {}, 0
        self.lock, self.list_barrier, self.searchable = threading.Lock(), list_barrier, list(searchable)

    def __call__(self, req, timeout):
        url = urllib.parse.urlparse(req.full_url)
        method = req.get_method()
        if url.path == "/v1/account":
            return response({"id": ACCOUNT})
        if url.path == "/v1/customers/search":
            return response({"data": [{"id": c} for c in self.searchable], "has_more": False})
        if url.path == "/v1/customers/" + CUSTOMER:
            return response({"id": CUSTOMER, "livemode": False, "metadata": {"team_id": TEAM}})
        if url.path == "/v1/billing/credit_grants" and method == "GET":
            customer = urllib.parse.parse_qs(url.query)["customer"][0]
            with self.lock:
                snapshot = {"data": [g for g in self.grants.values() if g["customer"] == customer], "has_more": False}
            if self.list_barrier:
                self.list_barrier.wait(timeout=5)
            return response(snapshot)
        if url.path == "/v1/billing/credit_grants" and method == "POST":
            params = urllib.parse.parse_qs(req.data.decode())
            key = req.get_header("Idempotency-key")
            with self.lock:
                self.posts += 1
                if key in self.keys:
                    if self.keys[key][0] != params:
                        body = io.BytesIO(json.dumps({"error": {"type": "idempotency_error"}}).encode())
                        raise urllib.error.HTTPError(req.full_url, 400, "Bad Request", {}, body)
                    return response(self.grants[self.keys[key][1]])
                grant_id = f"credgr_test_{len(self.grants) + 1}"
                self.grants[grant_id] = {
                    "id": grant_id, "customer": params["customer"][0], "category": params["category"][0],
                    "priority": int(params["priority"][0]), "expires_at": None, "voided_at": None, "livemode": False,
                    "amount": {"type": "monetary", "monetary": {"currency": "usd",
                                                                "value": int(params["amount[monetary][value]"][0])}},
                    "applicability_config": {"scope": {"price_type": params["applicability_config[scope][price_type]"][0]}},
                    "metadata": {"event_label": params["metadata[event_label]"][0], "team_id": params["metadata[team_id]"][0]}}
                self.keys[key] = (params, grant_id)
                return response(self.grants[grant_id])
        if url.path.startswith("/v1/billing/credit_grants/") and method == "GET":
            with self.lock:
                return response(self.grants.get(url.path.rsplit("/", 1)[1]))
        raise AssertionError(f"unexpected Stripe request {method} {url.path}")


def paid_row(trial_event_usd=None):
    return {"team_id": TEAM, "exists": True, "managed": False, "awaiting_plan": False, "kind": "subscription",
            "plan_key": "developer_monthly", "family": "developer", "contract_offer": "developer_monthly",
            "contract": True, "contract_customer": CUSTOMER, "customer": CUSTOMER,
            "subscription_status": "active", "trial_event_usd": trial_event_usd, "trial_event_remaining_usd": 0,
            "known_customers": [CUSTOMER]}


def stripe():
    return event_credit.Stripe("sk_test_example", False, ACCOUNT, True, event_credit.API_VERSION)


class EventCreditTest(unittest.TestCase):
    def run_main(self, row, amount, fake, reloaded=None):
        grants = tempfile.NamedTemporaryFile("w", suffix=".csv")
        self.addCleanup(grants.close)
        grants.write(f"{TEAM},{amount}\n")
        grants.flush()
        argv = ["event_credit.py", "--grants", grants.name, "--label", LABEL, "--database-url", "postgres://example",
                "--environment", "staging", "--expected-account", ACCOUNT, "--apply"]
        out, err = io.StringIO(), io.StringIO()
        with patch("sys.argv", argv), patch.dict(os.environ, {"STRIPE_SECRET_KEY": "sk_test_example"}), \
                patch.object(event_credit, "load_routes", side_effect=[[row], [reloaded or row]]), \
                patch("urllib.request.urlopen", fake), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = event_credit.main()
        return code, json.loads(out.getvalue())["teams"][0]

    def test_trial_grant_then_paid_checkout_rerun_does_not_grant_again(self):
        fake = FakeStripe()
        code, team = self.run_main(paid_row(trial_event_usd=100), "100", fake)
        self.assertEqual((code, team["outcome"], fake.posts), (0, "already granted as trial credit", 0))
        code, team = self.run_main(paid_row(trial_event_usd=100), "80", fake)
        self.assertEqual((code, fake.posts), (2, 0))
        self.assertTrue(team["outcome"].startswith("REFUSED"))

    def test_billing_state_changed_before_create_grants_nothing(self):
        changes = {"customer": {"customer": "cus_example_new", "known_customers": [CUSTOMER, "cus_example_new"]},
                   "status": {"subscription_status": "canceled"}, "plan": {"kind": "free", "plan_key": "free", "family": "free"}}
        for name, change in changes.items():
            with self.subTest(name):
                fake = FakeStripe()
                code, team = self.run_main(paid_row(), "100", fake, {**paid_row(), **change})
                self.assertEqual((code, team["outcome"], fake.posts),
                                 (2, "REFUSED: billing state changed during the run; rerun", 0))

    def credit_old_customer(self, fake):
        old = event_credit.grant_form(TEAM, OLD_CUSTOMER, LABEL, 10000)
        with patch("urllib.request.urlopen", fake):
            stripe().request("POST", "/v1/billing/credit_grants", old, "earlier-run")
        fake.posts = 0

    def test_customer_replaced_after_grant_rerun_does_not_grant_again(self):
        fake = FakeStripe()
        self.credit_old_customer(fake)
        row = paid_row()
        row["known_customers"] = [OLD_CUSTOMER, CUSTOMER]
        code, team = self.run_main(row, "100", fake)
        self.assertEqual((code, team["grant_customer"], fake.posts, len(fake.grants)), (2, OLD_CUSTOMER, 0, 1))
        self.assertIn("previous customer", team["outcome"])
        code, team = self.run_main(row, "80", fake)
        self.assertEqual((code, fake.posts, len(fake.grants)), (2, 0, 1))

    def test_replaced_customer_found_only_through_stripe_search(self):
        fake = FakeStripe(searchable=[OLD_CUSTOMER])
        self.credit_old_customer(fake)
        code, team = self.run_main(paid_row(), "100", fake)
        self.assertEqual((code, team["grant_customer"], fake.posts, len(fake.grants)), (2, OLD_CUSTOMER, 0, 1))

    def test_overlapping_runs_with_different_amounts_grant_once(self):
        fake = FakeStripe(threading.Barrier(2))
        results = {}

        def run(cents):
            results[cents] = event_credit.stripe_team(stripe(), paid_row(), LABEL, cents, event_credit.API_VERSION,
                                                      lambda team: paid_row())

        with patch("urllib.request.urlopen", fake):
            threads = [threading.Thread(target=run, args=(cents,)) for cents in (8000, 10000)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        self.assertEqual(len(fake.grants), 1)
        outcomes = sorted(r["outcome"].split(":")[0] for r in results.values())
        self.assertEqual(outcomes, ["REFUSED", "granted"])
        refused = next(r for r in results.values() if r["outcome"].startswith("REFUSED"))
        self.assertTrue(refused["conflict"])


if __name__ == "__main__":
    unittest.main()
