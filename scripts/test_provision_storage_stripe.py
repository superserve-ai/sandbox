import contextlib
import copy
import io
import unittest
from unittest.mock import patch
import urllib.error

from provision_storage_stripe import (
    EVENT, LOOKUP, PATHS, PRODUCT_ID, PRODUCT_NAME, ProvisionError, Stripe,
    definition, provision,
)


def spec():
    return definition({"schema_version": 1, "storage_usd_per_gib_second": "0.000000030000", "tax_behavior": "exclusive"})


def catalog():
    return {
        "meter": [{"id": "mtr_example", "livemode": False, "event_name": EVENT,
                   "status": "active", "default_aggregation": {"formula": "sum"}, "event_time_window": None,
                   "customer_mapping": {"type": "by_id", "event_payload_key": "stripe_customer_id"},
                   "value_settings": {"event_payload_key": "value"}}],
        "product": [{"id": PRODUCT_ID, "livemode": False, "name": PRODUCT_NAME, "active": True}],
        "price": [{"id": "price_example", "livemode": False, "active": True, "product": PRODUCT_ID,
                   "currency": "usd", "billing_scheme": "per_unit", "type": "recurring", "lookup_key": LOOKUP,
                   "unit_amount_decimal": "0.010800000000", "tax_behavior": "exclusive",
                   "recurring": {"meter": "mtr_example", "interval": "month", "interval_count": 1,
                                 "usage_type": "metered"}}],
    }


class FakeStripe(Stripe):
    def __init__(self, data=None, apply=False):
        super().__init__("rk_test_fixture", False, "acct_example", apply)
        self.data = copy.deepcopy(data if data is not None else {k: [] for k in PATHS})
        self.calls = []
        self.fail_after = None
        self.account_response = self.account

    def request(self, method, path, params=None):
        self.calls.append((method, path, params))
        if path == "/v1/account":
            return {"id": self.account_response}
        kind = next(k for k, p in PATHS.items() if p == path)
        if method == "GET":
            rows = self.data[kind]
            if kind == "price":
                active = (params or {}).get("active", "true") == "true"
                rows = [row for row in rows if row["active"] is active]
            return {"data": copy.deepcopy(rows), "has_more": False}
        if not self.apply:
            raise AssertionError("Write attempted in preview")
        obj = copy.deepcopy(catalog()[kind][0])
        self.data[kind].append(obj)
        if kind == self.fail_after:
            self.fail_after = None
            raise ProvisionError("Lost create response")
        return obj


class ProvisionTests(unittest.TestCase):
    def run_quiet(self, stripe):
        with contextlib.redirect_stderr(io.StringIO()):
            return provision(stripe, spec())

    def test_exact_conversion_and_invalid_rates(self):
        self.assertEqual(spec()["unit_amount_decimal"], "0.0108")
        for rate in ("NaN", "Infinity", "-1", "0", 0.1, "1e-8", "0.000000000000000001"):
            with self.subTest(rate=rate), self.assertRaises(ProvisionError):
                definition({"schema_version": 1, "storage_usd_per_gib_second": rate, "tax_behavior": "exclusive"})

    def test_preview_empty_catalog_never_writes(self):
        stripe = FakeStripe()
        result = self.run_quiet(stripe)
        self.assertEqual(result["actions"], dict.fromkeys(PATHS, "create"))
        self.assertTrue(all(method == "GET" for method, _, _ in stripe.calls))

    def test_create_then_rerun_is_noop_and_price_links_meter(self):
        stripe = FakeStripe(apply=True)
        result = self.run_quiet(stripe)
        writes = [(p, args) for method, p, args in stripe.calls if method == "POST"]
        self.assertEqual(len(writes), 3)
        self.assertNotIn("event_time_window", writes[0][1])
        self.assertEqual(writes[2][1]["recurring[meter]"], result["ids"]["meter"])
        self.assertEqual(writes[2][1]["unit_amount_decimal"], "0.0108")
        stripe.calls.clear()
        self.assertEqual(self.run_quiet(stripe)["actions"], dict.fromkeys(PATHS, "reuse"))
        self.assertTrue(all(method == "GET" for method, _, _ in stripe.calls))

    def test_lost_create_response_recovers_without_duplicate(self):
        for kind in PATHS:
            with self.subTest(kind=kind):
                stripe = FakeStripe(apply=True)
                stripe.fail_after = kind
                with self.assertRaises(ProvisionError):
                    self.run_quiet(stripe)
                self.run_quiet(stripe)
                self.assertEqual({k: len(v) for k, v in stripe.data.items()}, dict.fromkeys(PATHS, 1))

    def test_manual_product_identity_follows_meter_price_and_rejects_extra_price(self):
        data = catalog()
        data["product"][0].update(id="prod_manual", name="Manually named storage")
        data["price"][0].update(product="prod_manual", lookup_key=None)
        stripe = FakeStripe(data, apply=True)
        self.assertEqual(self.run_quiet(stripe)["ids"]["product"], "prod_manual")
        self.assertTrue(all(method == "GET" for method, _, _ in stripe.calls))
        stripe.data["price"].append({**data["price"][0], "id": "price_other", "recurring": None})
        with self.assertRaises(ProvisionError):
            self.run_quiet(stripe)

    def test_conflicts_abort_before_any_write(self):
        mutations = [
            lambda d: d["meter"][0].update(event_time_window="hour"),
            lambda d: d["meter"][0].update(status="inactive"),
            lambda d: d["price"][0].update(unit_amount_decimal="1.08"),
            lambda d: d["price"][0].update(tax_behavior="inclusive"),
            lambda d: d["price"][0]["recurring"].update(meter="mtr_other"),
            lambda d: d["price"][0].update(transform_quantity={"divide_by": 1000, "round": "up"}),
            lambda d: d["product"][0].update(active=False),
            lambda d: d["meter"].append({**d["meter"][0], "id": "mtr_other"}),
            lambda d: d["price"].append({**d["price"][0], "id": "price_other"}),
            lambda d: d["product"].clear(),
        ]
        for mutation in mutations:
            stripe = FakeStripe(catalog(), apply=True)
            mutation(stripe.data)
            with self.subTest(mutation=mutation), self.assertRaises(ProvisionError):
                self.run_quiet(stripe)
            self.assertTrue(all(method == "GET" for method, _, _ in stripe.calls))

    def test_wrong_account_or_mode_rejected(self):
        stripe = FakeStripe(apply=True)
        stripe.account_response = "acct_other"
        with self.assertRaises(ProvisionError):
            self.run_quiet(stripe)
        self.assertEqual(len(stripe.calls), 1)
        with self.assertRaises(ProvisionError):
            Stripe("rk_live_fixture", False, "acct_example")
        stripe = FakeStripe(catalog(), apply=True)
        stripe.data["meter"][0]["livemode"] = True
        with self.assertRaises(ProvisionError):
            self.run_quiet(stripe)

    def test_archived_storage_prices_abort_before_any_write(self):
        for apply in (False, True):
            for active_price in (False, True):
                with self.subTest(apply=apply, active_price=active_price):
                    data = catalog()
                    archived = {**data["price"][0], "id": "price_archived", "active": False}
                    data["price"] = data["price"] + [archived] if active_price else [archived]
                    stripe = FakeStripe(data, apply=apply)
                    with self.assertRaises(ProvisionError):
                        self.run_quiet(stripe)
                    self.assertTrue(all(method == "GET" for method, _, _ in stripe.calls))

    def test_price_inventory_paginates_both_states_with_separate_cursors(self):
        stripe = Stripe("rk_test_fixture", False, "acct_example")
        def page(item_id, more):
            return {"data": [{"id": item_id, "livemode": False}], "has_more": more}
        with patch.object(stripe, "request", side_effect=[
            page("price_active_1", True), page("price_active_2", False),
            page("price_archived_1", True), page("price_archived_2", False),
        ]) as request:
            self.assertEqual(len(stripe.inventory("price")), 4)
            self.assertEqual([call.args[2] for call in request.call_args_list], [
                {"limit": 100, "active": "true"},
                {"limit": 100, "active": "true", "starting_after": "price_active_1"},
                {"limit": 100, "active": "false"},
                {"limit": 100, "active": "false", "starting_after": "price_archived_1"},
            ])

    def test_paginated_inventory_and_incomplete_response(self):
        stripe = Stripe("rk_test_fixture", False, "acct_example")
        with patch.object(stripe, "request", side_effect=[
            {"data": [{"id": "mtr_first", "livemode": False}], "has_more": True},
            {"data": catalog()["meter"], "has_more": False},
        ]) as request:
            self.assertEqual(len(stripe.inventory("meter")), 2)
            self.assertEqual(request.call_args.args[2]["starting_after"], "mtr_first")
        for page in ({"data": [], "has_more": True}, {"data": []}):
            with patch.object(stripe, "request", return_value=page), self.assertRaises(ProvisionError):
                stripe.inventory("meter")

    def test_http_scope_idempotency_and_secret_redaction(self):
        stripe = Stripe("rk_test_fixture", False, "acct_example", apply=True)
        requests = []
        def respond(request, timeout):
            requests.append(request)
            return io.BytesIO(b'{"id":"prod_example"}')
        with patch.object(stripe.opener, "open", side_effect=respond):
            for _ in range(2):
                stripe.request("POST", PATHS["product"], {"name": "Storage"})
            self.assertEqual(requests[0].get_header("Idempotency-key"), requests[1].get_header("Idempotency-key"))
            with self.assertRaises(ProvisionError):
                stripe.request("POST", "/v1/subscriptions", {})
            stripe.apply = False
            with self.assertRaises(ProvisionError):
                stripe.request("POST", PATHS["product"], {})
        error = urllib.error.HTTPError("https://api.stripe.com", 403, "rk_test_fixture", {}, io.BytesIO(b'rk_test_fixture'))
        with patch.object(stripe.opener, "open", side_effect=error):
            with self.assertRaises(ProvisionError) as caught:
                stripe.request("GET", "/v1/account")
            self.assertNotIn("rk_test_fixture", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
