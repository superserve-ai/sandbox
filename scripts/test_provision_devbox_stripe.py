import contextlib
import copy
import io
import json
from decimal import Decimal
from pathlib import Path
import re
import unittest

from provision_devbox_stripe import API_VERSION, PRO, USAGE, provision
from provision_storage_stripe import PATHS, ProvisionError, Stripe

ROOT = Path(__file__).resolve().parents[1]


class FakeStripe(Stripe):
    def __init__(self, apply=False):
        super().__init__("sk_test_fixture", False, "acct_example", apply, API_VERSION, "devbox-catalog-v1")
        self.data = {kind: [] for kind in PATHS}
        self.writes = []

    def request(self, method, path, params=None):
        if path == "/v1/account":
            return {"id": self.account}
        kind = next(k for k, p in PATHS.items() if p == path)
        if method == "GET":
            active = (params or {}).get("active", "true") == "true"
            rows = [r for r in self.data[kind] if kind != "price" or r["active"] is active]
            return {"data": copy.deepcopy(rows), "has_more": False}
        if not self.apply:
            raise AssertionError("Write attempted in preview")
        self.writes.append((kind, params))
        obj = self.create(kind, params, len(self.writes))
        self.data[kind].append(obj)
        return copy.deepcopy(obj)

    @staticmethod
    def create(kind, params, serial):
        base = {"livemode": False}
        if kind == "meter":
            return {**base, "id": f"mtr_{serial}", "event_name": params["event_name"], "status": "active",
                    "default_aggregation": {"formula": params["default_aggregation[formula]"]},
                    "event_time_window": None,
                    "customer_mapping": {"type": params["customer_mapping[type]"],
                                         "event_payload_key": params["customer_mapping[event_payload_key]"]},
                    "value_settings": {"event_payload_key": params["value_settings[event_payload_key]"]}}
        if kind == "product":
            return {**base, "id": params["id"], "name": params["name"], "active": True}
        amount = params.get("unit_amount_decimal", str(params.get("unit_amount")))
        return {**base, "id": f"price_{serial}", "active": True, "currency": params["currency"],
                "billing_scheme": params["billing_scheme"], "type": "recurring", "product": params["product"],
                "transform_quantity": None, "lookup_key": params["lookup_key"], "unit_amount_decimal": amount,
                "tax_behavior": params["tax_behavior"], "currency_options": {"usd": {"unit_amount_decimal": amount}},
                "recurring": {"meter": params.get("recurring[meter]"), "interval": params["recurring[interval]"],
                              "interval_count": params["recurring[interval_count]"],
                              "usage_type": params["recurring[usage_type]"]}}


def run_quiet(stripe):
    with contextlib.redirect_stderr(io.StringIO()):
        return provision(stripe)


class ProvisionTests(unittest.TestCase):
    def test_preview_never_writes_and_lists_everything_missing(self):
        result = run_quiet(FakeStripe())
        self.assertEqual(result["mode"], "preview")
        self.assertEqual(result["create"]["vcpu"], ["meter", "product", "price"])
        self.assertEqual(result["create"]["pro_annual"], ["price"])

    def test_apply_creates_the_catalog_the_api_validates_and_rerun_reuses_it(self):
        stripe = FakeStripe(apply=True)
        env = run_quiet(stripe)["github_environment_variables"]
        prices = {p["lookup_key"]: p for p in stripe.data["price"]}
        meters = {m["event_name"]: m["id"] for m in stripe.data["meter"]}
        self.assertEqual(prices["superserve_vcpu_hours_monthly"]["unit_amount_decimal"], "5.04")
        self.assertEqual(prices["superserve_memory_gib_hours_monthly"]["unit_amount_decimal"], "1.62")
        self.assertEqual(prices["superserve_storage_gib_hours_monthly"]["unit_amount_decimal"], "0.0108")
        self.assertEqual(prices["superserve_pro_monthly"]["unit_amount_decimal"], "120000")
        self.assertEqual(prices["superserve_pro_annual"]["recurring"]["interval"], "year")
        pro_product = prices["superserve_pro_monthly"]["product"]
        self.assertNotIn(pro_product, {prices[u["lookup"]]["product"] for u in USAGE})
        resources = json.loads(env["DEVBOX_CONFIG_BILLING_RESOURCE_CONFIG"])
        self.assertEqual([r["stripe_price_id"] for r in resources],
                         env["DEVBOX_CONFIG_STRIPE_CHECKOUT_PRICE_IDS"].split(","))
        for r in resources:
            self.assertEqual(prices[next(u["lookup"] for u in USAGE if u["resource"] == r["resource_key"])]
                             ["recurring"]["meter"], meters[r["stripe_event_name"]])
        self.assertEqual(env["DEVBOX_CONFIG_STRIPE_PRO_MONTHLY_PRICE_ID"], prices["superserve_pro_monthly"]["id"])
        stripe.writes.clear()
        self.assertEqual(run_quiet(stripe)["github_environment_variables"], env)
        self.assertEqual(stripe.writes, [])

    def test_existing_price_that_differs_in_any_validated_term_stops_before_writing(self):
        changes = {
            "superserve_vcpu_hours_monthly": [
                ("unit_amount_decimal", "5.05"), ("tax_behavior", "inclusive"),
                ("currency_options", {"usd": {}, "eur": {}}), ("custom_unit_amount", {"minimum": 1}),
                ("recurring", {"trial_period_days": 7}), ("recurring", {"meter": "mtr_other"}),
            ],
            "superserve_pro_monthly": [
                ("unit_amount_decimal", "120000.00"), ("tax_behavior", "inclusive"),
                ("currency_options", {"usd": {}, "eur": {}}), ("recurring", {"trial_period_days": 7}),
                ("recurring", {"interval": "year"}),
            ],
        }
        for lookup, edits in changes.items():
            for field, value in edits:
                with self.subTest(lookup=lookup, field=field, value=value):
                    stripe = FakeStripe(apply=True)
                    run_quiet(stripe)
                    price = next(p for p in stripe.data["price"] if p["lookup_key"] == lookup)
                    if field == "recurring":
                        price["recurring"].update(value)
                    else:
                        price[field] = value
                    stripe.writes.clear()
                    with self.assertRaises(ProvisionError):
                        run_quiet(stripe)
                    self.assertEqual(stripe.writes, [])


class SourceAgreementTests(unittest.TestCase):
    def test_usage_rates_match_the_seeded_pricing_rates(self):
        writers = [p for p in sorted((ROOT / "supabase/migrations").glob("*.sql"))
                   if re.search(r"(INSERT INTO|UPDATE) pricing_rate\b", p.read_text())]
        self.assertEqual([p.name for p in writers], ["20260617000003_billing_pricing_credits.sql"])
        rates = dict(re.findall(r"\('payg', '(\w+)', 'second', ([0-9.]+),", writers[0].read_text()))
        self.assertEqual({u["resource"]: Decimal(u["usd_per_second"]) for u in USAGE},
                         {k: Decimal(v) for k, v in rates.items()})

    def test_pro_amounts_match_the_api_offers(self):
        source = (ROOT / "internal/api/billing_pro_checkout.go").read_text()
        offers = dict(re.findall(r'case "(pro_\w+)":\s*return proOffer\{Key: key, Amount: (\d+)', source))
        self.assertEqual({p["offer"]: p["cents"] for p in PRO}, {k: int(v) for k, v in offers.items()})


if __name__ == "__main__":
    unittest.main()
