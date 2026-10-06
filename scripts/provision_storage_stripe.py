#!/usr/bin/env python3
"""Preview or provision the shared storage catalog; never activate billing."""

from __future__ import annotations

import argparse
from decimal import Decimal, InvalidOperation, localcontext
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

API_VERSION = "2026-08-26.dahlia"
EVENT = "storage_gib_hours"
PRODUCT_ID = "superserve_storage_gib_hours"
PRODUCT_NAME = "Superserve Storage"
LOOKUP = "superserve_storage_gib_hours_monthly"
PATHS = {"meter": "/v1/billing/meters", "product": "/v1/products", "price": "/v1/prices"}


class ProvisionError(Exception):
    pass


def definition(raw):
    if set(raw) != {"schema_version", "storage_usd_per_gib_second", "tax_behavior"}:
        raise ProvisionError("Definition must contain schema_version, storage_usd_per_gib_second, tax_behavior")
    if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
        raise ProvisionError("Unsupported definition schema_version")
    rate_text = raw["storage_usd_per_gib_second"]
    if not isinstance(rate_text, str) or not re.fullmatch(r"[0-9]{1,12}(\.[0-9]{1,24})?", rate_text):
        raise ProvisionError("Rate must be a positive decimal string from the active database rate")
    with localcontext() as ctx:
        ctx.prec = 60
        rate = Decimal(rate_text)
        cents = (rate * 3600 * 100).normalize()
        if rate <= 0 or cents.as_tuple().exponent < -12:
            raise ProvisionError("Rate must be positive and exactly representable in Stripe's 12 decimal places")
    if raw["tax_behavior"] not in ("exclusive", "inclusive", "unspecified"):
        raise ProvisionError("Invalid tax_behavior")
    return {"unit_amount_decimal": format(cents, "f"), "tax_behavior": raw["tax_behavior"]}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Stripe:
    def __init__(self, key, live, account, apply=False):
        prefix = "live" if live else "test"
        if not re.fullmatch(r"[sr]k_" + prefix + r"_[A-Za-z0-9]+", key):
            raise ProvisionError("Credential does not match the requested environment")
        if not re.fullmatch(r"acct_[A-Za-z0-9]+", account):
            raise ProvisionError("Expected account must be a Stripe account ID")
        self.key, self.live, self.account, self.apply = key, live, account, apply
        self.opener = urllib.request.build_opener(NoRedirect())

    def request(self, method, path, params=None):
        if method not in ("GET", "POST") or path not in {*PATHS.values(), "/v1/account"}:
            raise ProvisionError("Request is outside the catalog provisioning scope")
        if method == "POST" and (not self.apply or path == "/v1/account"):
            raise ProvisionError("Writes require --apply and a catalog endpoint")
        params = params or {}
        encoded = urllib.parse.urlencode(params).encode()
        headers = {"Authorization": "Bearer " + self.key, "Stripe-Version": API_VERSION}
        url = "https://api.stripe.com" + path
        if method == "GET":
            url += "?" + encoded.decode()
        else:
            fingerprint = json.dumps([self.account, API_VERSION, path, params], sort_keys=True)
            headers["Idempotency-Key"] = "storage-catalog-v1-" + hashlib.sha256(fingerprint.encode()).hexdigest()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(url, data=encoded if method == "POST" else None, headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=30) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            # Do not print provider error bodies: they can contain credential details.
            raise ProvisionError(f"Stripe {method} {path}: HTTP {exc.code}; inspect Stripe request logs, then rerun") from None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            raise ProvisionError(f"Stripe {method} {path}: response unavailable; rerun to reconcile any partial creation") from None

    def verify_account(self):
        account = self.request("GET", "/v1/account")
        if account.get("id") != self.account:
            raise ProvisionError("Credential belongs to a different Stripe account")

    def inventory(self, kind):
        rows, seen = [], set()
        # Stripe lists only active prices by default; archived prices can still conflict.
        filters = [{"active": "true"}, {"active": "false"}] if kind == "price" else [{}]
        for filters_for_state in filters:
            cursor = None
            for _ in range(100):
                params = {"limit": 100, **filters_for_state}
                if kind == "price":
                    params["expand[]"] = "data.currency_options"
                if cursor:
                    params["starting_after"] = cursor
                page = self.request("GET", PATHS[kind], params)
                data = page.get("data")
                if not isinstance(data, list) or type(page.get("has_more")) is not bool:
                    raise ProvisionError("Malformed Stripe inventory")
                for item in data:
                    if not isinstance(item, dict) or not item.get("id") or item["id"] in seen:
                        raise ProvisionError("Malformed or repeated Stripe inventory item")
                    if item.get("livemode") is not self.live:
                        raise ProvisionError("Stripe inventory environment mismatch")
                    seen.add(item["id"])
                    rows.append(item)
                    if len(rows) > 10000:
                        raise ProvisionError("Stripe inventory exceeds 10,000 objects; no writes attempted")
                if not page["has_more"]:
                    break
                if not data:
                    raise ProvisionError("Incomplete Stripe inventory")
                cursor = data[-1]["id"]
            else:
                raise ProvisionError("Stripe inventory exceeds 100 pages per state; no writes attempted")
        return rows


def one(items, kind):
    if len(items) > 1:
        raise ProvisionError(f"Multiple storage {kind} objects exist; reconcile them manually")
    return items[0] if items else None


def require(actual, expected, label):
    for key, value in expected.items():
        if actual.get(key) != value:
            raise ProvisionError(f"Existing {label} conflicts at {key}; no replacement will be created")


def inspect(stripe, spec):
    # Finish all reads and conflict checks before creating any object.
    meters, products, prices = [stripe.inventory(kind) for kind in PATHS]
    meter = one([m for m in meters if m.get("event_name") == EVENT], "meter")
    if meter:
        require(meter, {"status": "active", "default_aggregation": {"formula": "sum"},
                       "event_time_window": None,
                       "customer_mapping": {"type": "by_id", "event_payload_key": "stripe_customer_id"},
                       "value_settings": {"event_payload_key": "value"}}, "meter")
    product = one([p for p in products if p["id"] == PRODUCT_ID or p.get("name") == PRODUCT_NAME
                   or p.get("metadata", {}).get("billing_resource") == "storage_gib"], "product")
    candidates = [p for p in prices if p.get("lookup_key") == LOOKUP
                  or (product and p.get("product") == product["id"])
                  or (meter and (p.get("recurring") or {}).get("meter") == meter["id"])]
    price = one(candidates, "price")
    # An existing manually-created price establishes its product's identity.
    if price and not product:
        product = one([p for p in products if p["id"] == price.get("product")], "product")
        if product:
            one([p for p in prices if p.get("product") == product["id"]], "price")
    if product:
        require(product, {"active": True}, "product")
    if price:
        if not meter or not product:
            raise ProvisionError("Storage price exists without a matching meter and product")
        require(price, {"active": True, "currency": "usd", "billing_scheme": "per_unit",
                        "type": "recurring", "product": product["id"], "transform_quantity": None,
                        "custom_unit_amount": None, "tax_behavior": spec["tax_behavior"]}, "price")
        currencies = price.get("currency_options")
        if not isinstance(currencies, dict) or not currencies:
            raise ProvisionError("Storage price currency options were not expanded; no writes attempted")
        if set(currencies) != {"usd"}:
            raise ProvisionError("Storage price has additional currency options; reconcile them manually")
        require(price.get("recurring") or {}, {"meter": meter["id"], "interval": "month",
                "interval_count": 1, "usage_type": "metered", "trial_period_days": None}, "price recurring settings")
        try:
            equal = Decimal(str(price.get("unit_amount_decimal"))) == Decimal(spec["unit_amount_decimal"])
        except InvalidOperation:
            equal = False
        if not equal:
            raise ProvisionError("Existing storage price has a different rate; no replacement will be created")
    return {"meter": meter, "product": product, "price": price}


def provision(stripe, spec):
    stripe.verify_account()
    found = inspect(stripe, spec)
    plan = {"account": stripe.account, "livemode": stripe.live, "api_version": API_VERSION,
            "event_name": EVENT, "currency": "usd", **spec,
            "actions": {kind: "reuse" if obj else "create" for kind, obj in found.items()},
            "ids": {kind: obj["id"] if obj else None for kind, obj in found.items()}}
    if not stripe.apply:
        return {"mode": "preview", **plan}
    print(json.dumps({"mode": "apply_plan", **plan}, indent=2), file=sys.stderr)
    if not found["meter"]:
        found["meter"] = stripe.request("POST", PATHS["meter"], {
            "display_name": "Superserve storage usage", "event_name": EVENT,
            "default_aggregation[formula]": "sum", "customer_mapping[type]": "by_id",
            "customer_mapping[event_payload_key]": "stripe_customer_id", "value_settings[event_payload_key]": "value"})
    if not found["product"]:
        found["product"] = stripe.request("POST", PATHS["product"], {
            "id": PRODUCT_ID, "name": PRODUCT_NAME, "metadata[billing_resource]": "storage_gib"})
    if not found["price"]:
        found["price"] = stripe.request("POST", PATHS["price"], {
            "product": found["product"]["id"], "currency": "usd", "billing_scheme": "per_unit",
            "recurring[interval]": "month", "recurring[interval_count]": 1,
            "recurring[usage_type]": "metered", "recurring[meter]": found["meter"]["id"],
            "lookup_key": LOOKUP, **spec})
    verified = inspect(stripe, spec)
    if any(not obj for obj in verified.values()):
        raise ProvisionError("Post-creation inventory is incomplete; rerun to reconcile")
    return {"mode": "verified", **plan, "ids": {k: v["id"] for k, v in verified.items()}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--definition", type=Path, required=True)
    parser.add_argument("--environment", choices=["staging", "production"], required=True)
    parser.add_argument("--expected-account", required=True)
    parser.add_argument("--pass-entry", required=True, help="Password-store entry; first line contains the key")
    parser.add_argument("--apply", action="store_true", help="Create missing catalog objects (default: read-only preview)")
    args = parser.parse_args()
    try:
        spec = definition(json.loads(args.definition.read_text()))
        secret = subprocess.run(["pass", "show", args.pass_entry], capture_output=True, text=True, check=False)
        if secret.returncode or not secret.stdout.strip():
            raise ProvisionError("Could not read credential from pass")
        stripe = Stripe(secret.stdout.splitlines()[0].strip(), args.environment == "production", args.expected_account, args.apply)
        print(json.dumps(provision(stripe, spec), indent=2))
    except (ProvisionError, OSError, ValueError, TypeError) as exc:
        # File/parser errors are safe; credential/provider errors are sanitized above.
        print(f"Storage catalog setup failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
