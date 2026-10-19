#!/usr/bin/env python3
"""Preview or provision the devbox Stripe sandbox billing catalog."""

from __future__ import annotations

import argparse
from decimal import Decimal
import json
import os
import sys

from provision_storage_stripe import PATHS, ProvisionError, Stripe, require, require_price

API_VERSION = "2026-05-27.dahlia"
TAX_BEHAVIOR = "exclusive"

# Rates are USD per second, as seeded in pricing_rate; the API rejects a
# provider price whose cents per hour differ from them by any amount.
USAGE = [
    {"resource": "vcpu", "event": "cpu_vcpu_hours", "usd_per_second": "0.000014000000",
     "product": "superserve_vcpu_hours", "name": "Superserve vCPU", "lookup": "superserve_vcpu_hours_monthly",
     "billable": True},
    {"resource": "memory_gib", "event": "memory_gib_hours", "usd_per_second": "0.000004500000",
     "product": "superserve_memory_gib_hours", "name": "Superserve Memory", "lookup": "superserve_memory_gib_hours_monthly",
     "billable": True},
    {"resource": "storage_gib", "event": "storage_gib_hours", "usd_per_second": "0.000000030000",
     "product": "superserve_storage_gib_hours", "name": "Superserve Storage", "lookup": "superserve_storage_gib_hours_monthly",
     "billable": False},
]

# The Pro fee must live on a product of its own: invoice rounding refuses a
# fee that shares a product with metered usage.
PRO_PRODUCT = {"id": "superserve_pro", "name": "Superserve Pro"}
PRO = [
    {"offer": "pro_monthly", "cents": 120000, "interval": "month", "lookup": "superserve_pro_monthly"},
    {"offer": "pro_annual", "cents": 1200000, "interval": "year", "lookup": "superserve_pro_annual"},
]


def cents_per_hour(usd_per_second):
    return Decimal(usd_per_second) * 360000


def one(items, label):
    if len(items) > 1:
        raise ProvisionError(f"Multiple {label} objects exist; reconcile them manually")
    return items[0] if items else None


def inspect(stripe):
    meters, products, prices = [stripe.inventory(kind) for kind in PATHS]
    found = {}
    for usage in USAGE:
        label = usage["resource"]
        meter = one([m for m in meters if m.get("event_name") == usage["event"]], f"{label} meter")
        if meter:
            require(meter, {"status": "active", "default_aggregation": {"formula": "sum"},
                           "event_time_window": None,
                           "customer_mapping": {"type": "by_id", "event_payload_key": "stripe_customer_id"},
                           "value_settings": {"event_payload_key": "value"}}, f"{label} meter")
        product = one([p for p in products if p["id"] == usage["product"]], f"{label} product")
        if product:
            require(product, {"active": True}, f"{label} product")
        price = one([p for p in prices if p.get("lookup_key") == usage["lookup"]], f"{label} price")
        if price:
            if not meter or not product:
                raise ProvisionError(f"{label} price exists without its meter and product")
            require_price(price, f"{label} price", product["id"], TAX_BEHAVIOR,
                          cents_per_hour(usage["usd_per_second"]),
                          {"meter": meter["id"], "interval": "month", "usage_type": "metered"})
        found[label] = {"meter": meter, "product": product, "price": price}
    product = one([p for p in products if p["id"] == PRO_PRODUCT["id"]], "Pro product")
    if product:
        require(product, {"active": True}, "Pro product")
    found["pro"] = {"product": product}
    for pro in PRO:
        price = one([p for p in prices if p.get("lookup_key") == pro["lookup"]], f"{pro['offer']} price")
        if price:
            if not product:
                raise ProvisionError(f"{pro['offer']} price exists without the Pro product")
            label = f"{pro['offer']} price"
            require_price(price, label, product["id"], TAX_BEHAVIOR, pro["cents"],
                          {"meter": None, "interval": pro["interval"], "usage_type": "licensed"})
            # The API compares the Pro amount as an exact string, not as a number.
            require(price, {"unit_amount_decimal": str(pro["cents"])}, label)
        found[pro["offer"]] = {"price": price}
    return found


def missing(found):
    return {group: [kind for kind, obj in objs.items() if not obj] for group, objs in found.items()}


def create(stripe, found):
    for usage in USAGE:
        objs = found[usage["resource"]]
        if not objs["meter"]:
            objs["meter"] = stripe.request("POST", PATHS["meter"], {
                "display_name": usage["name"] + " usage", "event_name": usage["event"],
                "default_aggregation[formula]": "sum", "customer_mapping[type]": "by_id",
                "customer_mapping[event_payload_key]": "stripe_customer_id",
                "value_settings[event_payload_key]": "value"})
        if not objs["product"]:
            objs["product"] = stripe.request("POST", PATHS["product"], {
                "id": usage["product"], "name": usage["name"], "metadata[billing_resource]": usage["resource"]})
        if not objs["price"]:
            objs["price"] = stripe.request("POST", PATHS["price"], {
                "product": objs["product"]["id"], "currency": "usd", "billing_scheme": "per_unit",
                "recurring[interval]": "month", "recurring[interval_count]": 1,
                "recurring[usage_type]": "metered", "recurring[meter]": objs["meter"]["id"],
                "unit_amount_decimal": format(cents_per_hour(usage["usd_per_second"]).normalize(), "f"),
                "lookup_key": usage["lookup"], "tax_behavior": TAX_BEHAVIOR})
    if not found["pro"]["product"]:
        found["pro"]["product"] = stripe.request("POST", PATHS["product"], dict(PRO_PRODUCT))
    for pro in PRO:
        if not found[pro["offer"]]["price"]:
            found[pro["offer"]]["price"] = stripe.request("POST", PATHS["price"], {
                "product": found["pro"]["product"]["id"], "currency": "usd", "billing_scheme": "per_unit",
                "unit_amount": pro["cents"], "recurring[interval]": pro["interval"],
                "recurring[interval_count]": 1, "recurring[usage_type]": "licensed",
                "lookup_key": pro["lookup"], "tax_behavior": TAX_BEHAVIOR})


def environment(found):
    usage_prices = [found[u["resource"]]["price"]["id"] for u in USAGE]
    resources = [{"resource_key": u["resource"], "usage_unit": "second", "stripe_event_name": u["event"],
                  "stripe_price_id": price, "tracked": True, "billable": u["billable"],
                  "subscription_enabled": True} for u, price in zip(USAGE, usage_prices)]
    return {
        "DEVBOX_CONFIG_STRIPE_API_VERSION": API_VERSION,
        "DEVBOX_CONFIG_STRIPE_CHECKOUT_PRICE_IDS": ",".join(usage_prices),
        "DEVBOX_CONFIG_STRIPE_PRO_MONTHLY_PRICE_ID": found["pro_monthly"]["price"]["id"],
        "DEVBOX_CONFIG_STRIPE_PRO_ANNUAL_PRICE_ID": found["pro_annual"]["price"]["id"],
        "DEVBOX_CONFIG_BILLING_RESOURCE_CONFIG": json.dumps(resources, separators=(",", ":")),
    }


def provision(stripe):
    stripe.verify_account()
    found = inspect(stripe)
    todo = {group: kinds for group, kinds in missing(found).items() if kinds}
    plan = {"account": stripe.account, "api_version": API_VERSION, "create": todo}
    if not stripe.apply:
        return {"mode": "preview", **plan}
    print(json.dumps({"mode": "apply_plan", **plan}, indent=2), file=sys.stderr)
    create(stripe, found)
    verified = inspect(stripe)
    if any(missing(verified).values()):
        raise ProvisionError("Post-creation inventory is incomplete; rerun to reconcile")
    return {"mode": "verified", **plan, "github_environment_variables": environment(verified)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-account", required=True, help="Stripe account ID of the devbox sandbox")
    parser.add_argument("--apply", action="store_true", help="Create missing catalog objects (default: read-only preview)")
    args = parser.parse_args()
    try:
        key = os.environ.get("STRIPE_SECRET_KEY", "").strip()
        if not key:
            raise ProvisionError("Set STRIPE_SECRET_KEY to the devbox sandbox's test-mode key")
        stripe = Stripe(key, False, args.expected_account, args.apply, API_VERSION, "devbox-catalog-v1")
        print(json.dumps(provision(stripe), indent=2))
    except (ProvisionError, OSError, ValueError, TypeError) as exc:
        print(f"Devbox catalog setup failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
