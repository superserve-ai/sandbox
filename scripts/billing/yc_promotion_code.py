#!/usr/bin/env python3
"""Preview or create the YC promotion code: one free month of the published Pro plan."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

API_VERSION = "2026-05-27.dahlia"


class SetupError(Exception):
    pass


class Stripe:
    def __init__(self, key, live, account, apply, api_version):
        prefix = "live" if live else "test"
        if not re.fullmatch(r"[sr]k_" + prefix + r"_[A-Za-z0-9]+", key):
            raise SetupError("Credential does not match the requested environment")
        if not re.fullmatch(r"acct_[A-Za-z0-9]+", account):
            raise SetupError("Expected account must be a Stripe account ID")
        self.key, self.live, self.account, self.apply, self.api_version = key, live, account, apply, api_version

    def request(self, method, path, params=None):
        if method == "POST" and not self.apply:
            raise SetupError("Writes require --apply")
        params = params or {}
        encoded = urllib.parse.urlencode(params, doseq=True)
        headers = {"Authorization": "Bearer " + self.key, "Stripe-Version": self.api_version}
        url = "https://api.stripe.com" + path
        data = None
        if method == "GET":
            url += "?" + encoded if encoded else ""
        else:
            fingerprint = json.dumps([self.account, self.api_version, path, params], sort_keys=True)
            headers["Idempotency-Key"] = "yc-promotion-" + hashlib.sha256(fingerprint.encode()).hexdigest()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            data = encoded.encode()
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            if exc.code == 404 and method == "GET":
                return None
            # Provider error bodies can echo request details; keep output to the status.
            raise SetupError(f"Stripe {method} {path}: HTTP {exc.code}; inspect Stripe request logs, then rerun") from None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            raise SetupError(f"Stripe {method} {path}: response unavailable; rerun to reconcile") from None

    def verify_account(self):
        if (self.request("GET", "/v1/account") or {}).get("id") != self.account:
            raise SetupError("Credential belongs to a different Stripe account")


def plan_price(stripe, version_id, price_id):
    if price_id:
        price = stripe.request("GET", "/v1/prices/" + urllib.parse.quote(price_id))
        if not price:
            raise SetupError(f"Price {price_id} does not exist in this Stripe account")
    else:
        lookup = f"superserve_plan_{version_id}_monthly"
        found = stripe.request("GET", "/v1/prices", {"lookup_keys[]": lookup, "limit": 2})["data"]
        if len(found) != 1:
            raise SetupError(f"Expected one price with lookup key {lookup}; open one Pro checkout so the API creates it, or pass --price")
        price = found[0]
    metadata = price.get("metadata") or {}
    recurring = price.get("recurring") or {}
    if (metadata.get("commercial_offer") != "pro_monthly" or (version_id and metadata.get("plan_version_id") != version_id)
            or recurring.get("interval") != "month" or recurring.get("usage_type") != "licensed"
            or not isinstance(price.get("unit_amount"), int) or price["unit_amount"] <= 0):
        raise SetupError(f"Price {price['id']} is not the Pro monthly fee (commercial_offer pro_monthly, licensed, monthly, positive amount)")
    if price.get("livemode") is not stripe.live or not price.get("active"):
        raise SetupError(f"Price {price['id']} is not active in this environment")
    return price


def check_coupon(coupon, product):
    applies = ((coupon.get("applies_to") or {}).get("products")) or []
    if (coupon.get("percent_off") != 100 or coupon.get("duration") != "once" or applies != [product] or not coupon.get("valid")
            or coupon.get("redeem_by") or coupon.get("max_redemptions")):
        raise SetupError(f"Coupon {coupon['id']} exists with different terms; choose another --coupon-id")


def check_promotion(promotion, coupon_id, max_redemptions):
    source = promotion.get("promotion") or {}
    linked = source.get("coupon") if "promotion" in promotion else promotion.get("coupon")
    linked = linked.get("id") if isinstance(linked, dict) else linked
    restrictions = promotion.get("restrictions") or {}
    if (linked != coupon_id or not restrictions.get("first_time_transaction") or restrictions.get("minimum_amount")
            or promotion.get("expires_at") or promotion.get("max_redemptions") != max_redemptions or not promotion.get("active")):
        raise SetupError(f"Promotion code {promotion['code']} exists with different terms; choose another --code")


def run(stripe, args):
    stripe.verify_account()
    price = plan_price(stripe, args.plan_version_id, args.price)
    product = price["product"] if isinstance(price["product"], str) else price["product"]["id"]
    coupon_id = args.coupon_id or "yc-pro-" + product
    plan = {"account": stripe.account, "livemode": stripe.live, "price": price["id"], "product": product,
            "coupon": {"id": coupon_id, "percent_off": 100, "duration": "once", "applies_to": [product]},
            "promotion_code": {"code": args.code, "first_time_transaction": True, "max_redemptions": args.max_redemptions}}
    coupon = stripe.request("GET", "/v1/coupons/" + urllib.parse.quote(coupon_id), {"expand[]": "applies_to"})
    if coupon:
        check_coupon(coupon, product)
    found = stripe.request("GET", "/v1/promotion_codes", {"code": args.code, "active": "true", "limit": 2})["data"]
    if len(found) > 1:
        raise SetupError("Several active promotion codes share this code; reconcile them in Stripe")
    if found:
        check_promotion(found[0], coupon_id, args.max_redemptions)
    plan["actions"] = {"coupon": "reuse" if coupon else "create", "promotion_code": "reuse" if found else "create"}
    if not stripe.apply:
        return {"mode": "preview", **plan}
    if not coupon:
        stripe.request("POST", "/v1/coupons", {"id": coupon_id, "name": args.coupon_name, "percent_off": 100,
                                              "duration": "once", "applies_to[products][0]": product})
    if not found:
        found = [stripe.request("POST", "/v1/promotion_codes", {
            "promotion[type]": "coupon", "promotion[coupon]": coupon_id, "code": args.code,
            "restrictions[first_time_transaction]": "true", "max_redemptions": args.max_redemptions})]
    check_coupon(stripe.request("GET", "/v1/coupons/" + urllib.parse.quote(coupon_id), {"expand[]": "applies_to"}), product)
    check_promotion(found[0], coupon_id, args.max_redemptions)
    return {"mode": "verified", **plan, "promotion_code_id": found[0]["id"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--environment", choices=["staging", "production"], required=True)
    parser.add_argument("--expected-account", required=True)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--plan-version-id", help="Published v2 Pro catalog version; its API-created monthly price is looked up")
    target.add_argument("--price", help="Monthly Pro price, when the API is configured with an explicit Pro price ID")
    parser.add_argument("--code", required=True, help="Customer-facing promotion code")
    parser.add_argument("--max-redemptions", type=int, required=True)
    parser.add_argument("--coupon-id", help="Defaults to yc-pro-<product>")
    parser.add_argument("--coupon-name", default="YC: first month of Pro")
    parser.add_argument("--pass-entry", help="Password-store entry whose first line is the key; defaults to STRIPE_SECRET_KEY")
    parser.add_argument("--api-version", default=API_VERSION)
    parser.add_argument("--apply", action="store_true", help="Create what is missing (default: read-only preview)")
    args = parser.parse_args()
    try:
        if args.max_redemptions < 1:
            raise SetupError("--max-redemptions must be positive")
        if not re.fullmatch(r"[A-Za-z0-9]{3,64}", args.code):
            raise SetupError("--code must be 3-64 letters or digits")
        if args.pass_entry:
            secret = subprocess.run(["pass", "show", args.pass_entry], capture_output=True, text=True, check=False)
            key = secret.stdout.splitlines()[0].strip() if secret.returncode == 0 and secret.stdout.strip() else ""
        else:
            key = os.environ.get("STRIPE_SECRET_KEY", "").strip()
        if not key:
            raise SetupError("No Stripe credential")
        stripe = Stripe(key, args.environment == "production", args.expected_account, args.apply, args.api_version)
        print(json.dumps(run(stripe, args), indent=2))
    except (SetupError, OSError, KeyError, TypeError) as exc:
        print(f"YC promotion code setup failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
