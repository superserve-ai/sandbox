#!/usr/bin/env python3
"""Give event participants credit: signup trial credit for trial teams, a Stripe credit grant for Developer/Pro teams."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from decimal import Decimal
from pathlib import Path

API_VERSION = "2026-05-27.dahlia"
TRIAL_SQL = Path(__file__).with_name("trial-credit-topup.sql")
LABEL = re.compile(r"[a-z0-9][a-z0-9._-]{0,99}")
MAX_CENTS = 100000
PAID_STATUSES = ("active", "trialing", "past_due")
RESERVED_METADATA = {"entitlement_id", "matching_credit_id", "prepaid_purchase_id", "pro_upgrade_id", "activation_identity"}

ROUTING_SQL = """
SELECT COALESCE(json_agg(json_build_object(
  'team_id', t.id, 'exists', x.id IS NOT NULL,
  'managed', x.id IS NOT NULL AND qm_team_managed_billing(t.id),
  'awaiting_plan', x.id IS NOT NULL AND billing_team_awaiting_plan(t.id),
  'kind', p.kind, 'plan_key', p.plan_key, 'family', COALESCE(p.terms->>'family', v.family),
  'contract_offer', c.offer_key, 'contract', p.contract_id IS NOT NULL, 'contract_customer', c.customer_id,
  'customer', a.stripe_customer_id, 'subscription_status', a.stripe_subscription_status,
  'trial_event_usd', e.amount_usd, 'trial_event_remaining_usd', e.remaining_usd) ORDER BY t.id), '[]')
FROM unnest(string_to_array(:'teams', ',')::uuid[]) t(id)
LEFT JOIN team x ON x.id = t.id
LEFT JOIN team_plan_assignment p ON p.team_id = t.id AND p.effective_to IS NULL
LEFT JOIN billing_plan_version v ON v.id = p.plan_version_id
LEFT JOIN billing_commercial_contract c ON c.id = p.contract_id
LEFT JOIN team_billing_account a ON a.team_id = t.id
LEFT JOIN team_credit_grant e ON e.id = md5('trial-credit-topup:' || :'label' || ':' || t.id::text)::uuid AND e.team_id = t.id;
"""


CUSTOMER_COLUMNS_SQL = """
SELECT COALESCE(json_agg(json_build_array(c.table_name, c.column_name) ORDER BY c.table_name, c.column_name), '[]')
FROM information_schema.columns c
JOIN information_schema.tables t ON t.table_schema = c.table_schema AND t.table_name = c.table_name AND t.table_type = 'BASE TABLE'
WHERE c.table_schema = 'public' AND c.column_name IN ('customer_id', 'stripe_customer_id') AND c.data_type = 'text'
  AND EXISTS(SELECT 1 FROM information_schema.columns k WHERE k.table_schema = 'public' AND k.table_name = c.table_name
             AND k.column_name = 'team_id' AND k.data_type = 'uuid');
"""
IDENTIFIER = re.compile(r"[a-z_][a-z0-9_]*")


class SetupError(Exception):
    pass


class IdempotencyConflict(Exception):
    pass


def route(row):
    if not row["exists"]:
        return "refused", "team not found"
    if row["managed"]:
        return "refused", "managed billing"
    if row["awaiting_plan"]:
        return "trial", "new-signup trial"
    kind, plan, family = row["kind"], row["plan_key"], row["family"]
    if kind is None:
        return "refused", "legacy pay-as-you-go (no plan assignment): unverified, under test"
    if kind == "custom":
        return "refused", "Enterprise/custom"
    if kind == "free":
        return "refused", "Free: upgrade to Developer first"
    if kind in ("legacy_payg", "prepaid"):
        return "refused", f"legacy pay-as-you-go/Starter ({plan}): unverified, under test"
    if kind != "subscription" or family not in ("developer", "pro"):
        return "refused", f"unsupported plan {kind}/{plan}"
    if row["contract"] and not re.fullmatch(family + r"_(monthly|annual)", row["contract_offer"] or ""):
        return "refused", f"commercial contract {row['contract_offer']}"
    if not row["customer"]:
        return "refused", "no billing customer"
    if row["contract"] and row["contract_customer"] != row["customer"]:
        return "refused", "contract customer differs from the team's billing customer"
    if row["subscription_status"] not in PAID_STATUSES:
        return "refused", f"subscription status {row['subscription_status']}"
    return "stripe", family


def psql(database_url, sql, variables, read_only):
    env = dict(os.environ)
    if read_only:
        env["PGOPTIONS"] = (env.get("PGOPTIONS", "") + " -c default_transaction_read_only=on").strip()
    cmd = ["psql", database_url, "-X", "-q", "-v", "ON_ERROR_STOP=1"]
    for name, value in variables.items():
        cmd += ["-v", f"{name}={value}"]
    return subprocess.run(cmd + ["-At", "-f", "-"] if read_only else cmd + ["-f", str(TRIAL_SQL)],
                          input=sql if read_only else None, capture_output=True, text=True, env=env, check=False)


def read_json(database_url, sql, variables):
    result = psql(database_url, sql, variables, read_only=True)
    if result.returncode != 0:
        raise SetupError("read-only query failed: " + result.stderr.strip())
    return json.loads(result.stdout.strip().splitlines()[-1])


def customers_sql(columns):
    parts = []
    for table, column in columns:
        if not (IDENTIFIER.fullmatch(table) and IDENTIFIER.fullmatch(column)):
            raise SetupError(f"unexpected customer column {table}.{column}")
        parts.append(f'SELECT team_id, "{column}" AS customer FROM public."{table}" '
                     f"WHERE team_id = ANY(string_to_array(:'teams', ',')::uuid[]) AND \"{column}\" IS NOT NULL")
    return ("SELECT COALESCE(json_object_agg(team_id, customers), '{}') FROM (SELECT team_id, "
            "array_agg(DISTINCT customer ORDER BY customer) AS customers FROM (" + " UNION ALL ".join(parts) +
            ") s GROUP BY team_id) g;")


def load_routes(database_url, teams, label):
    variables = {"teams": ",".join(teams), "label": label}
    rows = read_json(database_url, ROUTING_SQL, variables)
    columns = read_json(database_url, CUSTOMER_COLUMNS_SQL, {})
    known = read_json(database_url, customers_sql(columns), variables) if columns else {}
    for row in rows:
        row["known_customers"] = known.get(row["team_id"], [])
    return rows


class Stripe:
    def __init__(self, key, live, account, apply, api_version):
        prefix = "live" if live else "test"
        if not re.fullmatch(r"[sr]k_" + prefix + r"_[A-Za-z0-9]+", key):
            raise SetupError("Credential does not match the requested environment; live keys require --environment production")
        if not re.fullmatch(r"acct_[A-Za-z0-9]+", account or ""):
            raise SetupError("--expected-account must be a Stripe account ID")
        self.key, self.live, self.account, self.apply, self.api_version = key, live, account, apply, api_version

    def request(self, method, path, params=None, idempotency_key=None):
        if method == "POST" and not self.apply:
            raise SetupError("Writes require --apply")
        encoded = urllib.parse.urlencode(params or {}, doseq=True)
        headers = {"Authorization": "Bearer " + self.key, "Stripe-Version": self.api_version}
        url = "https://api.stripe.com" + path
        data = None
        if method == "GET":
            url += "?" + encoded if encoded else ""
        else:
            headers["Idempotency-Key"] = idempotency_key
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            data = encoded.encode()
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            try:
                error = json.load(exc).get("error") or {}
                kind, code = error.get("type"), error.get("code")
            except (ValueError, AttributeError):
                kind = code = None
            if method == "GET" and (exc.code == 404 or code == "resource_missing"):
                return None
            if method == "POST" and exc.code in (400, 409):
                if kind == "idempotency_error" or exc.code == 409:
                    raise IdempotencyConflict(f"Stripe {path}: HTTP {exc.code} {kind or 'conflict'}") from None
            # Provider error bodies can echo request details; keep output to the status.
            raise SetupError(f"Stripe {method} {path}: HTTP {exc.code}; inspect Stripe request logs, then rerun") from None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            raise SetupError(f"Stripe {method} {path}: response unavailable; rerun to reconcile") from None

    def verify_account(self):
        if (self.request("GET", "/v1/account") or {}).get("id") != self.account:
            raise SetupError("Credential belongs to a different Stripe account")

    def label_grants(self, customer, label):
        found, cursor = [], None
        for _ in range(20):
            params = {"customer": customer, "limit": 100}
            if cursor:
                params["starting_after"] = cursor
            page = self.request("GET", "/v1/billing/credit_grants", params)
            if page is None:
                return found
            for grant in page["data"]:
                if grant.get("customer") != customer:
                    raise SetupError(f"Stripe returned a credit grant for another customer than {customer}")
                if (grant.get("metadata") or {}).get("event_label") == label:
                    found.append(grant)
            if not page.get("has_more"):
                return found
            cursor = page["data"][-1]["id"]
        raise SetupError(f"Credit grants for {customer} exceed the inspection bound")

    def team_customers(self, team):
        found, page = set(), None
        for _ in range(20):
            params = {"query": f"metadata['team_id']:'{team}'", "limit": 100}
            if page:
                params["page"] = page
            result = self.request("GET", "/v1/customers/search", params)
            found |= {c["id"] for c in result["data"]}
            if not result.get("has_more"):
                return found
            page = result["next_page"]
        raise SetupError(f"Customers for team {team} exceed the inspection bound")


def grant_form(team, customer, label, cents):
    return {"customer": customer, "category": "promotional", "name": "Event credit",
            "amount[type]": "monetary", "amount[monetary][currency]": "usd", "amount[monetary][value]": str(cents),
            "priority": "50", "applicability_config[scope][price_type]": "metered",
            "metadata[event_label]": label, "metadata[team_id]": team}


def grant_key(team, label):
    return "event-credit-" + hashlib.sha256(json.dumps([team, label]).encode()).hexdigest()


def curl_command(form, key, api_version):
    parts = ["curl", "-sS", "https://api.stripe.com/v1/billing/credit_grants", "-u", '"$STRIPE_SECRET_KEY:"',
             "-H", shlex.quote("Stripe-Version: " + api_version), "-H", shlex.quote("Idempotency-Key: " + key)]
    for name, value in form.items():
        parts += ["-d", shlex.quote(f"{name}={value}")]
    return " ".join(parts)


def check_grant(grant, customer, cents, live):
    scope = (grant.get("applicability_config") or {}).get("scope") or {}
    amount = (grant.get("amount") or {}).get("monetary") or {}
    metadata = grant.get("metadata") or {}
    if (grant.get("customer") != customer or grant.get("category") != "promotional" or grant.get("priority") != 50
            or scope.get("price_type") != "metered" or scope.get("prices") or grant.get("expires_at")
            or amount.get("currency") != "usd" or amount.get("value") != cents or grant.get("livemode") is not live
            or grant.get("voided_at") or RESERVED_METADATA & set(metadata)):
        raise SetupError(f"Credit grant {grant.get('id')} for {customer} does not have the event credit terms")


def stripe_team(stripe, row, label, cents, api_version, reload_route):
    team, customer = row["team_id"], row["customer"]
    form, key = grant_form(team, customer, label, cents), grant_key(team, label)
    known = sorted(set(row.get("known_customers") or []) | {customer})
    result = {"team_id": team, "route": "stripe", "plan": row["plan_key"], "customer": customer,
              "subscription_status": row["subscription_status"], "amount_cents": cents}
    if stripe is None:
        return {**result, "outcome": "preview: run the command only if no customer of this team has a grant with this event_label",
                "checks": [f'curl -sS -G https://api.stripe.com/v1/billing/credit_grants -u "$STRIPE_SECRET_KEY:" -d customer={shlex.quote(c)} -d limit=100'
                           for c in known] + [f'curl -sS -G https://api.stripe.com/v1/customers/search -u "$STRIPE_SECRET_KEY:" '
                                              f'--data-urlencode {shlex.quote(f"query=metadata[{chr(39)}team_id{chr(39)}]:{chr(39)}{team}{chr(39)}")}'],
                "command": curl_command(form, key, api_version)}
    found = stripe.request("GET", "/v1/customers/" + urllib.parse.quote(customer))
    if not found or found.get("deleted") or found.get("livemode") is not stripe.live:
        return {**result, "outcome": "refused: customer missing, deleted or in the other mode"}
    owner = (found.get("metadata") or {}).get("team_id")
    if owner and owner != team:
        return {**result, "outcome": f"refused: customer belongs to team {owner}"}
    customers = sorted(set(known) | stripe.team_customers(team))
    labelled = [g for c in customers for g in stripe.label_grants(c, label)
                if (g.get("metadata") or {}).get("team_id") == team]
    existing = [g for g in labelled if not g.get("voided_at")]
    result["customers_checked"] = customers
    if len(existing) > 1:
        return {**result, "outcome": "refused: several grants carry this label; reconcile in Stripe"}
    if labelled and not existing:
        return {**result, "outcome": "REFUSED: this label's grant was voided; use a new label", "conflict": True,
                "grant_id": labelled[0]["id"]}
    if existing:
        grant = existing[0]
        granted = ((grant.get("amount") or {}).get("monetary") or {}).get("value")
        if granted != cents:
            return {**result, "outcome": f"REFUSED: label already granted {granted} cents, not {cents}", "conflict": True,
                    "grant_id": grant["id"], "grant_customer": grant["customer"]}
        check_grant(grant, grant["customer"], cents, stripe.live)
        if grant["customer"] != customer:
            return {**result, "outcome": f"REFUSED: already granted on previous customer {grant['customer']}, which the current "
                    "customer's invoices cannot use; void it and use a new label to re-grant", "conflict": True,
                    "grant_id": grant["id"], "grant_customer": grant["customer"]}
        return {**result, "outcome": "already granted", "grant_id": grant["id"], "grant_customer": grant["customer"]}
    if not stripe.apply:
        return {**result, "outcome": "would grant", "command": curl_command(form, key, api_version)}
    if reload_route(team) != row:
        return {**result, "outcome": "REFUSED: billing state changed during the run; rerun", "conflict": True}
    try:
        created = stripe.request("POST", "/v1/billing/credit_grants", form, key)
    except IdempotencyConflict:
        return {**result, "outcome": "REFUSED: another request for this team and label used different terms or is in flight; "
                "rerun to see the grant", "conflict": True}
    # An idempotent replay returns the creation response; read the grant's current state.
    created = stripe.request("GET", "/v1/billing/credit_grants/" + urllib.parse.quote(created["id"]))
    check_grant(created or {}, customer, cents, stripe.live)
    return {**result, "outcome": "granted", "grant_id": created["id"]}


def parse_cents(value):
    if not re.fullmatch(r"\d+(\.\d{1,2})?", value.strip()):
        raise SetupError(f"amount {value!r} must be a positive whole-cent USD value like 100 or 80.50")
    cents = int(Decimal(value.strip()) * 100)
    if cents <= 0:
        raise SetupError(f"amount {value!r} must be above zero")
    if cents > MAX_CENTS:
        raise SetupError(f"amount {value!r} is above {MAX_CENTS // 100} USD")
    return cents


def parse_grants(path):
    grants, first = {}, True
    with open(path, newline="", encoding="utf-8-sig") as handle:
        for line, record in enumerate(csv.reader(handle), 1):
            if not record or not "".join(record).strip() or record[0].strip().startswith("#"):
                continue
            header, first = first and record[0].strip().lower() == "team_id", False
            if header:
                continue
            if len(record) != 2:
                raise SetupError(f"line {line}: expected team_id,amount_usd")
            try:
                team = str(uuid.UUID(record[0].strip()))
            except ValueError:
                raise SetupError(f"line {line}: invalid team ID") from None
            cents = parse_cents(record[1])
            if grants.get(team, cents) != cents:
                raise SetupError(f"line {line}: team {team} listed with two amounts")
            grants[team] = cents
    if not grants:
        raise SetupError("No team rows given")
    return grants


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--grants", required=True, help="CSV of team_id,amount_usd rows (optional header)")
    parser.add_argument("--label", required=True, help="Event label, the idempotency key per team")
    parser.add_argument("--database-url", default=os.environ.get("DATABASE_URL"))
    parser.add_argument("--only", choices=["all", "trial", "stripe"], default="all")
    parser.add_argument("--apply", action="store_true", help="Commit trial grants and create Stripe grants (default: preview)")
    parser.add_argument("--environment", choices=["development", "staging", "production"])
    parser.add_argument("--expected-account", help="Stripe account the key must belong to")
    parser.add_argument("--pass-entry", help="Password-store entry whose first line is the key; defaults to STRIPE_SECRET_KEY")
    parser.add_argument("--api-version", default=API_VERSION)
    args = parser.parse_args()
    report, trial_conflict = [], False
    try:
        grants = parse_grants(args.grants)
        if not LABEL.fullmatch(args.label):
            raise SetupError("--label must be 1-100 lowercase letters, digits, dot, dash or underscore")
        if not args.database_url:
            raise SetupError("Set DATABASE_URL or --database-url")
        trial, stripe_rows = [], []
        for row in load_routes(args.database_url, sorted(grants), args.label):
            target, why = route(row)
            prior = row["trial_event_usd"]
            if prior is not None and target != "trial":
                prior_cents = int(Decimal(str(prior)) * 100)
                same = prior_cents == grants[row["team_id"]]
                report.append({"team_id": row["team_id"], "route": target, "plan": row["plan_key"],
                               "amount_cents": grants[row["team_id"]], "conflict": not same,
                               "trial_grant_remaining_usd": row["trial_event_remaining_usd"],
                               "outcome": "already granted as trial credit" if same else
                               f"REFUSED: label already granted {prior_cents} cents as trial credit, not {grants[row['team_id']]}"})
            elif target != "refused" and args.only not in ("all", target):
                report.append({"team_id": row["team_id"], "route": target, "outcome": f"skipped: --only {args.only}"})
            elif target == "trial":
                trial.append(row["team_id"])
            elif target == "stripe":
                stripe_rows.append(row)
            else:
                report.append({"team_id": row["team_id"], "route": "refused", "plan": row["plan_key"],
                               "amount_cents": grants[row["team_id"]], "outcome": "refused: " + why})

        stripe = None
        if stripe_rows and (args.apply or args.environment):
            if not args.environment:
                raise SetupError("--apply for Developer/Pro teams requires --environment and --expected-account")
            if args.pass_entry:
                secret = subprocess.run(["pass", "show", args.pass_entry], capture_output=True, text=True, check=False)
                key = secret.stdout.splitlines()[0].strip() if secret.returncode == 0 and secret.stdout.strip() else ""
            else:
                key = os.environ.get("STRIPE_SECRET_KEY", "").strip()
            if not key:
                raise SetupError("No Stripe credential")
            stripe = Stripe(key, args.environment == "production", args.expected_account, args.apply, args.api_version)
            stripe.verify_account()
        for row in stripe_rows:
            report.append(stripe_team(stripe, row, args.label, grants[row["team_id"]], args.api_version,
                                      lambda team: next(iter(load_routes(args.database_url, [team], args.label)), None)))

        if trial:
            pairs = ",".join(f"{team}:{Decimal(grants[team]) / 100}" for team in trial)
            result = psql(args.database_url, None, {"grants": pairs, "label": args.label,
                                                    "commit": "yes" if args.apply else "no"}, read_only=False)
            print(result.stdout, end="")
            trial_conflict = "REFUSED: label already granted" in result.stdout
            if result.returncode != 0:
                raise SetupError("trial credit transaction failed and rolled back: " + result.stderr.strip())
    except (SetupError, OSError, KeyError, IndexError, TypeError, ValueError) as exc:
        print(f"Event credit failed: {exc}", file=sys.stderr)
        return 1
    finally:
        if report:
            print(json.dumps({"mode": "apply" if args.apply else "preview", "label": args.label, "teams": report}, indent=2))
    if trial_conflict or any(r.get("conflict") for r in report):
        print("Event credit: nothing was added for REFUSED rows (label conflict, voided grant, or billing state "
              "changed during the run); see each row's outcome.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
