# Operator-sponsored usage

Sponsorship grants monthly metered usage credit without a payment receipt, base
subscription fee, card requirement, paid plan, or signup promotion. The team's
plan and resource limits stay unchanged. Credits use the existing grant worker,
recovery scanner, invoice calendar, credit ledger, and invoice reconciliation.

## Operator procedure

Use the internal operator credential and `X-Actor-User-Id` with the operator's
UUID in the team's home billing region. These endpoints are under
`/internal/teams/:team_id/billing/sponsored-entitlements`:

- `POST /preflight` returns identity and member emails, current billing state,
  conflicts, frozen resource scope, monthly schedule, and `funding_capacity`
  (budget, observed count, whether the target is already observed, and availability).
  It makes no writes and reserves no capacity; apply can lose the last slot to
  another enrollment after preflight.
- `POST` persists approval and starts background onboarding. Send exactly the
  same body and idempotency key to retry. Changed terms with the same key fail.
- `GET /:operation_id` returns immutable approval, provider identities, calendar,
  issued/pending grants, revocation, and the last reconciliation error.
- `POST /:operation_id/revoke` stops new grants. A dispatched grant finishes or
  recovers with its original request. Issued credit keeps its original expiry.

Example body (amounts are USD cents):

```json
{
  "idempotency_key": "sponsor-example-approval-1",
  "schedule": [
    {"periods": 3, "amount_cents": 3000000},
    {"periods": 9, "amount_cents": 100000}
  ],
  "start": "now",
  "reason": "Approved pilot sponsorship",
  "reference": "Private approval reference"
}
```

Schedules contain 1–24 months, each with 1–100000000 cents. Approval records the
actor, reason, reference, request, and resolved start once. Existing accounts
keep their billing anniversary: a mid-period approval receives the full first
amount until the original boundary. New accounts establish the anniversary when
the usage subscription is created; preflight dates are provisional until then.
Unused credit expires without rollover. Missed periods are not backfilled.

Unpaid finalized debt, overlapping commercial or sponsored authority, YC
approval, and pending paid checkout block approval or issuance. Existing usage
subscriptions must match the approved resource terms and anniversary. An existing
anniversary without an aligned subscription is rejected before provider creation;
reconcile that billing setup separately rather than resetting its anniversary.
Successive sponsorships on a retained subscription must preserve the original
resource terms so historical usage and closing invoices keep their authority.
A price/meter migration requires separate billing recovery. Ordinary
customer and host credentials cannot approve or revoke sponsorship.

## Access and exhaustion

A confirmed grant and fresh positive spendable-credit observation establish
eligibility. Approval or an uncertain provider response does not. The existing
funding observer subtracts unsettled usage, including live intervals. When credit
is exhausted, existing admission and suspension enforcement stops further use.
Continued usage requires a usable card and a verified collection route. The next
month's confirmed grant can restore eligibility. Previously paused resources
are not restarted automatically. Abuse restrictions remain authoritative.

This is periodic enforcement, not a per-request spending reservation. Credit
observations, admission caching, and the suspension sweep introduce delay.
Retained storage can continue accruing charges after compute pauses. Such usage
is still recorded and reconciled; sponsorship does not erase overages or debt.

## Rollout and recovery

Apply the regional migration before deploying all API and billing workers. Drain
older workers before approving sponsored teams: old writers do not understand
this authority. Keep the existing production usage-entitlement and invoice-export
release gates, including their alert prerequisites. Approval does not enable the
global grant gate. Do not roll back to older binaries after admitting sponsors.

Approval opts only the selected team into funding observation and enforcement.
It respects the existing observation-capacity budget (initially four teams); a
new observer fails atomically if that budget is full. Already-observed teams
need no additional slot. Follow [funding rollout validation](funding-access.md)
before expanding that budget. No production activation is implied by this change.

Inspect operation `last_error`, `sponsorship_activation` backlog count/oldest age
(including unclaimed approvals), `sponsorship_reconciliation` work metrics, and
existing entitlement work/coverage metrics,
funding freshness, and invoice work. Provider creation and grants use stable
idempotency keys and durable attempt timestamps. Unknown creation or issuance
beyond the 23-hour replay window requires operator recovery; never substitute a
new key to bypass an unknown outcome. Revocation retains unresolved bootstrap
attempts until their identities are recovered. Recovered provider objects stay
in the audit record even when no grant was issued; inspect them before replacing
billing setup. Revocation neither voids a current grant nor cancels the usage
subscription or outstanding invoices.

Before production approval, exercise cardless onboarding, product create/resume,
credit exhaustion and pause, card addition, anniversary renewal, response loss,
revocation, and a closing invoice in staging. Local fake-provider tests validate
state transitions and replay; they do not prove live provider configuration.
