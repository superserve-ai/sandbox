# Adopt annual Pro alongside sponsored credits

The operator adoption endpoint recognizes an existing annual Pro item on a
sponsored usage subscription. It grants Pro product limits and records an
explicit first-year base-fee waiver. The existing sponsorship remains the only
first-year usage allowance source. Adoption does not create a customer,
subscription, invoice, payment, discount, or credit grant.

This bounded path supports the original twelve-month sponsorship: $30,000 per
month for three months, then $1,000 per month for nine months. It preserves the
original anniversary, grant identities and consumption. The first $12,000 annual
fee is waived. Subsequent annual terms cost $12,000 and use the standard Pro
$1,000 monthly allowance only after verified annual payment.

## Operator workflow

Use the existing operator authentication and `X-Actor-User-Id` header. First POST
`/internal/teams/{team_id}/billing/sponsored-annual/preflight` with:

```json
{
  "idempotency_key": "annual-adoption-example",
  "merchant_account": "acct_example",
  "sponsorship_id": "00000000-0000-4000-8000-000000000001",
  "customer_id": "cus_example",
  "subscription_id": "sub_example",
  "item_id": "si_example",
  "base_price_id": "price_example",
  "live_mode": false,
  "reason": "Approved first-year annual fee waiver",
  "reference": "operator-approval-reference"
}
```

Preflight is observational and returns an evidence snapshot, original term,
renewal amount and `preflight_fingerprint`. It requires the exact active
sponsorship, annual licensed item and frozen monthly resource/rounding items.
Debt, pending invoice items, nonzero historical base lines, uncertain grant
issuance and unfinished invoice closes require reconciliation first. Existing
completed invoice history is retained. Consumption may continue between
preflight and apply; it is observed again and never reset.

POST the same request plus `preflight_fingerprint` to
`/internal/teams/{team_id}/billing/sponsored-annual`. Apply rechecks the provider
under the customer-processing lease and local account lock, then atomically
records the authority and applies Pro limits. A changed configuration returns
409 and requires a new preflight. Reusing an identical key/request returns the
original operation; changing its terms returns 409. A lost response is recovered
by retrying the identical request. Inspect the returned operation using GET
`/internal/teams/{team_id}/billing/sponsored-annual/{operation_id}`.

The existing `keep_as_draft` collection hold must remain in place. An unknown
`billing_schedules` override is a conflict even if Stripe's separate `schedule`
field is empty. The adoption endpoint never guesses how to clear such an
override. Resolve provider configuration using a separately verified procedure
before applying local adoption. A zero-dollar proration is not evidence of a
paid annual fee or a full annual discount. This path supports no collectible
historical base line; it rejects discounted gross-fee reconciliation.

## Verification and recovery

Verify the operation is active, the billing summary identifies Pro Annual with
`base_fee_waived: true`, the renewal price is $12,000, and the included usage
references the existing sponsored entitlement. Default Pro limits apply;
customized team limits are preserved. Confirm fresh provider/calendar checks,
unchanged customer/subscription/item/anniversary, unchanged grant and usage
history, and no new provider financial objects.

Annual adoption does not bypass membership permissions, abuse restrictions,
debt checks, or credit exhaustion enforcement. It neither adds a payment method
nor automatically resumes paused sandboxes.

At the original anniversary, reconciliation ends the expired sponsored contract
and creates exactly one pending standard annual successor on the same
subscription. Stripe owns collection. Only verified cash settlement for the
exact annual item and service year activates the successor. Unpaid renewal
creates no new allowance; late or repeated payment notifications cannot restart
the first year. Cancellation preserves historical authority and custom limits.

A blocked operation exposes `last_error` and retries through the bounded annual
reconciliation worker. Do not delete authority rows, rewrite dates, reset grants,
or forge checkout/payment records to recover it. Preserve invoice holds and
resolve the recorded conflict. Schema deployment must precede compatible API
and worker deployment; enable adoption only after those readers are deployed.
After adoption, rolling back to an older binary that cannot recognize the fee
item is unsafe. This change performs no automatic customer adoption or backfill.
