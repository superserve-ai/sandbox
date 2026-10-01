# Invoice cent reconciliation

Active live-billing subscriptions are enrolled automatically. Each commercial period is independently reconciled
against the finalized Stripe invoice. Exact decimal usage and prices are
multiplied before rounding each resource line directly to integer cents, half up.
For example, `1.05499999999` produces 105 cents and `1.05500000001` produces 106.
No intermediate six-decimal dollar rounding or fractional usage carry is used.
Remaining credits and legitimate customer invoice balances can carry forward.

## Close sequence

1. A background worker adds a separate monthly metered one-cent rounding price
   and enrolls the subscription under a persistent `pause_collection=keep_as_draft`
   hold, without a scheduled resume time. Shared rounding
   product, meter, and price configuration is created or reused automatically.
   Resource prices,
   resource units, and previously submitted events remain unchanged.
2. The existing export path freezes the completed period and submits its usage.
   Enrolled accounts can accept a small, symmetric quantity discrepancy
   provisionally. That observation cannot authorize financial close.
3. The worker binds an immutable plan to the actual scheduled-renewal invoice,
   customer, subscription, period, prices, accounting snapshots, and credit
   balance. It compares the authoritative charge with the charge calculated from
   the observed provider quantities. A correction is limited to one cent per
   resource line.
4. A positive correction uses the separate metered price so it remains eligible
   for Billing credits. A negative correction uses an invoice-specific fixed
   discount, which applies before credits. Original usage events are not edited.
5. After adjustment aggregation and another validation, the worker finalizes the
   invoice with `auto_advance=false`. Finalization recomputes eligible renewal
   usage; the draft display is not relied on as the final charge.
6. Verification checks the finalized charge, actual Billing-credit application,
   remaining credit ledger, net invoice amount, and movement in the customer's
   invoice balance. A zero amount due is insufficient evidence.
7. The database close gate permits the local period to record only that verified
   settlement. The independent local/shadow credit ledger is not debited again.
   Collection is released only after local finalization and fresh verification.

The plan progresses through `prepared`, `adjusted`, `finalizing`, `verified`, and
`released`. A per-team lock serializes work. Stable provider identities and saved
attempt timestamps protect response-loss recovery. Positive meter-event retries
stop after 23 hours unless the expected quantity is already observed. Coupons
have deterministic invoice-specific IDs. Older enrolled periods settle first.
Missing evidence, changed snapshots, or mismatched settlement leaves the period
held with a persisted error. An already-finalized mismatch requires operator
recovery; the worker never hides it with a credit note or a second invoice.

## Supported configuration and rollout

Apply the migrations and deploy the worker. Existing active accounts are queued
by the migration; subscription activation queues new accounts in the same database
transaction as their billing association. No per-customer operator call is required.
The worker processes a bounded queue with persisted backoff, while usage export
also ensures enrollment before submitting events. Shadow-billing accounts are not
enrolled. Provider configuration and eligibility are checked before collection is
changed. A failed account records its error without blocking the next account.

Enrollment retains a tentative attempt boundary across retries, then checks actual
renewals after the subscription hold is established. Eligible in-flight drafts are
held individually. Already-finalized invoices and unheld drafts created before the
rounding item was installed are excluded by moving the boundary past their period.
A held invoice is never silently excluded. This preserves response-loss recovery
without claiming protection before the provider hold actually existed. Frozen held invoices
can finish reconciliation after cancellation. A replacement subscription receives
its own hold and adjustment item, and a fresh enrollment boundary, once the previous
subscription has ended. Its association is committed only when prior enrolled periods
are settled and released. Frozen historical periods finish against their saved
association while the replacement remains held, then enrollment retries complete
the transition. A new billing anchor cannot reinterpret historical usage. Overlapping
unfrozen periods still require recovery; they are never reassigned to the replacement. Unsupported configurations
remain visible for recovery. The optional operator
route `POST /internal/teams/:team_id/billing/invoice-reconciliation` remains available
with `adjustment_price_id` and `adjustment_event_name`; it uses the same enrollment
logic and requires the operator credential and platform billing-write permission.

The first implementation supports USD, monthly per-unit metered subscriptions,
ordinary `subscription_cycle` invoices, and non-expiring all-metered USD Billing
credit grants. Accounts must already have their commercial billing anchor so the
local export worker can process their periods; unanchored legacy accounts remain
pending without enrollment changes until their existing cutover process establishes it.
Persisted historical `skipped_shadow` exports retain their existing handoff path
and quantity close checks; they are not retroactively enrolled.
The adjustment meter must be an active sum meter using the normal
customer/value payload mapping. Subscription-item prices must stay unchanged
through the invoiced service period. Invoice lines must cover that period and
match the current resource price mapping. Mid-cycle price changes that prevent
recomputation remain unsupported and must not bypass finalized-money verification.
Inactive, preloaded storage items are supported only with zero provider usage.

Existing discounts, tax, shipping, credit notes, tiered/transformed prices,
price-scoped or expiring grants, another live subscription on the customer, and
incomplete provider inventories require separate treatment. The worker does not
release collection for unsupported evidence. A changed credit balance during
close also holds the immutable plan for operator recovery.

Automatic catalog creation additionally needs product, price, and meter creation
permissions on the application's Stripe credential. Provider permissions include
reading subscriptions/items, prices, meters and
summaries, invoices/lines, credit grants and credit balances; writing subscription
holds/items, meter events, invoice discounts/finalization/advancement, and coupons.
Use the deployment's pinned Stripe API version. Enrolled subscriptions must stay
held during worker outages or rollback. Older binaries cannot bypass the new
invoice gate; do not drop the migration or resume subscriptions to work around it.
No new work runs on sandbox startup or resume paths.

## Validation

Real Stripe test-mode probes established:

- A fresh preview changed from 105 to 106 cents after an adjustment; the eventual
  invoice consumed exactly 106 cents of credits.
- A genuine scheduled renewal initially drafted at 105 cents recomputed to 106
  after a late in-period adjustment, consuming 106 of 1000 cents of credits.
- A one-cent discount reduced a 106-cent charge to 105. Full coverage consumed
  105 cents and left 895; partial coverage consumed the available 100 cents and
  carried the remaining 5 cents into customer invoice balance.
- A billing-cycle-reset draft did **not** recompute late metered usage. That invoice
  type is rejected. Direct amount edits on metered subscription lines were also
  rejected by Stripe and are not used.

The fixtures deliberately place the target one cent across a boundary; they do
not claim Stripe misrounded an individual input. Provider probes establish API
behavior. Database integration tests separately exercise exact-cost planning,
full/partial/no credits, inactive storage, response loss during finalization and
release, restart recovery, immutable plans, old-writer close rejection, and
failure to apply a correction or preserve the expected remaining credit. Enrollment
tests cover migration backfill, new activation, shadow exclusion, queue fairness,
concurrent workers, lost item-creation responses, stable catalog recovery, cancellation
recovery, and safe replacement enrollment.
Arithmetic
tests cover both sides and exact half-cent ties, multiplication, overflow, and
independent consecutive periods.

References: [renewal recomputation and price-change limitations](https://docs.stripe.com/billing/subscriptions/usage-based/configure-grace-period),
[credit eligibility and ordering](https://docs.stripe.com/billing/subscriptions/usage-based/billing-credits),
[preview semantics](https://docs.stripe.com/api/invoices/create_preview),
[subscription-line updates](https://docs.stripe.com/api/invoice-line-item/update).
