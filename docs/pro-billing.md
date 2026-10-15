# Pro signup billing

Pro purchase is available only to a newly created team whose onboarding choice
is still open. Existing teams and a committed Free choice remain PAYG. The
`offer` field on `POST /stripe/checkout-session` accepts `pro_monthly` or
`pro_annual`; licensed price IDs come only from backend configuration.

Apply the plan-aware Checkout migration before deploying the API. Configure
`STRIPE_PRO_MONTHLY_PRICE_ID` ($1,200 USD monthly) and
`STRIPE_PRO_ANNUAL_PRICE_ID` ($12,000 USD annually), using licensed per-unit
prices on products separate from metered usage. Both use flexible billing on
the same subscription as the existing monthly PAYG resource prices. The tested
Stripe schema is `2026-07-29.dahlia`. Empty Pro price settings disable new
purchases; existing frozen purchases and payment recovery continue.

This change does not enable a Pro launch by itself. The monthly usage-entitlement
issuer and scoped expiring-credit reconciliation must be deployed before
exposing the new offers. This path records verified base payments and activates
commercial contracts; it never issues usage grants or the PAYG activation
promotion. Metering, resource rates, and usage export remain unchanged.

## Checkout recovery

`POST /stripe/plan-choice` with `{"offer":"free"}` commits Free access without
a card. It returns a conflict while a Pro payment may still complete or after
Pro has been committed. Account/team access remains available.

`POST /stripe/pro-checkout/recover` with `{}` retrieves the original purchase,
verifies cash payment evidence, and converges local activation. With
`{"restart":true}`, it first closes an open unpaid Checkout or verifies that a
terminal subscription's invoices and payment intents cannot receive funds.
Only `retryable` permits a fresh plan selection. `active` confirms paid
activation. `payment_confirmation_pending` retains the original purchase;
a browser redirect, timeout, or stale tab must not reset that state.

Paid receipts are saved before invoice enrollment. Pro activation and trial
termination wait until enrollment has installed and verified the rounding item
and collection hold and committed the matching invoice account. Enrollment
failures retain the pending purchase; recovery retries without charging again.

The background reconciler also recovers missed webhooks and local transaction
failures. Pending attempts are revisited in bounded batches; settled accounts and their
invoice history are checked hourly for missed renewals.
Canceled subscriptions keep payment recovery until their complete invoice
inventory is terminal and all paid invoices have been verified. Paid coverage
is preserved until its service term expires for already-active contracts. A paid
purchase first observed after its subscription has terminated stays pending with
`paid subscription terminated before activation; billing recovery requires support`.
Verified receipts and their original service periods are retained, the signup trial
is not ended, and conflicting purchases remain blocked. A canceled subscription
cannot be enrolled automatically, so this condition requires support resolution;
retries alone cannot restore service. Background checks for this condition run hourly.

Inspect `billing_signup_choice.last_error`, `next_check_at`, and
`invoice_cursor`, the existing Stripe webhook records, and `pro_payment` billing
work telemetry when recovery remains pending. Lost create responses reuse the
frozen idempotency key within its safe retention window. After that window,
recovery searches provider sessions by the original generation. Never clear a
purchase fence based only on elapsed time. Resolve provider identity or restore
provider access and retry the recovery endpoint. Closed-purchase evidence and
the existing generation fence reject delayed callbacks, including older API
replicas during rollout.

Negative usage rounding is scoped to metered products so it cannot discount the
licensed fee. Invoice validation separately checks the licensed service term,
usage lines, credit settlement, and customer balance carry-forward. A final
usage invoice after cancellation does not sell a new Pro service term.

The independent 30-second backlog sampler exports
`billing_pro_paid_activation_pending` and
`billing_pro_paid_activation_pending_age_seconds` for verified payments awaiting
local activation, and `billing_pro_recovery_overdue` plus
`billing_pro_recovery_overdue_age_seconds` for pending choices past their next
check. Counts are capped at 1,000 per offer, and zero samples clear recovered
backlogs. Alert on paid activation age above 10 minutes and overdue recovery age
above 15 minutes. Sampling failures are recorded separately from recovery work.
Checkout captures validated resource amounts and meter mappings with its frozen
request, so later catalog or flag changes cannot reinterpret an in-flight sale.

Unexpired base-payment receipts are rechecked independently of the historical
invoice cache. Refunds, disputes, or credit-note allocations that may affect the
base fee create a payment-scoped verification hold. Usage-only credit notes are
checked by invoice-line identity. A hold blocks new activation and entitlement
authorization from that receipt without deleting payment history, ending the
contract, revoking issued grants, or preventing confirmation of an uncertain
provider write. Verified later periods continue reconciling independently.
Inspect `billing_pro_payment_verification` and recovery errors for these cases;
refund allocation and recovery of already-consumed credits require explicit
resolution. Pro invoice status is refreshed from the subscription's latest
invoice, so delayed webhook payloads cannot regress it.

Pro invoice enrollment, usage export, and invoice closing retain the purchased
resource price and meter mappings after catalog changes. Usage billability and
effective-period rates remain authoritative in the existing ledger. A monetary
rate change requires a coordinated pricing/subscription migration; mismatched
provider and ledger rates keep collection held. Annual licensed fees are
validated separately from monthly storage usage. A paid subscription first observed as
past due stays pending until Stripe reports it active; its payment and trial
remain intact. Webhooks can recover it immediately after payment status changes,
with hourly background retries as a fallback.
