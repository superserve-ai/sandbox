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

Pro launch additionally requires the integrated validation described below.
The Checkout path records verified base payments and activates commercial
contracts; the background entitlement worker issues the monthly usage grant.
Pro never receives the PAYG activation promotion. Metering, resource rates, and
full measured-usage export remain unchanged.

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

## Monthly usage entitlements

Apply `20261015213000_monthly_usage_entitlement_issuance.sql` before deploying
control-plane replicas. The background entitlement worker issues one $1,000
usage grant per original monthly anniversary for both Pro plans. Annual payment
coverage is verified independently of the monthly credit cadence. Every new
authorization refreshes its covering base receipt and checks for any open or
uncollectible invoice on the owned customer. Partial payment blocks issuance;
due dates and subscription `past_due` are not the collection gate.

At renewal, the previous usage invoice must be reconciled, released, and paid,
including a correctly settled zero-dollar invoice. Monthly renewal combines the
next $1,200 base fee and previous usage less previous credits on one invoice.
For $1,350 usage, that invoice is $1,550. Annual usage closes do not repeat the
annual fee. The initial activation has no previous closing invoice to await.

The durable entitlement stores pending, uncertain, and issued states. An
uncertain request retains its parameters and idempotency key across restarts.
Recovery first discovers a matching provider grant; only a completed absence
check permits replay within 23 hours. Older uncertainty requires operator
resolution and never starts a new grant. Immediate requests omit `effective_at`;
confirmation saves Stripe's actual timestamp and verifies that it excludes the
previous invoice. Expiry remains one second after the mapped closing boundary.
Credits use priority 50 and cover the frozen CPU, memory, storage, and rounding
prices. Invoice reconciliation checks each actual credit transaction, its line
and invoice, the saved grant, ledger conservation, and earliest-expiry ordering.
Fixed fees cannot consume these credits. Existing all-metered, non-expiring
promotional grants remain eligible. Credit priority or scope drift holds invoices
for review rather than guessing an allocation.

`BILLING_USAGE_ENTITLEMENTS_ENABLED` defaults to false. Enable it only after
all control-plane replicas run this version and the merge validation passes.
Turning it off stops new dispatch and replay; discovery and confirmation of
possible existing grants continue.

`BILLING_ENTITLEMENT_WORKERS` defaults to 8 (range 2–32). Half the capacity is
reserved for fresh work and half for retries; each claims a bounded batch with
expiring database leases.
Normal eligibility checks recur every 20 seconds; idle lanes poll every five
seconds. Successful grants sleep until the next anniversary. Failed operations
back off from 10 seconds to five minutes. Grant inventory discovery saves a
cursor after each 50-object page and resumes across restarts. Ordinary first
issuance does not enumerate old grants. Invoice checks select grants by the
closing period and retrieve current evidence before using it. At most 200
positive-balance grants may fund one close; larger simultaneously eligible sets
require operator reconciliation. Candidate evaluation resumes in 50-grant pages,
so depleted non-expiring history does not consume that limit. Before a completed
scan can authorize finalization, all retained positive candidates are retrieved
again to detect voids or consumption while earlier pages were saved. A change in
the provider ledger or grant-inventory list head restarts the scan, including
when a previously exhausted grant is reinstated. The provider inventory head
must also match a completed local discovery pass. Expired grants from
other monthly periods are excluded by the query. Delayed cycle-invoice discovery also saves its cursor
between 100-invoice pages, with no upper creation-time cutoff.

Inspect `billing_entitlement_work` for the next check, failure age, last error,
lease, and inventory cursor. `billing_usage_entitlement` holds the frozen
request and provider confirmation; `billing_provider_credit` is a discovery
index, not payment authority. `billing_entitlement_withheld` records the latest
observation and sustained platform failures; `billing_entitlement_debt` retains
each distinct blocking invoice for that period. Closing rechecks debt timing: payment before
expiry or missing full-period nonpayment evidence requires allowance recovery.
An issuance failure must never be treated as customer forfeiture. Invoice
creation time alone does not prove nonpayment: checks use finalized/payable
time. A scheduled renewal has a five-minute close-processing budget after its
boundary; later finalization or a retained platform incident requires manual
review before forfeiture. Other invoices must already have been payable at the
period start to prove that they prevented issuance throughout that period. When
saved debt observations are insufficient, historical invoice discovery resumes
in 50-invoice pages across all statuses, including debt settled after expiry.
A proving invoice is retained for subsequent checks; missing proof keeps the
invoice held for recovery.

`usage_entitlement` billing-work telemetry records attempts and failures.
The independent `usage_entitlement_backlog` sampler updates
`billing_event_backlog_capped` and `billing_event_oldest_age_seconds` with
`state=entitlement_due`. The count includes jobs over one minute late and is
capped at 1,000 (a value of 1,000 means at least that many); age is uncapped.
Alert on sustained overdue age and sampler errors, including issuer stalls. The
independent `entitlement_coverage_sample` audit scans active Pro contracts in
indexed 1,000-contract pages, at most one page per second, while issuance is
enabled. After each complete sweep it publishes the same backlog metrics with
`state=entitlement_paid_missing`: paid current periods missing a confirmed grant
for more than 15 minutes, measured from the later of period start and payment.
It includes missing or incorrectly deferred work items and excludes debt observed
within the last minute. `state=entitlement_debt_unknown` is the subset without
a current clean-debt observation; stale debt cannot silently suppress an alert.
These are recovery candidates, not authorization to issue credit. Counts cap at
1,000 and ages remain uncapped. Alert on either nonzero missing coverage or audit
errors; use the maximum across replicas, not the sum. Sweeps pause 30 seconds
after completion; detection delay grows by one second per 1,000 contracts.
The audit makes no provider calls and never replaces the issuance checks. The
worker emits an error with the contract ID after five minutes of failure, or
immediately when an unresolved grant has less than 15 minutes until expiry;
repeat alerts are limited to once per hour. Route these errors to the billing
on-call. Inspect pending grants and keep invoice collection held while resolving
an outage. Restore provider access and let the saved request resume. If a
request exceeded the replay window, locate and verify the original grant using
its entitlement metadata; never clear or replace its saved identity. If an
eligible period was missed entirely, escalate for explicit customer remediation
and corrected invoice settlement. Do not extend the old grant or automatically
roll its balance into another month.

## Entitlement merge and launch gate

Keep new Pro offers disabled until the integrated Stripe staging flow is proven.
Before merge, retain evidence for payment, correct-period grant, measured usage,
and the reconciled invoice, including monthly combined renewals, annual monthly
refresh, duplicate workers, lost responses, boundary crashes, missing/draft
closing invoices, old unpaid and partial balances, zero-dollar settlement, late
restoration, earliest-expiring credit, and positive/negative rounding. Explicitly
exercise omitted `effective_at` and delayed finalization after expiry against the
pinned Stripe version. Local simulated-provider tests establish application
behavior; they do not replace that provider validation. A draft PR may precede
this evidence, but merge and launch may not.

Rollback is a drain operation, not a binary-only reversal. Disable new grant
issuance first, keep this version running to recover uncertainty, and drain all
`credit_version=1` invoice plans to `released` before starting an older invoice
worker. Do not run old and new invoice workers together after enabling Pro
issuance. If a plan cannot drain, keep collection held and deploy a forward fix;
do not delete frozen plans, grants, or requests to make an older binary proceed.
The database deliberately rejects older Pro overdue observations as new credit
authority. Existing issued grants and legacy invoice plans remain readable.
