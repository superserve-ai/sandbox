# YC billing-calendar transition and recovery

YC adoption keeps the original provider subscription and annual anniversary. An
open legacy period can overlap that anniversary even when invoice enrollment has
already completed. Retry the saved operation; do not create another offer,
subscription, waiver, or grant to work around the overlap.

## Deployment order and destination

Apply `20261017012100_yc_billing_calendar_transition.sql` to **regional billing
PostgreSQL databases**, starting with staging. With the repository migration
runner these destinations are `staging`, then, only under a separately authorized
production rollout, `use4` and `usw2`. This is not a shared Auth migration. It
creates regional transition evidence and guards on regional accounting tables;
it does not change global company approval authority.

1. Use the normal migration-first deployment workflow. Its prerequisite waits
   for push CI and applies the regional migrations to staging, then `use4` and
   `usw2` when production is authorized, before deploying the API to staging and
   then production. Preserve environment approvals, invoice holds, and existing
   export and entitlement gates. Do not run the new binaries before migration.
2. Verify the deployed revision, serving traffic, health, and billing errors.
   Starting the new workers automatically reconciles due YC operations,
   including saved partial activations and active operations missing a receipt.
   Confirm successful reconciliation and its receipt before declaring activation
   complete; unresolved accounting conflicts require the recovery procedure below.
3. Include the approved-resource credit-scope recovery from PR #707 before
   accepting CPU/memory-only credit issuance. Integrate the coupon evidence fix
   independently; its subscription creation identities and idempotency keys
   remain unchanged by this transition.
4. Validate the staging scenario below using assigned synthetic fixtures. Do not
   create production fixtures or manually convert customer accounts as a rollout
   check. Retry clearly transient deployment failures; otherwise stop and notify
   the release owner. Do not automatically repair billing state or roll back.
   Retain the migration and its audit rows if application rollout is paused.

The migration itself does not change period boundaries, anchors, or provider
resources. Older APIs can use the additive schema, but they do not enforce the
new reconciliation receipt before enrollment or activation. After reconciliation,
the database rejects stale calendar writes; normal readers already use the saved
commercial anniversary. Full-service shutdown and a permanent old-binary fence
are not prerequisites. Period locks, foreign keys, and non-FK writer fences
serialize accounting records with each transition. These guards also add locking
to shared billing tables; accounts without a YC operation are not converted.

The existing branch-staging deployment gate refuses migration inputs different
from main. Use a reviewed revision through that gate after the migrations are
available there, or the owning deployment workflow's explicitly approved staging
procedure. The disabled experimental calendar-drain workflow is not required.
Do not bypass the gate, execute branch SQL through shared Auth, or
interpret passing local fixtures as deployed acceptance. A push/merge to main can
trigger production deployment; this procedure does not authorize that action.

## What reconciliation does

The transaction takes the existing webhook processing lease, the team invoice
advisory lock, the billing-account lock, existing contract locks, and period locks
in that order. It reconciles periods **before** saving the local subscription association,
commercial anchor, contract, or waiver. A conflict rolls back that transaction.
Saved provider identities and earlier partial enrollment remain available for
recovery. A saved anniversary is sufficient to reconcile the calendar even when
the worker stopped in `provider_pending` before contract adoption. That repair
does not create the contract, waiver, or provider resources; activation continues
only after its remaining checks pass. YC operations cannot independently enroll invoices until the
transition has a receipt, and activation requires that receipt. Previously
active operations and all operations entering annual renewal reconcile a missing
receipt before continuing, without recreating contracts or provider state. They
first verify that the provider subscription start and billing-cycle anchor still
match the saved anniversary; drift leaves the periods and receipt unchanged.
This recovery runs even when a missing payment method, payment-method lookup
failure, or latest-invoice refresh failure blocks subsequent billing. Payment
readiness still gates usage and renewal; invoice validation precedes activation
and renewal.

For an untouched open `[legacy_start, legacy_end)` crossing the anniversary, it
changes only its end to the anniversary and creates the adjacent anniversary
period. Every elapsed month is materialized on a delayed retry using the original
anchor, including month-end handling. Existing exact monthly periods, statuses,
finalized history, the annual waiver, and entitlement schedule remain unchanged.
The overlap exclusion constraint remains installed. New period inserts share the
account lock, and the receipt rejects stale future periods on the old calendar
even before the new calendar has materialized those months.

The historical prefix stays open with its original start and no invented
settlement. Raw usage is still measured within half-open intervals, so a late
measurement crossing the anniversary belongs once to each side. The prefix is
not eligible for YC credit or automatic export under the new subscription. If it
later needs collection, keep it as an explicit legacy accounting obligation and
obtain a reviewed settlement plan under its original authority. Do not map it to
the YC invoice or finalize it at zero merely to clear a queue.

A successful transition stores `billing_yc_calendar_transition`: operation/team,
anniversary, previous account/anchor, complete pre-change period rows, original
approving actor/evidence reference, and commit time. The receipt is immutable.
Repeating reconciliation retains that evidence and cannot recreate a period
straddling the anniversary.

## Already-stuck operations

1. Verify the operation's team home region and provider merchant/test mode. Read
   `GET /internal/teams/:team_id/billing/yc/status`. Capture the operation ID,
   subscription/customer IDs, original annual start/end, first invoice, contract,
   and `last_error` in restricted operator evidence. This endpoint does not return
   the calendar receipt, waiver, credit schedule, or enrollment state. Obtain those
   through authorized read access to the team's regional billing database:
   `billing_yc_calendar_transition`, `billing_contract_waiver`,
   `billing_contract_entitlement_schedule`, and `billing_invoice_enrollment`.
   Keep real identifiers out of public PRs and logs.
2. Confirm the migration and worker revision in that team's regional database.
   Do not clear `enrolling`, the provider attempt, or the saved subscription.
3. Call `POST /internal/teams/:team_id/billing/yc/reconcile` with the existing
   operator credential and `X-Actor-User-Id`. The background reconciler uses the
   same path. A saved anchor/contract/enrollment needs no rollback first. The
   transition rechecks the real periods transactionally; no manual shortening is
   needed for an untouched open period. Previously adopted `ended` operations
   require this explicit call because the background scheduler excludes them.
   Recovery requires the original customer/subscription to remain the current
   account binding and retains `ended`; it does not renew or reactivate service.
   If that binding has been cleared or replaced, preserve the historical authority
   and use the reviewed accounting-conflict procedure instead.
4. On success inspect the immutable transition receipt and period list using
   the regional queries below.
   Check exactly adjacent coverage, the same original subscription/anniversary,
   the same waiver and schedule, and completed activation. Separately verify the
   current grant's issuance/adoption and scope; `active` alone is not evidence
   that Stripe has issued credit.
5. On `yc_calendar_conflict`, keep the operation pending and follow the review
   below. The message contains the team, affected interval, anniversary, and
   dependency category. Retrying does not remove or modify that authority.

Use these parameterized read-only queries with `$1` bound to the verified team
UUID and `$2` to the operation UUID returned by the status endpoint. Run them
before and after reconciliation using the approved regional billing read role;
retain the results in restricted operator evidence. No receipt row means there
is no recorded transition for that operation; an API `active` state alone does
not establish completion.

```sql
SELECT * FROM billing_yc_calendar_transition
WHERE team_id = $1 AND operation_id = $2;

SELECT * FROM team_billing_period
WHERE team_id = $1
ORDER BY period_start, period_end;
```

## Review procedure for accounting conflicts

Automatic shortening is prohibited when the period has approval, block/review
state, export/finalization markers, financial amounts, or dependent accounting
records. Even a zero-valued usage summary is a dependency. The implementation
checks these paths:

| Authority | Evidence to retain |
| --- | --- |
| Usage | `team_billing_usage`, export measurements and export usage |
| Cumulative exports | All `billing_usage_export` attempts, including uncertain or skipped attempts |
| Incremental exports | `billing_incremental_period`, allocations, events, observations, corrections, meter reconciliation |
| Invoice work | `billing_invoice_calendar`, `billing_invoice_close`, immutable plans/provider evidence |
| Close work and review | `billing_period_close_work` including live leases, `billing_period_anomaly` including resolved rows |
| Settlement | Period financials and `team_credit_ledger` period references |
| Credits | `billing_usage_entitlement`, withholding/debt evidence, its authority, frozen requests, idempotency keys and provider grant evidence |

The first four non-FK paths (usage summary, cumulative export, credit ledger, and
entitlement) are explicitly fenced; withholding/debt writers share the contract
lock. Other accounting paths are protected by direct or transitive period foreign
keys. Provider invoice-discovery/credit-inventory cursors are keyed to provider
windows, not local period authority; they are retained without changing their
keys or evidence. Non-FK records with incompatible periods crossing or following
the anniversary require review even when the period rows are already adjacent.
Writers without an exact parent period share the account lock; they fail with a
retryable lock conflict if reconciliation already holds it, rather than waiting
in the reverse lock order. Retry reloads the committed anniversary and rejects
incompatible keys.

The owning billing operator and accounting reviewer must record the following
before an operator-assisted correction:

1. Snapshot the affected period and all dependencies above, existing processing
   leases, original account/contract/waiver/schedule, and provider invoice/grant/
   meter state. Resolve uncertain provider outcomes using their existing
   idempotency and evidence procedures; do not replay under new identifiers.
2. Classify which intervals are already authoritative and who owns each usage
   allocation, accepted export, invoice and credit. Reconcile totals to the raw
   interval source. Keep pre-anniversary usage outside YC coverage.
3. If a case is truly untouched, the built-in transition is the supported
   correction: retry reconciliation and retain its receipt. A historical manual
   repair that already produced adjacent periods is accepted without rewriting
   those periods; attach the earlier operator's evidence to the incident record.
4. If dependencies exist, there is **no generic destructive SQL repair**. Do not
   delete dependencies, reset exports, zero/finalize the old period, disable
   triggers/constraints, move records to new keys, or change the anniversary.
   The reviewer must approve a case-specific settlement/correction implementation
   that retains the original authority and immutable provider associations. Test
   it on a synthetic reproduction, record before/after quantities and provider
   IDs, require a second billing review, and execute only in its explicitly owned
   regional recovery lane. Until that implementation can represent the old
   authority without overlapping the YC calendar, leave activation unresolved.
5. Attach the recovery approval, executing actor, revision, timestamps, complete
   before/after evidence, and subsequent reconciliation/grant results to the
   restricted incident record. Never edit the transition receipt to certify a
   correction it did not perform. For an operation marked active by an older
   worker, the saved state alone is not transition evidence: require its receipt
   and a successful reconciliation response before declaring recovery complete.

## Staging acceptance

Use an existing **synthetic** staging account with an open legacy period and a
verified annual subscription whose anniversary lies within it. Keep identifiers
and fixture ownership in the staging workflow's evidence, and use Stripe test
mode. Include a second account with a usage/export dependency as the conflict
control. Do not repurpose an unassigned account.

Record deployed API/worker revision and regional migration version first. Drive
approval/payment-method readiness and reconciliation through the operator API.
Confirm the empty period becomes adjacent historical/new periods, including a
retry after local adoption; the dependency control must stay pending with all
records unchanged. Verify the provider subscription, base waiver, original
anniversary and frozen price scope are unchanged. Measure synthetic usage on
both sides of the boundary and verify no pre-anniversary YC credit coverage.

After the credit-scope dependency is deployed, continue the same operation
through current credit issuance/adoption, confirm exactly one grant at the saved
scheduled amount, confirm retry does not duplicate it, and validate product
access and invoice/export evidence using the owning staging workflow. Keep a
pending result if deployment gates or that dependency are unavailable. Local
race-enabled PostgreSQL/operator fixtures are regression evidence, not Stripe
staging acceptance.
