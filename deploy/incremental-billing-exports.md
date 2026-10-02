# Incremental billing exports

This implementation uses the existing commercial anniversary period. It reserves
normalized cumulative usage in `billing_export_allocation`, and keeps immutable
provider payloads and individual delivery outcomes in `billing_export_event`.
`submitted` means the meter submission succeeded. It does not mean Stripe has
finished counting the event. `billing_export_observation` stores separately read
provider totals and their observation window, time, and errors.

## Operation

- `BILLING_INCREMENTAL_EXPORT_INTERVAL` defaults to `1h` and accepts `24h`.
- `BILLING_INCREMENTAL_EXPORT_DISABLED=true` stops the background service.
- Existing per-team export and storage flags remain authoritative.
- Discovery pages 100 accounts per minute. A worker claims one team per poll,
  scans at most 48 persisted hourly aggregates, consumes at most 48 changed
  measurements, and handles at most two active periods. Discovery starts at the
  current anniversary period on enrollment, then revisits tracked hours with
  minute-paced page continuations and waits for the
  configured cadence. Retained source values avoid rewriting unchanged hours.
  Repeated sweeps catch late commits and historical corrections; sweep duration
  grows with the number of retained hours. Rollups do not write export queues.
- Work uses persisted leases; Stripe requests have a 30-second timeout and occur
  outside transactions. Retries retain the event payload and coverage. An
  uncertain event older than 23 hours requires operator recovery.
- Unchanged usage is reconciled on a separate six-hour interval.

## Customer billing enablement

`billing_export_enabled` is the live-billing switch used by both the billing
summary and Stripe checkout. Live billing is the default for new teams. The
enablement migration inserts an explicit `true` row for every existing team
without an override, then enables the global flag. Existing team-level `false`
rows are preserved as reviewed opt-outs and take precedence over the global
default.

After applying the migration in each production cell, verify all of the
following before handover:

1. `feature_flag.enabled` is `true` for `billing_export_enabled`.
2. Every team has a `team_feature_flag` row for that key.
3. The count of `enabled = false` overrides matches the reviewed opt-out list.
4. A newly created team reports live billing and can open Stripe checkout.
5. Each reviewed opt-out remains in shadow mode and cannot open checkout.

Do not replace the migration with a global update alone: the explicit backfill
keeps the fleet state auditable and prevents a later global-default change from
silently changing reviewed opt-outs.

Production control planes in `us-east4` and `us-west2` use continuously allocated
CPU (`cpu_idle = false`) and retain ten minimum instances per revision. Both the
API and Terraform deployment workflows enforce those settings so background
exports and reconciliation continue without incoming requests. Continuous CPU
allocation increases idle compute cost. Preserve these settings during rollout
and verify worker tick activity during a period without request traffic before
completing handover.

These are initial engineering bounds, not a measured capacity claim. Before
rollout, record query plans, query counts, rows scanned/updated, duration, and lag
for idle, disabled, active, catch-up, and concurrent-worker workloads. Include the
measurement discovery sweep and the global export-flag re-enablement path in that review.

## Operator endpoints

All paths below are under the existing internal API and require platform billing
permissions. Adoption and recovery POSTs require `OPERATOR_API_TOKEN` in the
Bearer authorization header, plus `X-Actor-User-Id` for the authorized platform
admin. The host-shared `INTERNAL_API_TOKEN` cannot authorize these mutations.

- `GET /teams/:team_id/billing/periods/:period_id/export-accounting` returns event
  history and provider observations. Events and corrections are ordered by
  `(created_at, id)`, with at most 500 records per collection. Pass the last
  returned event ID as `after` and the last correction ID as `after_correction`
  to continue each collection independently. Cursors must belong to the requested
  team and period.
- `POST /teams/:team_id/billing/periods/:period_id/adopt-exports` accepts `evidence`,
  `complete_inventory: true`, and `events`. Each event supplies `resource`,
  `measured_through`, `identifier`, `idempotency_key`, `event_name`, `customer_id`,
  `quantity`, and Unix-second `timestamp`. Quantities are decimal strings.
- `POST /billing/export-events/:event_id/recover` accepts reviewed `evidence` and
  replaces a confirmed rejected event within its original reservation. It does
  not free coverage or change later accepted events. This also works after
  finalization: call the existing period export endpoint to submit the reviewed
  replacement and reconcile it. Repeat that endpoint for pending retries;
  scheduled frozen-period reconciliation only observes. Frozen usage, period
  totals, and credit records remain unchanged, and no new coverage is allocated.
  For an expired
  `recovery_required` event, include `outcome: "accepted"` or `outcome: "rejected"`
  with reviewed event-specific provider evidence. Acceptance resolves the original
  event without submission. Rejection records the outcome without releasing
  coverage; call again with evidence and no outcome to create its replacement.
  Resolution evidence is retained on the original event. Aggregate totals or an
  absent/delayed summary do not establish an event's outcome. Close still requires
  fresh matching provider reconciliation after resolution.
- The existing period export endpoint uses incremental accounting for enrolled
  periods and newly eligible authoritative periods. Initial measurement may
  return `202` with `measurement_pending`.

For adoption, first disable export and review the complete external event
inventory. Verify the exact identifiers, quantities, semantic timestamps, and
original coverage boundaries independently.
Adoption requires a boundary within the period and a timestamp equal to one second
before that boundary truncated to the minute, matching exporter attribution.
Inventories using a different timestamp convention require operator recovery;
do not change the original timestamp or invent a boundary to make them pass.
The endpoint compares all configured
billable meter totals with the supplied inventory; aggregate equality alone does
not prove the identity of each external event. If the original idempotency key is
unavailable, record an explicitly named adoption-only provenance key. Adopted
records never enter the submission queue. The endpoint leaves export disabled.
Enablement remains a separate reviewed operator action.

Use this same adoption operation to reconcile external events accepted after
enrollment. Disable export and include every active local submitted/adopted event
alongside the new external events in the complete inventory (at most 100 events).
Copy local payloads and coverage boundaries exactly; existing events retain their
identity, source, and allocation. Only new external events add coverage. Resolve
pending, uncertain, or rejected reservations through event recovery first. A
missing or changed local event rejects the inventory. Repeat the same inventory
safely, then re-enable export and run reconciliation/close to export only the
remaining usage. Finalized or already exported periods cannot be adopted into.

## Close and recovery

Retain the existing period approval step. Close measures final authoritative usage,
freezes the snapshot, and allocates the residual. Finalization requires resolved
active events and fresh matching provider observations. Credits continue through
the existing finalizer. Do not send an independent manual period delta after
incremental delivery has begun.

### First-period close checklist

Keep the existing manual recovery procedure and disabled-export instruction in
force until deployment and reviewed preload handover are complete. Record the
chosen close path and its evidence in the operator runbook. After incremental
handover, replace the old standalone manual delta with the shared export path.

1. Confirm the authoritative anniversary boundaries, subscription, adopted
   preload, and any later manual exports against the reviewed inventory. Complete
   final authoritative measurement and the existing period approval step.
2. Invoke the shared period export endpoint for only the remaining residual.
   Follow `measurement_pending` and outstanding retries to completion; resolve
   rejected or uncertain events through the event-specific recovery procedure.
   Never submit the full period or the old post-preload manual delta again.
3. Reconcile full-period authoritative CPU and memory quantities against adopted
   preload plus subsequent counted increments, including the final residual.
   Retain fresh matching Stripe observations and all event pages as evidence;
   local submission success alone is insufficient. Resolve missing/excess usage,
   pending/failed events, and stale observations before declaring close complete.
4. Inspect the subscription invoice for the same period and reconcile its metered
   quantities and charges with the full-period totals and applicable pricing.
   Verify the contractual credit is applied for the agreed amount and period,
   and that the activation credit has not been granted or applied twice. Use the
   private runbook for the actual commercial amounts and provider references.
5. Confirm storage billing remains disabled for this handover: no storage export
   events, counted storage usage, or storage invoice charges may appear. Resolve
   any unexpected storage entry before signing off the invoice.
6. Verify normal local finalization completes after the export/reconciliation
   gate. Reconcile the period's gross charges, credits applied, and net invoice
   amount with the invoice; inspect `team_credit_grant` balances and
   `team_credit_ledger` consumption for the period. Local credit consumption must
   not be assumed to prove provider credit application. Do not trigger another
   full-period export or edit finalized totals to resolve a discrepancy.
7. Verify the next authoritative anniversary period starts at the prior period's
   end with the same commercial anchor and subscription. Confirm hourly exports
   and provider reconciliation continue for new-period usage without carrying
   forward or resubmitting prior-period coverage. Record operator sign-off and
   any unresolved recovery work; incomplete checks remain open obligations.

A downward correction records a discrepancy; it never sends negative usage.
Changed measurements after export freeze become anomaly evidence. Provider errors
remain recordable after finalization without changing finalized financial totals.
Expired uncertain outcomes require provider evidence and operator reconciliation;
do not resend them under a new identity merely because a summary is delayed.

## Production operator identity rollout

Each production Cloud Run service uses a dedicated regional runtime account:
`superserve-controlplane-use4` and `superserve-controlplane-usw2`. Each account
can read its configured runtime secrets and encrypt/decrypt with the existing
`credentials-kek` key. The deployment account can act as these identities.
`OPERATOR_API_TOKEN` references `operator-api-token-use4` or
`operator-api-token-usw2`; operators provision the secret values outside Terraform.
Use independent random tokens, distinct from `INTERNAL_API_TOKEN`, and keep them
in the operator credential store. No token values belong in plans, logs, or source.

VMD accounts, including the older shared `superserve-api-runner`, retain their
existing assignments and grants. They receive no operator-secret access. Do not
grant either operator secret at project scope or grant hosts permission to
impersonate the new control-plane identities.

Before deploying the binary:

1. Review plans for both production roots. Expect new control-plane identities,
   secret metadata, secret accessor grants, key grants, deployment act-as grants,
   and Cloud Run template changes. No host identity or VM changes are required.
2. Run the shared production/us-central1 bootstrap before either regional apply.
   Normal Terraform CD and the manual west2/all rollout enforce this ordering.
   The bootstrap grants the deployment
   account `roles/iam.securityAdmin` with an exact resource type/name condition
   restricting access to the `credentials-kek` CryptoKey. CD can then create,
   repair, and remove regional runtime IAM grants without an administrator apply.
   The grant provides IAM policy management, not direct encrypt/decrypt or key
   lifecycle permissions. CD is trusted to deploy code using runtime credentials
   and to manage this key's access policy. Both workflows poll the key's
   `testIamPermissions` endpoint for up to ten minutes before proceeding, so
   eventual IAM propagation cannot release regional applies prematurely. For
   direct regional Terraform commands, run the shared bootstrap and permission
   check first. Do not run an older failed workflow revision that predates these
   dependencies. Import existing Terraform-managed resources into
   their owning root when necessary.
3. In each root, bootstrap `google_secret_manager_secret.operator_api_token`
   with a targeted apply.
   Add an enabled secret version through the approved operator credential process
   before the full apply. Terraform intentionally creates no secret version;
   an empty secret prevents a ready Cloud Run revision. If metadata or an IAM
   grant already exists, import it into its owning root before applying.
4. Apply the complete regional plans, east then west. Each API module waits for
   its secret, key, and deployment grants. CD manages the runtime key grants
   using the shared bootstrap permission. Verify both services become ready
   with the new runtime identity and operator secret reference. Exercise an
   existing KMS-backed credential operation and normal database/API access to
   confirm the identity switch preserved required access.
5. Run the normal deployment. Both production deployment workflows check the
   current service template's dedicated identity and operator secret reference
   before updating the image; a code-only deployment against old infrastructure
   fails with an instruction to complete this rollout. The check reads metadata,
   never the token. Confirm the latest ready revision receives all traffic.
6. Verify an authorized platform admin can read accounting and perform a reviewed
   adoption/recovery operation through the operator credential. Confirm the
   host-shared token is rejected for those mutations. Verify effective IAM on
   both operator secrets excludes VMD identities, including inherited grants and
   impersonation paths. Keep exporter enablement unchanged until handover.

For a binary rollback, preserve the new runtime identities, secret mappings, and
IAM grants; update the image on the current service template. Do not route traffic
to an old revision with the host-shared identity. If an identity rollback is
necessary, first quiesce operator mutations, remove the operator secret mapping,
then restore the prior identity in Terraform and revoke the new operator grants.
Adoption/recovery will remain unavailable until the isolated identity is restored;
the normal deployment compatibility gate deliberately blocks that configuration.
Do not work around it by granting the shared host account operator-secret access.
Retain secret versions for audited recovery. Let Terraform remove runtime KMS
grants before deleting the corresponding runtime identities. Retain the shared CD permission until regional grant removal
is complete.

## Rollout and rollback

Apply the migration before starting the new binary. Quiesce older export workers
and in-flight requests during cutover. Enrollment refuses existing live cumulative
attempts; use the verified `adopt-exports` endpoint while export is disabled
for their compatibility handover. Include every sent/accepted legacy event in
the complete provider inventory with matching resource, customer, event name,
exact quantity, identifier, and stored idempotency key. Supply the original
provider timestamp and reviewed measurement boundary: legacy rows do not store
those fields. Pending or failed legacy attempts require operator reconciliation
before handover; aggregate totals alone cannot resolve them. Finalized or frozen
periods remain recovery cases. Quiesce old writers before collecting evidence.
Enrollment and coverage adoption commit atomically, and subsequent catch-up
subtracts adopted quantities. Repeat adoption with the same inventory safely;
it does not submit those events. Existing cumulative rows remain intact. Once enrolled, database triggers reject cumulative writes for
that period, including writes from an older binary after rollback. Retain the
schema and fences during rollback; disable the new background service and recover
through shared event accounting. Do not delete event history or un-enroll a period
that has reserved or submitted coverage.

## Provider contracts to verify

Stripe documents at least 24-hour identifier deduplication, a 35-day timestamp
window, decimal meter values, asynchronous processing, and minute-aligned summary
queries. The implementation attributes aggregate events to complete minutes inside
the anniversary while retaining exact local coverage boundaries.

- [Create a meter event](https://docs.stripe.com/api/billing/meter-event/create)
- [Record usage](https://docs.stripe.com/billing/subscriptions/usage-based/recording-usage-api)
- [Read meter summaries](https://docs.stripe.com/api/billing/meter-event-summary/list)

The existing 12-decimal cumulative normalization is retained. A delta requiring
more than 15 payload digits is split into exact integer and fractional events.
Verify those payloads against the deployed provider before rollout; no precision
or adopted external quantity is discarded.

### Operational metrics

The control-plane recorder emits `billing_operations_total` (bounded operation
and success/error labels), `billing_operation_duration_seconds`, and
`billing_work_items_total` for ticks, measurements, submissions, reconciliation,
and backlog sampling. Alert on missing tick activity and sustained errors;
`billing_work_due_lag_seconds` measures lateness of claimed work.

`billing_event_backlog_capped` samples up to 1,000 active events per state using
an index every worker poll. Treat 1,000 as a lower bound, not an exact total.
`billing_event_oldest_age_seconds` retains the actual oldest event age even when
counts are capped. Pending, uncertain, recovery-required, rejected, submitted,
and adopted states remain separate. Each replica samples the shared database:
use the maximum across replicas, not the sum. Failed samples emit errors and
leave gauges unchanged; require recent successful sampling when alerting.

`billing_reconciliation_total` distinguishes matched, missing, excess, and
unavailable provider evidence, with fresh/stale/unknown previous observation
labels (stale means older than six hours). `billing_previous_observation_age_seconds`
records that prior age before refreshing the observation. A failed previous
observation is unknown. `billing_observed_quantity` and
`billing_discrepancy_quantity` are approximate distributions of individual
resource observations, not accounting totals or fleet gauges. Unknown provider
values emit neither a provider quantity nor a discrepancy sample. Resource labels
are limited to CPU, memory, and storage; identifiers remain in logs and the
reconciliation operator surface.

### Reviewed usage corrections

A changed hourly aggregate after close is a request for authoritative
remeasurement, not a billable delta. For example, hourly accounting at 8 units,
followed by a raw close snapshot of 10 and an hourly catch-up to 10, creates no
additional billable usage. The close snapshot stays immutable while provider
reconciliation is pending, as well as after finalization.

Use the operator credential and an authorized billing actor for these steps:

1. POST `/internal/teams/{team}/billing/periods/{period}/measure-correction`
   with `{"resource":"cpu"}` (or `memory` / `storage`). The response records
   exact normalized measurement, frozen baseline, existing reservations, proposed
   target, predecessor, period version, and PostgreSQL snapshot identity.
   Closed periods are remeasured from raw intervals and artifact retention with
   the exact anniversary bounds, including partial boundary hours. Open periods
   use the persisted incremental measurement. The accounting read endpoint lists
   correction evidence; its `after` UUID cursor applies independently to both
   the events and corrections arrays.
2. Review the source evidence and proposed target. POST
   `/internal/billing/export-corrections/{id}/apply` with
   `{"action":"accept_usage","evidence":"reviewed measurement reference"}`.
   Approval remeasures, checks reservations and correction version, and rejects
   stale proposals. If state changed, request and review a new proposal. Retry
   the same applied ID with the same action and evidence after an ambiguous API
   response; it cannot reserve the correction twice.
3. A downward discrepancy requires `action: "retain_exported"`, with evidence
   explicitly recording the decision to retain existing exported coverage.
   This disposition does not refund, credit, change an invoice, or send negative
   usage. Further growth up to that retained coverage is not billed again;
   growth beyond it exports only the excess. A further downward change below
   the reviewed measurement requires a new review. If retaining exports is not
   the appropriate commercial resolution, leave the discrepancy unresolved and
   handle the financial adjustment separately before choosing a disposition.
4. Use the existing period export endpoint to deliver approved correction events
   and reconcile the result. Positive corrections use the same immutable event
   payload, reservations, retries, rejection recovery, and provider summary
   checks as other exports, including after finalization. They never rewrite
   finalized usage, local charges, or credit-ledger entries. Old event timestamps
   remain subject to provider limits; an expired provider reporting window needs
   operator settlement, not a replacement event with a new period timestamp.
5. For an hourly-change anomaly, measure and approve each enabled resource after
   discovery. Once those reviews exist, the anomaly is resolved with the actor
   identity. Unreviewed hourly changes and downward discrepancies block the
   transition to exported/finalized. New discoveries remain visible for another
   review. Invoice and credit reconciliation remains an operator obligation.

Each operator measurement has a 20-second database statement timeout and the API
has a 25-second deadline. A transaction advisory claim limits expensive correction
reads to one per team at a time. Raw reads occur before taking the period lock;
there is no provider I/O in the transaction. Normal ticks never run this full
raw-period remeasurement. Measurements describe a consistent database snapshot:
source writes committed afterward belong to a subsequent review. Approvals use
fresh snapshots and reject changed quantities, changed freeze state, intervening
allocations, and intervening corrections. No worker, heartbeat, rollup, or sandbox
lifecycle path triggers the operator scan.
