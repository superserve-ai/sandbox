# Automatic billing period closing

The controlplane discovers ended commercial periods and validates, exports,
settles and releases eligible invoices without an admin approval. Each region
uses its own database and existing billing-export feature eligibility. An
invoice marked `released` has passed local settlement checks and may proceed
through Stripe's existing collection method; it does not imply payment success.

## Operation and capacity

Apply the schema migration before deploying the worker. Old human approvals
remain readable and valid. Set `BILLING_AUTOMATIC_CLOSE_DISABLED=true` to stop
new automatic attempts and invoice reconciliation/release, including calls from
the incremental exporter. Restart the affected controlplane revisions to apply
configuration changes. Already dispatched provider requests cannot be recalled.

The billing-export feature flag prevents new approval/export work. Already
frozen, enrolled periods continue reconciling their accepted usage and immutable
invoice settlement even if that flag is disabled. Recovery does not allocate or
submit new usage while exports are disabled; incomplete delivery remains held.
Use the emergency automatic-close switch above to stop invoice release as well.

Discovery traverses 100 periods per page using the period primary key; it waits
one minute after a complete sweep. A replica processes at most four sequential
attempts per batch with a 60-second batch deadline, then waits 5-6 seconds.
Atomic claims cap this new worker at four active attempts per regional database,
regardless of replica count. Other existing export/enrollment workers retain
their own budgets. This is a concurrency budget, not a promise about Stripe
requests per second. Provider transport retains its 15-second request timeout.

A claim expires after two minutes; attempts run for at most 60 seconds, with a
separate three-second acknowledgement. Only the matching claim token may record
its result. Invoice settlement uses the same per-team transaction advisory lock
as enrollment. Close claims also acquire the existing export worker's team lease,
so incremental export and automatic closing cannot run concurrently for a team,
including during rollout alongside older exporters. Account associations are
re-read after ownership is acquired.
Manual approval and automatic approval share the snapshot transaction and
period row lock. Export events and local credit settlement retain their existing
idempotency and immutable-plan gates.

Validation/provider errors retry after five minutes. Future provider cycles
retry no later than the mapped end, with a maximum six-hour wait. The queue
preserves attempts, last attempt/progress, stage and bounded error detail even
before an invoice close plan exists. Released work stops consuming the queue.
Use these records for restricted operator diagnosis; do not put team or invoice
identities into metric labels. The `period_close` operation uses existing work
metrics. Independent overdue and worker-absence alerts are deployed separately.

Capacity acceptance target: a 1,000-period due queue must be traversable without
starvation or duplicate active ownership. Measure actual close latency during
rollout; at four active attempts and a measured 1-second average attempt, a
1,000-attempt workload has a 250-second service-time lower bound before polling,
provider waits and retry delays. A period may require multiple attempts. The
60-second attempt ceiling is a protection limit, not an expected latency or a
completion SLA. Provider waits and financial blockers cannot be counted as
completed throughput. Do not raise concurrency without checking database pool
headroom and provider rate limits shared with other billing workers.

## Recovery and classification

Read current account, period, invoice calendar, close-work and immutable-plan
state in the owning region. The automatic path attempts all eligible ended
periods; there is no deployment cutoff or separate historical approval list.

- Verified commercial activation and a matching calendar: allow normal processing.
- Missing invoice enrollment: the worker invokes existing provider-validated
  enrollment. Missing subscription sync or unprovable historical enrollment stays
  held with a diagnostic; do not backdate enrollment or reconstruct invoice
  authority from elapsed time alone.
- Future provider cycle: retain the hold until the mapped cycle ends.
- Incomplete storage, unresolved anomalies, or differing usage/credits: correct
  the underlying evidence through its owning workflow, then retry normally.
- Pre-activation, trial-only and approved non-billable history: preserve the
  original treatment and access. Missing subscription is not proof of zero usage.
- Abuse restrictions or an activation recovery hold: preserve financial records;
  do not restore grants, entitlements, login access or compute eligibility.

The worker never runs the activation-recovery command, changes access controls,
or grants activation credits. Account-specific exemptions and audit evidence
belong in private operational records, never public code or fixtures. Enabling
billing export for an exempt account is a separate authorized billing-policy
change, not a cleanup action.

If manual recovery is required, use the owning regional internal API with the
existing platform billing-write authorization: read the period and export
preview, approve through the admin endpoint, then export. A conflict is a
blocker to investigate, not permission to edit statuses or finalize in Stripe.
Verify local `finalized_at`, immutable close state `released`, and the actual
provider invoice/customer/calendar/amount and payment outcome. A zero-dollar
invoice still requires the same settlement evidence.

## Rollout and outstanding production checks

Code publication does not authorize customer charges or database-session
termination. Validate in an isolated database first. After an authorized rollout,
observe a clean newly due period through release in each region and a controlled
blocker remaining held. Recheck existing recovery candidates against fresh
provider state; preserve completed prior recovery and pending exclusions.

Older replicas acquired session advisory invoice locks that can survive on
transaction-pooler backends. This worker uses transaction locks on the same key,
so it deliberately does not bypass old owners. Drain old revisions and have the
owning operator identify any orphaned locks from fresh backend evidence before
coordinated recovery. Never use a saved PID list or blanket session termination.
A lingering lock is not a reason to replace an immutable plan or mark an invoice
released by hand. The separate ownership-recovery work remains responsible for
production orphan cleanup and verification under the deployed pooler.
