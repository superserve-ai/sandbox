# Meter precision reconciliation

Local cumulative measurement minus exact reserved coverage determines new usage.
Provider observations never change reservations, event identities, timestamps,
payloads, or acceptance status. Manual adoption still requires exact complete
inventory equality.

## Quantity policy

`binary64-equivalent-v2` applies the same comparison to CPU, memory and storage,
for each daily/partial-edge bucket and the whole-window total. Exact equality
still passes. A nonzero signed residual requires all of the following:

- The exact local quantity is between `1e-12` and `1e9`, inclusive, and both
  quantities are positive. Zero local usage requires exact provider zero.
- The absolute residual is at most `2^(floor(log2(local))-52)`, computed with
  rational arithmetic, and both exact decimals round to the same binary64 value
  (nearest, ties to even). Magnitude alone never establishes equivalence.
- Two complete provider bucket passes match the submitted/adopted local sums at
  that precision and exactly agree with each other numerically. Pending,
  uncertain, rejected, missing, or out-of-window events cannot establish proof.
- An ungrouped reread and the local inventory remain unchanged.

For example, `24695.364339748334` and `24695.364339748336` map to the same
binary64 value. A neighboring binary64 value fails even if within one spacing.
Neither provider conversion nor the accepted residual changes local accounting.
Each comparison starts from the exact cumulative local sum; earlier residuals
never increase the allowance. A new period is reconciled independently, and
prior-period residual history remains retained.

This is a deliberately narrow acceptance policy, not a bound guaranteed by
Stripe. Stripe documents double-precision aggregation loss but does not provide
a universal error bound. Matching aggregates corroborate quantity, not individual
event identity or acceptance. See [Stripe's precision documentation](https://docs.stripe.com/changelog/dahlia/2026-04-22/billing-meter-event-values-validation).

Exact equality and provider lag remain allowed for ordinary exports outside this
residual policy range, with the normal quantity validation and reservation guards.
If a negative residual lacks complete precision evidence it remains provider
lag, preserving ordinary delivery retries without authorizing closing or
speculative resubmission. Unexplained excess,
unsupported magnitudes, malformed responses and exhausted evidence budgets require
reconciliation/operator recovery; the system never widens the allowance.

## Evidence and work bounds

Queries use the same half-open, minute-aligned event-time window. Complete UTC
days use daily summaries; partial first/last days use separate exact-window
ungrouped summaries. A decision pins one meter ID. Windows span at most 32 days
and 33 buckets. Each pass makes at most three summary requests with `limit=100`;
`has_more=true` is incomplete evidence, not a successful truncated result. Empty
provider intervals are accepted only when the corresponding local quantity is
zero. [Stripe defines these window and pagination semantics](https://docs.stripe.com/api/billing/meter-event-summary/list).

The fallback reads at most 4097 local rows to enforce a 4096-event limit, makes
two bucket passes and one ungrouped reread, and has a 30-second timeout. Meter
discovery is independently capped at five pages. The worker deadline retains
five seconds for cleanup/backoff when starting fallback work. Existing worker
leases, scheduling, submission limits and backoff remain unchanged. Provider I/O
runs outside period locks and sandbox lifecycle paths.

Decision logs include resource, meter, window, local/reserved/submitted/provider
quantities, exact signed difference, bound, policy and outcome (`equal`,
`provider_lag`, `explained_precision`, `unexplained_excess`, or `incomplete`).
Observations retain the raw provider value and errors. They are not accounting.

## Closing and compatibility

An additive migration creates append-only `billing_meter_reconciliation` history.
Each successful full-period drift observation retains raw quantities, signed
residual, both complete bucket passes, policy, period/resource/customer/meter,
collection and observation times, and an exact JSON accounting snapshot. The
snapshot includes bounded historical event/coverage state, correction version,
frozen measurements and current customer. It is compared before/after provider
work, again while persisting under the period lock, and by the database close
guard. History survives observation refresh and commercial-period rollover.

The existing close/finalization trigger retains its exact local
measured-target/reserved/submitted, unresolved-delivery and freshness guards.
For either sign of explained drift it additionally checks the history tied to that precise
observation, a collection age of at most two hours, full-period window, current
accounting/customer, policy equivalence and both complete, stable bucket partitions. Coverage is
checked using exact local bucket sums, not sums of rounded provider values. Subsequent
periods reconcile independently from zero reserved coverage. Existing correction
and disabled-resource semantics remain in place.

Immediately before export completion and finalization, the application independently
resolves each affected event name's current active meter. This has a total
30-second deadline, at most three resources and five discovery pages per resource,
and runs before acquiring period locks. The database requires the resulting
transaction-local mapping check, bound to the exact immutable evidence IDs and
aged at most 30 seconds at the gate. Missing readers, lookup failures, remaps,
expired checks and replacement observations fail closed. A remap requires fresh
applicable bucket evidence; the earlier evidence remains inspectable. Direct or
old-writer status updates cannot reuse historical drift evidence without this check.

This is current provider revalidation, not a provider transaction: a remote mapping
change after the lookup cannot be made atomic with the local commit. The bounded
check does not establish individual provider event identity or acceptance.

Deploy the additive migration before the new binary. Equality behavior remains
compatible. The database continues to validate historical `exact-daily-one-ulp-v1`
evidence using its original positive whole-window bound and exact daily sums;
new writers only produce v2 evidence. Older writers cannot produce v2 evidence.
Updating an observation
does not refresh the collection time or bind it to old history. Rolling back the
binary may block drift closing but does not rewrite usage or delete evidence.
The existing finalization transaction invokes the database guard before committing
credits/charges. Quantity evidence does not prove invoice or credit correctness.

## Recovery and rollout record

Runtime verification remains **pending** until a separately authorized rollout:

1. Record the actual deployed revision and UTC time. Re-read account, commercial
   period, work lease/error, measured usage, reservations and every event status.
   Save immutable payload/identity/coverage snapshots. Do not treat an earlier
   incident snapshot as current authority.
2. Validate in staging, then observe the normal worker processing existing work.
   Do not reset reservations, manually submit totals, replay accepted events, or
   rebase accounting to a provider summary.
3. Fix a commercial-period cutoff and compare the identical persisted event-time
   windows. Record all totals, signed differences, bucket evidence, pending
   deliveries and provider processing delay. Verify new events cover only the
   previously unreserved quantity and old payloads/coverage are unchanged.
4. Verify `billing_export_work.last_error` clears after a successful work pass.
   Inspect reconciliation errors/evidence separately. Record the next scheduled
   hourly pass and prove it exports only newly eligible usage.
5. For unsettled evidence, inspect at the next scheduled pass, then once after
   six hours, and once after 24 hours. After those three rechecks, or immediately
   for meaningful excess/invalid evidence, escalate with the retained evidence.
   Do not run an indefinite manual polling loop or enlarge numerical tolerance.
   Durable automatic retries retain their existing bounded cadence. Unsettled
   evidence remains pending, never a pass.
6. At each commercial close, retain full-period quantity evidence and separately
   verify invoice line quantities, prices, amounts and credits. A following
   period does not resolve the earlier period's discrepancy. Financial mismatches
   require an explicit correction decision; no automatic compensating charge,
   credit or usage event is authorized by this policy.

For every step retain timestamps, revision, period/cutoff, quantities, outcome
and evidence location in the private rollout record. No staging, deployed
recovery, hourly follow-up, provider settlement or invoice verification is claimed
by local implementation tests.
