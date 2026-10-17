# YC calendar staging candidate

This source path prepares validation of [PR #711](https://github.com/superserve-ai/sandbox/pull/711)
after the credit-scope and coupon changes. It does not change the generic credit
candidate runner or the approved calendar implementation.

**Live apply is disabled in source.** A previous deployment can pass its migration
job, fail deployment, and later rerun only that failed job with an older binary.
Workflow concurrency does not protect the service after a run ends. Before
enabling apply, the deployment owner must provide a reviewed fence effective for
historical workflow runs and their credentials, including failed-job reruns.
A check added only to the latest workflow is insufficient. Removing
`LIVE_APPLY_SUPPORTED` without that dependency is not a supported rollout.

## Invariant and outage scope

Old YC and invoice-enrollment executors must stop before the calendar migration
and compatible application startup. The API starts these schedulers before
listening, with no YC-only disable control. Traffic removal and entitlement flags
therefore cannot establish drain. With the current topology the required pause
affects the regional API and its colocated workers. Ordinary accounting writers
are protected by the calendar migration's locks and fences; this is not a request
to stop unrelated services or all provider activity.

The fixed destination is the **regional staging billing database**, using the
existing `staging` migration target. Shared Auth and production are excluded.
`candidate.json` pins the source revision, approval, latest successful CI run and
the single added migration's SHA-256. `history.json` carries the reviewed
historical variants with the post-credit-wakeup function expectation. It does
not repair or rewrite migration history. Any source, history or catalog mismatch
requires renewed review.

## Preflight and approval

After this workflow is on main with successful exact-main checks, dispatch
`YC calendar candidate` in `preflight` mode. The source PR and candidate PR must
have passed their reviews; the candidate must be an open, approved, non-draft PR
at the pinned revision. No preflight from the generic credit workflow is accepted.

Preflight builds the candidate without cloud credentials and verifies that its
inert `/bin/sleep infinity` entrypoint runs without networking. The later read-only
job checks the target, test-mode provider account, exact secret versions,
migration history/catalog, regional financial cohort, service configuration,
all service revisions and provider lifecycle observations. It inventories regional
Cloud Run services, jobs, worker pools and scheduled Cloud Run control calls.
Another possible billing executor stops validation rather than expanding the
outage automatically. The operator must also verify executors and deployment
controllers outside this inventory; a hash is not evidence of an absent external
worker. Review the complete inventory in restricted provider/database access.

Artifacts contain hashes/counts and deployment identities, not financial rows,
customer identifiers, secret values or runtime environment contents. A successful
preflight is not evidence that a future pause or migration has happened. The
receipt binds the runtime configuration, scaling, revision inventory, lifecycle
evidence, financial cohort, source and image archive. A later apply must use that
same archive and explicitly approved receipt; changed state requires a fresh
preflight and review. The full cohort is bound because resuming the API resumes
all its schedulers, including unrelated due commercial work.

The minimal human execution decision, after the deployment fence is integrated,
must approve all of the following together:

1. Exact preflight receipt and candidate image archive, regional target, maintenance
   window, complete executor inventory and enforcement against competing deployments.
2. Temporary staging API/webhook unavailability; removal of old revision tags;
   parking, migration and startup of only the approved compatible image.
3. Automatic financial effects for the inventoried cohort when compatible workers
   start, including uncertain-attempt recovery. Startup can process work before
   health checks or traffic restoration finish.
4. The existing synthetic staging account and operation selected in restricted
   evidence, its original anniversary and provider identities, permitted test-mode
   grant issuance, retry checks and fixture cleanup/residuals. No production data,
   account resets, recreated offers, invoice finalization or invoice payment.

Do not dispatch apply while its source gate is disabled. Hosted request-shape,
retirement and fixture acceptance remain unverified until an authorized run.

## Ordered execution

The dedicated workflow shares `control-plane-deploy` and `database-migrations`
serialization with the existing deployment paths. Regional SQL uses the existing
migration runner and advisory mutex. These locks supplement the required durable
deployment fence; they do not replace it.

1. Revalidate exact approval, checks, source, receipt, topology and database state.
   Publish only the approved image archive and resolve its registry digest.
2. Set service manual scaling to zero and remove old tags. Await the exact Cloud
   Run operation, successful reconciliation and observed generation.
3. Create an inert parked revision of that same image with `/bin/sleep infinity`,
   health checking disabled and no application entrypoint. Pin all traffic to it.
   Verify the returned configuration and revision. A provider rejection stops
   before migration. No candidate billing worker starts during parking.
4. Require every inventoried old revision, including previously tagged revisions,
   to report `RETIRED`, with matching observed generation and no reconciliation.
   A missing revision, missing telemetry, `RETIRING`, elapsed timeout or lease
   expiry does not establish retirement. Recheck configuration and inventory.
5. Require no active webhook-processing leases and unchanged financial authority.
   Preserve durable operations, attempts, idempotency keys and uncertain provider
   outcomes. Do not clear leases or mark work complete to force progress.
6. Recheck approval/topology/retirement, apply only the bound regional migration,
   then verify functions, writer fences, receipt RLS, unchanged overlap exclusion,
   prior migration history and financial cohort.
7. Recheck approval and retirement; install the approved image with the original
   application entrypoint and pinned secrets. Restore the recorded scaling
   configuration, with traffic exclusively on this new revision and no old tags.
   Await operations and verify health. Keep old revisions unroutable.

Cloud Run [manual scaling](https://docs.cloud.google.com/run/docs/configuring/services/manual-scaling)
does not disable tag-only revisions. The provider's
[revision lifecycle](https://docs.cloud.google.com/run/docs/managing/revisions)
defines retired infrastructure. The runner uses this lifecycle evidence rather
than delayed or absent monitoring samples. Cloud Run updates return
[long-running operations](https://docs.cloud.google.com/run/docs/reference/rest/v2/projects.locations.services/patch);
an accepted request alone is not completion.

## Stop and recovery

There is no automatic rollback and no automatic retry of an interrupted apply.
Retain the preflight receipt, image artifact, workflow logs and `yc-calendar-audit`
journal. The journal records timestamps, phases, operation identities and revision
lifecycle evidence without secret or financial contents. Preserve provider-side
operation evidence as well: abrupt runner termination can interrupt artifact
upload. A submitted update may complete after a runner timeout or cancellation.

| Last phase | Required recovery |
| --- | --- |
| Before `pause_requested` | No service mutation was requested by this path. Review changed evidence and obtain a fresh preflight. |
| `pause_requested` or `park_requested` | Resolve every recorded Cloud Run operation and inspect actual service/revision state. Migration was not requested yet; do not infer retirement or blindly restore tags/scaling. A separately approved restoration may use the recorded original configuration only after proving no calendar migration/transition exists. |
| `old_revisions_retired` | Keep the service parked. If cohort or approval changed, review it and prepare a new bounded recovery; do not edit billing rows to recreate the receipt hash. |
| `migration_requested` | Outcome may be unknown. Inspect exact regional migration history, SQL/catalog and immutable calendar receipts. Never rerun old SQL, delete history, or resume an old binary based on a failed workflow status. |
| `migration_verified` | Keep the calendar schema and parked service. A separately reviewed forward recovery must use this or a newer compatible image and recheck the retirement barrier. |
| `application_start_requested` or later | Compatible workers may already be running and may have issued provider requests. Inspect actual operations, revisions, scaling and billing evidence. Do not claim the service remains parked. Any renewed pause is a separately approved action; preserve uncertainty and use normal idempotent recovery. |

Do not rerun only failed jobs of an older deployment, dispatch the generic credit
apply path, restore old traffic tags, reset subscriptions, recreate offers, delete
calendar receipts or truncate accounting history as recovery. The durable
deployment fence must remain in force through failure, cancellation and recovery.

## Fixture acceptance after deployment

Use an approved existing synthetic account with an untouched open legacy period
straddling its original YC anniversary. Continue the same operation through
activation and credit issuance once the credit-scope dependency is available.
Record the adjacent historical prefix and new period, immutable transition receipt,
unchanged annual waiver/schedule/provider identities, and one grant identity across
retries. Verify usage before and after the boundary is attributed once and that
pre-anniversary usage receives no retroactive YC coverage.

Use a separate synthetic conflict control with existing accounting dependencies;
verify an actionable conflict and preserved authority. Reuse the calendar PR's
integration tests for detailed dependency and concurrency invariants. Actual
invoice consumption is a separate acceptance phase; this procedure does not
authorize creating, finalizing or paying invoices. Record the account/operation,
periods, grant, deployed revision, migration digest, cleanup and residuals in
restricted evidence. Do not report activation or rollout acceptance complete
while calendar reconciliation or the approved grant/access checks remain pending.
