# Durable template builds

New API and seed submissions capture specification and CPU/memory/disk shape.
The logical ID stays stable; each attempt has a unique `build-<attempt UUID>`
VM and directory. `template_build_execution` owns the current attempt and one
first-start deadline. `template_build_attempt` retains the host, installed
incarnation, rejection/failure reason, and cleanup obligation.

Bounds are fixed for the new protocol: two minutes before the first dispatch,
60 seconds for registration, three total execution attempts, and 30 minutes
from first dispatch through publication. Admission rejection consumes no
attempt and restores the original queue budget if nothing was admitted.
Replacement waiting never resets the execution budget. Seed waits 35 minutes.
A lost heartbeat, replaced incarnation, or confirmed missing execution after
registration grace permits a retry on an unused host. Uncertain transport
reconciles the same attempt; deterministic and unclassified VMD failures fail
it. Storage/control-plane outages reconcile the existing upload, without
rerunning guest steps.

Hosts must advertise `template_build_v1` on a fresh heartbeat, be active, and
match `TEMPLATE_BUILD_REGION` exactly (the registry's full region name, not a
short sandbox-ID prefix). The database is scoped to one environment. There is
no configured-host fallback. Ranking includes attempt load and CPU/memory
pressure relative to requested resources; pressure is advisory under the
existing overcommit policy. The VMD network allocator still admits each build.
The VMD deployment sets `VMD_ADVERTISE_ADDR` from the host interface for hosts
with `BACKUP_BUCKET`. VMD advertises build readiness only when this pressure
publication prerequisite is configured. Before enabling submissions, confirm
each eligible host also has a fresh `host_pressure` report accepted by the
control plane.

A global database claim lock enforces ten concurrent logical builds by default;
API team admission remains unchanged. VMD admission calls back under the same
host row lock used by drain. Already-admitted work may finish while draining.
Admission and owner RPCs carry versioned gRPC metadata:
`template-build-attempt` and `template-build-incarnation`. Only capable hosts
receive it; a different installed incarnation rejects it.

## Durable producer contract

The existing content-addressed uploader verifies every object and writes the
manifest before banking a notification in its durable outbox. The manifest and
outbox retain exact runtime paths, hashes, sizes, build metadata, and original
incarnation. A deduplicated manifest may omit per-file object names from the
report: the publication's immutable `manifest_object` is then the authoritative
mapping from file name to packing-specific object. Never derive these names.
Before fencing a lost producer, the control plane lists only that attempt's
generation prefix in the cell bucket. A completed manifest is checked against
the attempt identity, content address, artifact paths, and hashes, then recorded
through the same publication transaction as an outbox report. A bucket read
failure defers retry; an absent manifest permits retry. The control-plane
runtime identity therefore needs read and list access to `templates/` in its
own cell bucket. The storage reader is initialized at startup and closed on
shutdown.

The authenticated backup endpoint persists a `template_build_publication`
scoped to template, logical build, attempt, team, cell, submission revision,
bucket, and generation. `accepted_at IS NOT NULL` identifies accepted versions;
consumers can rescan this table after restart. Acceptance atomically changes
the logical status and template paths/resources. Submission revision prevents
an older completion from replacing a newer accepted version. No publication
means no new `ready`, even if VMD reports local success. Historical ready rows
without publications retain their historical meaning. The existing cross-cell
team migration command refuses teams with new execution records, because its
copy protocol does not yet transfer attempt/publication authority. Copying only
the mutable template row would lose this producer contract.

`BACKUP_BUCKET` must match VMD and the control plane in each cell. Staging and
both serving production cell configurations include this setting and
`TEMPLATE_BUILD_REGION`. The existing VMD workflow configures the bucket,
control-plane URL, internal token, and host region. The new report never strips
publication fields to satisfy an older server; deferred notifications remain
outboxed without blocking unrelated entries. Disable submissions during any
rollback rather than downgrading publication proof.

Cancellation/deletion atomically fences attempts. Cleanup uses recorded owners
and refuses a replacement incarnation; unreachable cleanup records persist.
Accepted or reported publications and live sandbox references protect files.
This intentionally retains old accepted versions: fleet retention/deletion is
a separate consumer. No recipient-host distribution, cache warmup, or sandbox
placement is implemented here. Keep the manual template-tree transfer bridge
until the distribution consumer is deployed; producer success alone does not
make a fresh host ready to run those templates.

## Rollout and rollback

1. Pause new seed jobs and API template submissions. Let existing builds finish
   within their existing 30-minute deadline while their old supervisors can
   still finalize them, or cancel their recorded VMD executions and wait for
   subprocess shutdown. Then quiesce every old build supervisor. Do not change
   default-host configuration to redirect old work.
2. Apply the immutable-input and execution migrations in each cell. The
   execution migration refuses to apply while any legacy build is pending,
   building, or snapshotting; it does not cancel builds or wait for completion.
   If it refuses, finish or cancel the remaining work and retry the migration.
   Historical inputs are not backfilled, and historical ready rows are
   untouched. The schema rejects old finalizers/dispatchers for new-contract
   rows, and canonical database input identity prevents duplicate work across
   hash formats.
3. Deploy the new control plane, including the admission and enriched backup
   routes, matching region/bucket configuration, and supervisor. Keep all old
   submitters/supervisors stopped. Deploy VMD with the existing backup reporter
   authentication and the new capability. Observe a fresh active heartbeat
   advertising `template_build_v1` in each cell before enabling submissions.
4. Enable submissions and seed jobs. Confirm `execution` in build status gives
   the attempt, retry reason/count, cell, and publication state. Logs include
   build/attempt/host IDs and accepted publication state. Check cleanup backlog
   rather than deleting unknown artifact directories manually.
5. On rollback, quiesce submissions and supervisors first. Keep schema and
   outbox data. Do not roll old writers back into a cell with active new-contract
   work. Finish/cancel those attempts with the new software before rollback;
   historical local-only readiness must never be relabeled durable.

The only added synchronous remote call is template-build admission. It is
bounded to ten seconds and runs after network-slot reservation, before user
steps. It adds no I/O to sandbox create/resume. Hashing/upload stays in the
existing background build/backup paths, with existing hash/upload metrics.

## Staging smoke and validation

The live smoke test is manual; CI/CD does not run it or wait for its result.
Use staging-only deployment dispatches for the initial validation. Coordinate
the production rollout window before merging: a push to main triggers migration
and deployment workflows that progress from staging to production without a
smoke-test gate.

The outer validation runner owns unit/integration suites and infrastructure
validation. Run focused suites covering supervisor, backup, VMD, API, seed,
and the database integration tests in `template_build_execution_test.go` and
`template_build_input_test.go`. No test result is implied by this runbook.

Use the existing compatible active staging host for initial live validation.
Submit disposable 1/2/8-vCPU templates through the seed/build interfaces and
require an accepted durable publication before each becomes ready. Seed
unchanged twice, change one spec, change one resource shape, then force rebuild;
expect zero, one, one, then all targeted logical builds. A failed/cancelled
rebuild must leave previous ready paths and resources usable. Record build and
attempt IDs, owner, accepted generation/manifest, and actual results before
production activation. This validates the deployed build/publication path;
it does not demonstrate cross-host failover.

Do not provision additional hosts or reactivate a draining host solely to
validate this rollout. Automated multi-host scheduling, retry, and fencing
coverage remains required. Live cross-host fault injection is deferred until
two compatible hosts are available and the selected owner's interruption will
not affect unrelated workloads; it is not a merge prerequisite. Record that
live failover remains unverified until the exercise succeeds.

For that later exercise, run
`scripts/smoke-template-builds.py --failure-helper <executable>` with staging
`DATABASE_URL`, `SYSTEM_TEAM_ID`, and a built `seed-templates` on PATH. This
script requires two eligible hosts and is not the single-host validation above.
The helper receives the recorded host ID, stops that owner while leaving an
alternate eligible host, and must return within two minutes. The script
submits 1/2/8-vCPU builds, requires the interrupted logical build to retry on
another host, requires accepted publications for all three, and verifies an
unchanged seed run adds no builds. Arrange recovery of the interrupted host
even if the test fails. Keep redeploy, drain, queue-expiry, and upload/restart
fault exercises scoped to an isolated test window rather than interrupting
the sole serving host.
