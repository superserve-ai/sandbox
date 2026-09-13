# Paused-sandbox evacuation implementation packet

Status: proposed design awaiting ownership-commit review, 2026-09-13.
Baseline `f584e04609534807def382af30abd1e7c3b4d6ef`. No migration implementation,
artifact transfer, resume, host drain or production operation is authorized by
this document. Start with the [drain contract](host-drain.md).

## Current execution paths

- API explicit resume and data-plane-triggered auto-resume share the paused
  sandbox resume path in `internal/api/handlers.go`. `ClaimResume` in
  `db/queries/sandboxes.sql` atomically changes paused -> resuming, joins the
  snapshot/base/policy inputs and takes the existing advisory lock. This stops
  two ordinary claims, but is not a durable cross-host operation or epoch fence.
- It resolves `sandbox.HostID` through `vmdForHost`, calls `ResumeInstance`, and
  on NotFound tries stateless `RestoreSnapshot` on that **same** VMD. Missing
  local restore artifacts fail; this path does not fetch a backup generation or
  select a different host. Template base fallback is only for legacy rows;
  prefer `sandbox.base_path` pinned at creation over a rebuilt template head.
- `internal/vm/manager.go`: ResumeVM can adopt an already live VM on retry or
  restore the tracked paused record. It needs vmstate, memory, disk and its
  dependencies; validates pause intent/wall-clock policy/presence requirements;
  reconstructs network slots and restarts Firecracker/boxd. Stateless restore
  recovers paths and policy without requiring a copied host BoltDB. It may
  adopt late boot results; a caller timeout does not prove the guest is absent.
- API manual pause, idle/billing reaper pause, and compensating re-pause after
  failed resume finalization all feed pause/snapshot finalization. Pause uses
  per-attempt tokens and snapshot generations; interrupted pause markers and
  in-flight backup work must be resolved before selecting a transferable head.
- `UpdateSandboxHost` **has a caller**: `internal/api/reaper.go` rollback resume
  writes the existing `sbx.HostID` with refreshed IP, then restores active status.
  Its SQL is only ID/team/not-destroyed guarded. It has no expected old owner,
  epoch, operation or snapshot-generation CAS and must not be reused naked.
- API resume has conditional paused/resuming state writes and active billing
  interval finalization. Delayed rollback/reaper/reconciler/report writes are
  still dangerous after a host move unless fenced by ownership epoch. Audit all
  writers, not just the host_id setter. Keep current persisted-owner routing
  unchanged until the new protocol is supported at both endpoints.

## Required restore bundle: templates alone are insufficient

Resolve paths from the claimed sandbox/snapshot and actual source VMD record;
never blindly copy a directory inferred from a template ID. Common locations
are `snapshots/<sandbox-id>` and `rundir/<sandbox-id>`, but pinned record paths
and RunDirID are authoritative.

| State | Required transfer/validation |
| --- | --- |
| Firecracker device/CPU snapshot | Exact `vmstate.snap`, its disk-overlay metadata (`vmstate.snap.overlay` where present), declared snapshot format and dependencies |
| Flat guest memory | Exact current sandbox `mem.snap`, not the template's initial memory |
| Layered guest memory | `mem.diff` paired with `mem.diff.presence`, `mem.diff.base`, and the immutable base memory image referenced by that sidecar; recursively resolve actual dependency chain |
| Guest disk | Sandbox-specific `rundir/<id>/overlay.ext4` plus pinned immutable base for overlay mode; otherwise its standalone `rootfs.ext4`. Full memory format does not imply the mutable disk is contained in the snapshot directory |
| Snapshot semantics | Memory `.wallclock` manifest, artifact ID, freeze/wake metadata and relevant pause intent. Unresolved/interrupted `pause.intent` is a hard stop, not a file to discard to make restore work |
| Control-plane authority | Sandbox/team identity, snapshot ID and generation/pause token, resources, pinned base identity, network/egress policy, preview policy/revision, secret bindings; apply current authoritative policy on destination before exposing it |
| Host-local reconstruction | Allocate destination namespace, IP/MAC/tap/slots, sockets, systemd/cgroup state and VMD record through the restore API. Do not copy source live namespace/socket/PID state or overwrite destination BoltDB |

Use a versioned manifest that names the entire closure with apparent size,
SHA-256, sparse layout/presence semantics, semantic role and immutable base
reference. Verify source at rest and pin/copy-on-write its exact head before
hashing/upload; do not hold an SQL transaction across network transfer. Retain
that pin until post-commit recovery/retention permits cleanup. Atomic destination
publication requires all files verified/fsynced and a completion marker last;
partial generations must never become selectable restore inputs.

## Reconciliation with previous portability and recovery work

The earlier host-replacement portability investigation proved copied flat and
pure-layered restores on compatible hosts, including a negative test for missing
presence bitmap. Reuse that requirement and those failure cases. A sparse copy
can change extent allocation even with identical apparent bytes; the paired
presence sidecar is essential. Matching guest kernel and copied-base integrity
remain necessary. Replace its old “copy then remap host” operator step with the
transaction/fencing protocol below.

The old assertion that no object backup tier exists is now obsolete, but the
new tier is not memory resume coverage:

- `internal/vm/manifest.go:collectPauseManifest` records `vmstate.snap` and
  `rootfs.ext4` with base digest; it does **not** include sandbox memory and its
  sidecars. `deploy/host-dr-runbook.md` explicitly promises filesystem-only
  cold recovery, not preservation of running processes.
- Reuse `internal/backup` journal, immutable content-addressed generations,
  create-only object writes, manifest-last completion, sparse packing/base cache,
  `RestoreGeneration` digest validation and fresh-directory/fsync behavior.
- `covered_snapshot_id` plus `covered_snapshot_generation` is a useful exact-pause
  anchor, but current backup coverage does not prove the richer memory bundle.
  Introduce an explicit bundle kind/version/completeness predicate; do not
  silently reinterpret existing disk-only generations as portable memory state.
- `GenerationManifest.VMDVersion` and template BuildID are insufficient runtime
  compatibility attestations. There is no complete automatic fetch-before-resume
  integration in the normal paused resume path inspected here. Filesystem DR
  remains a separate mode, never an automatic memory-resume downgrade.

## Transport decision

Recommend the existing **cell-local durable object artifact pipeline**, extended
for the complete memory-resume bundle and exact current pause generation. It
provides restartable staging, verified immutable bytes and independence from a
long-running SSH session/source availability. Confirm the deployed cell bucket,
reader identity, source uploader health, read grants and full-bundle completion;
existence of code is not evidence that live staging already has this coverage.
Do not reuse an ad-hoc historical migration bucket as new authority by default.

Direct transfer inside the cell is acceptable as a future transport optimization
under the same manifest, host authentication, resource bounds, destination
quarantine and completion protocol. Private reachability alone is insufficient;
peer HTTP ingress is not a file-transfer API. Avoid distributing SSH keys to
VMDs. For the first real move, prefer durable staging; if memory-volume cost is
unacceptable, review a scoped authenticated transfer endpoint separately. Neither
transport grants ownership or permits the destination to run before commit.

## Compatibility: hard gate, not version-string comparison

Bind attestations to the actual running VMD/Firecracker artifacts and snapshot
producer, not whatever a mutable filesystem symlink currently names. Require:

- Exact approved Firecracker binary SHA-256/build identity and required API
  features (layered/presence/UFFD/clock or freeze support as applicable). Same
  printed Firecracker version is not sufficient; reject unknown provenance.
- CPU architecture and supported CPU model/features, vCPU/memory/device snapshot
  configuration, KVM availability, host-kernel/userfaultfd requirements, network
  and disk backend support. Matching binaries alone do not establish this.
- Snapshot format/schema, producer VMD build/config identity and compatible
  supervisor/boxd wake protocol; reject unsupported frozen-workload images.
- Exact guest-kernel and immutable base memory/rootfs content digests required by
  this snapshot, including base chains, plus paired sidecar semantics. Reject
  missing/mismatched metadata or mark the sandbox explicitly non-migratable.
- Destination admission/capacity reservation, persistent template/data mounts,
  enough apparent/allocated/staging space, and valid cell secretsproxy/peer trust.

Initially allow only exact known-good build/config tuples backed by staging
restore tests. Cache immutable attestations away from hot paths and invalidate
on boot/build change. Hash/transfer memory during migration preparation, not on
every ordinary resume, heartbeat or placement request.

## Proposed smallest ownership state machine — REVIEW REQUIRED

Persistent operation row: migration ID/idempotency key, sandbox/team, source,
destination, expected ownership epoch, snapshot ID+generation+pause token,
bundle digest, destination prepare receipt, admission reservation, state,
lease/attempt number, created/prepared/committed/completed times and failure.
Unique live operation per sandbox. A lease alone never grants execution rights.

1. **PAUSED -> PREPARING (source authoritative).** Under the sandbox row lock
   and existing lifecycle/advisory-lock discipline, require paused, exact source,
   epoch and snapshot head, no destroy/other resume/move. Persist the operation
   and migration claim. Ordinary explicit/auto resume and expiry/delete/reaper
   paths must respect the claim. Confirm the source guest is stopped and pin the
   complete stable bundle; fence delayed source starts before proceeding.
2. **PREPARING -> PREPARED (source authoritative).** Validate destination build,
   capacity and cell; copy/materialize into an operation-specific namespace.
   Verify all bytes/dependencies and get a durable prepare receipt tied to that
   host incarnation, epoch, bundle and reservation. No guest execution, public
   route or billable active interval on destination. Keep source resumable if
   the operation is canceled before commit.
3. **PREPARED -> COMMITTED/RESUMING (single ownership linearization point).**
   In one short DB transaction CAS expected source+epoch+paused migration
   claim+snapshot generation+operation, validate prepare/reservation still valid,
   set destination owner and increment epoch, set resuming, append assignment
   history and transactional outbox. Unique `(sandbox_id, new_epoch)` and unique
   operation ID ensure exactly one commit. Clear/replace source IP/PID only with
   destination-owned values; never carry a source PID into the new assignment.
4. **COMMITTED -> ACTIVE.** Destination consumes an epoch-bound resume command,
   rechecks ownership and prepare receipt before starting, restores once, applies
   policies/credentials/networking and finalizes active with an epoch/operation
   CAS and billing interval. Repeated commands adopt only this operation's VM.
   A lost response retries/reconciles the destination, never boots the source.
5. **Pre-commit abort.** Revoke destination preparation/reservation, retain source
   ownership and complete restore bytes; release claim only after any destination
   execution possibility is fenced. A missing cleanup ACK stays visibly pending,
   not proof of rollback. Source can then resume normally.
6. **Post-commit failure.** Keep destination authoritative in a visible failed-
   resume/retryable state and retain the bundle. Do not silently revert host_id.
   Returning to source is a new ordered transition only after destination absence
   or fencing is proven. Source cleanup is delayed until recovery retention and
   durable destination responsibility are established.

### Commit timing tradeoff to approve

**Recommendation: commit after durable destination preparation, immediately
before guest execution, as part of the resume claim.** There is a short interval
where routing sees a new owner that is not yet ready; fail clearly until resume
completes. This matches ordinary resuming behavior and prevents uncommitted
side effects. Preparation is not a promise that every eventual restore succeeds;
post-commit failures remain owned and recoverable on the destination.

Committing before copying makes failures unnecessarily disruptive. Committing
only after a destination guest has resumed offers a nicer success boundary but
runs uncommitted guest code, can race source resume, and duplicates external
side effects/billing. It requires a stronger fenced, non-executing restore and
explicit release protocol. If review requires an actual Firecracker load before
commit, load it paused with egress/data-plane blocked and prove that no guest
instructions run; this is additional runtime work, not the current RestoreSnapshot
RPC. Do not improvise this choice during implementation.

## Concurrency, delayed events and billing

Carry monotonic ownership epoch + operation ID in every mutating lifecycle RPC,
VMD local record and asynchronous completion/report; both source and destination
must support the fence before opting a sandbox into moves. Preserve legacy
HOST_ID=default: upgrade protocol support without rebinding its host identity.
A DB CAS alone cannot stop an old in-flight RPC already executing on the source.
Pin the paused generation and obtain source quiescence/revocation before commit;
a lease expiry is insufficient grounds to assume a guest stopped. Recovery must
interrogate/fence the prior executor, not simply create a newer lease owner.

Add append-only assignment history with sandbox ID, old_host_id, new_host_id,
old/new epoch, migration ID, DB commit timestamp, actor/reason, snapshot/bundle
identity. Ordering comes from epoch, not wall clock alone. Record outbox delivery
idempotency and reject old-epoch pause/destroy/activation, backup coverage,
reconciler and reaper rollback writes. The current `UpdateSandboxHost` rollback
caller must gain expected-owner/epoch/state guards rather than being exempt.
Reconcile preview/secret mutations and deletion with the same claim ordering.

Close/open active billing intervals through existing pause/activation primitives;
preparation is not active compute. Finalize activation exactly once under epoch
CAS. Historical host attribution uses assignment epoch/time, not the current
host_id joined onto delayed records. A stale proxy lookup may fail; new requests
resolve the new owner. Never replay an established exec/WebSocket/upload stream
or broadcast lifecycle requests to source and destination.

## Implementation slices and validation

1. Schema/queries: operation claim, ownership epoch/history/outbox, CAS all
   lifecycle writers, exact snapshot-head reference and rollback ordering.
2. Runtime protocol: quiesce/prepare/execute/reconcile with durable epoch fences;
   integrate existing pause intent and generation pinning. Capability-gate old
   binaries. Preserve ordinary same-host resume's fast path.
3. Complete portable bundle and build attestation; reuse object pipeline and
   atomic materialization without treating disk-only backup as memory coverage.
4. Operator explicit single-sandbox move first; normal resume stays owner-pinned
   unless explicitly opted into the reviewed transition. Background balancing,
   host-death recovery and cross-cell movement remain out of scope.
5. Staging rehearsal only after review/implementation: choose a real sandbox
   currently owned by `default`; write a persistent file and keep a process-memory
   marker so disk-only cold boot cannot masquerade as resume. Pause via the normal
   API, record snapshot generation/owner epoch and prove source stopped. Prepare
   `superserve-vmd-staging-2`, commit once, resume there, verify file **and process
   continuity**, exec/read through the normal public path (including Host 1
   ingress), pause again and verify the new generation/ownership. Optionally move
   back with a new operation/epoch. No whole-host drain is required for this test.
6. Fault/race matrix: concurrent auto/manual resume/move/delete, reaper timeout,
   source re-pause, incomplete upload, altered base/presence bitmap, wrong build,
   unsupported snapshot, destination restart/disk-full, lost prepare/commit/start
   responses, worker death at each transition, delayed old-owner events and
   repeated callbacks. Prove at most one executing owner, no source loss before
   commit, durable recovery after commit and no duplicate active billing interval.

## Review questions

- Approve preparation -> ownership commit -> guest execution, accepting visible
  destination-owned resume failure instead of implicit host rollback?
- Is preserved process memory required for the initial move? This packet assumes
  yes. Filesystem-only recovery would be a distinct explicit product contract.
- Approve durable cell-local full-bundle staging for the first implementation;
  direct authenticated transfer can follow behind the same protocol?
- Should the first API be operator-only move-and-resume? Leaving the new owner
  paused is feasible, but would be a separately specified terminal state.
- Who owns the shared admission reservation and host build-attestation protocol?
  Block incompatible hosts rather than inventing a weak fallback.
