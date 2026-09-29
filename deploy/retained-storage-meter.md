# Retained physical storage

The opt-in VMD producer (`VMD_RETAINED_STORAGE_REPORTS=true`) inventories durable
VM dependencies and committed saved snapshots after lifecycle readiness, every
five minutes. Deploy the migration and accepting API/billing workers before
opting in a host. Neither this setting nor the migration enables storage charging
or customer snapshots.

Each report is a complete host inventory carried as one item in the existing
durable storage-report spool. The worker derives teams from sandbox and saved
snapshot rows, checks completeness, and applies the inventory atomically with
its report cursor. A host/team cuts over at its first accepted inventory's
DB receipt time. Older overlay-only reports cannot overwrite that contribution.
Overlay-only reports cannot update retained quantities after cutover; those
quantities stay at their last accepted values until a compatible producer returns.
On upgrade, background spool restoration moves the existing queue unchanged into
`.storage-report-queue/state.json`. The directory at the old queue filename
prevents older binaries from reading or replacing retained payloads. During a
binary rollback, storage spool reads/writes fail and storage publication stops;
heartbeat liveness continues. Restore a compatible producer with the same host
incarnation to drain the preserved queue in order, then publish fresh inventory.
Do not remove the directory or rewrite queued report identities to enable an old
writer. Do not roll back the schema or billing readers after a cutover.

An interrupted spool migration resumes from `.storage-report-queue.migrating`
on restart. If migration fails, storage reporting stays disabled until the
filesystem problem is resolved and the daemon restarts. Preserve both paths if
a legacy queue and a staged queue coexist; automatic recovery refuses to
overwrite either. Heartbeat liveness remains independent of this recovery.

On supported Linux XFS/ext4 filesystems, FIEMAP identifies physical data ranges.
Their union is charged once per team, host and filesystem at each interval;
private inode allocation metadata is separate. Independent identical writes are
separate physical ranges. The sampler does not flush guest writes or hash file
contents. Unsupported filesystems, delayed/encoded extents, missing declared
files, lifecycle overlap, metadata changes or exceeded budgets yield an unknown
inventory. They preserve the last accepted charge and produce a bounded warning.
A partial inventory is never a deletion signal.

The scan is limited to 4,096 owners, 32,768 file observations and physical ranges,
8 MiB of durable record input and 8 MiB of report JSON, with a 30-second context
budget. Individual filesystem syscalls cannot be interrupted. Large or fragmented
hosts exceeding these limits require qualification before opt-in; the meter does
not substitute apparent length or provisioned capacity. Artifact discovery stays off lifecycle paths. Legacy dependency persistence takes
the per-VM operation lock without waiting and patches three fields in one BoltDB
transaction, checking the generation again inside that transaction. A subsequent
pause/resume can wait for that single metadata commit; no filesystem scan runs
under the lock. Qualify this contention with the lifecycle latency checks before
opt-in. Receiver transactions
retain the existing two-second timeout and short lock waits.

Owner histories record generations and physical ranges. Replacing a full memory
image with a diff replaces that owner's dependency set, including the declared
base. Resume retains any backing files still named by the durable VM record.
Confirmed sandbox deletion and host-confirmed saved-snapshot deletion close only
that owner's references. Fork copies keep shared ranges billable independently
of their source. The quantity at a report receipt applies until the next receipt
or lifecycle boundary; no endpoint averaging or host-time backdating is used.

All total, hourly, series, platform, trial and export consumers use
`storage_mib_seconds`. Legacy intervals and template accounting are clipped at
the prospective cutover. New contributions use exact bytes divided by 1,048,576
for MiB-seconds and a further 1,024 for GiB-seconds. Compute intervals, prices and
finalized/exported usage guards retain their existing behavior.

## Validation and rollout evidence

No validation or production reconciliation result is asserted by this document.
The validation runner must execute the unit suites (including
`./internal/retainedstorage/...`), integration suites and race checks. The physical
suite requires a disposable directory on a real Linux reflink filesystem:

```sh
RETAINED_STORAGE_TEST_DIR=/mnt/qualified-test-volume go test -count=1 -race ./internal/vm -run TestRetainedPhysical
```

Without that variable the physical test explicitly skips. With it, unsupported
allocation or reflink behavior fails qualification. The suite covers sparse
allocation, three forks, divergence, independent identical writes, and source
removal. It does not by itself qualify the deployed filesystem or VM lifecycle.

Before customer charging, record the host/filesystem and code revision, full and
diff pause/resume measurements, snapshot/fork generation and deletion order,
measured shared/private byte totals, report IDs and receipt times, and matching
billing quantities. Compare physical data using sharing-aware extent unions;
summing `du` over reflink copies is not an independent shared-allocation oracle.
Check unsupported/incomplete warnings, report backlog and terminal reports,
snapshot-only settlement, producer restart, and mixed-version rollback. Compare
create/resume latency and worker transaction durations under representative fleet
size and fragmentation. Raw extent-history queries and the atomic host-inventory
transaction must be qualified at those sizes before opting in production hosts.


## Existing records without generation anchors

Do not enable the retained producer on a host until every existing owner resolves.
A pre-upgrade full pause can leave `RootfsPath` and `DeltaDir` absent,
`BaseMemPath` empty, and `SnapshotPath` pointing only to the sandbox's pause.
The host record then cannot identify the original template generation.
`BasePath` alone identifies a disk base, not the template delta: multiple builds
can share that base. A block-map sidecar describes written blocks, and a pause
manifest describes current pause files; neither establishes the missing original
generation. Selecting the latest template, even the only one currently on disk,
is not a valid recovery rule. Such a host remains blocked; rejecting its inventory
preserves prior quantities but does not complete the upgrade.

Use the one-time `cmd/retained-storage-reconcile` tool before opt-in. It reads
creation references directly from the control-plane `sandbox` rows in a read-only
transaction and verifies the installed host identity and database incarnation.
It accepts immutable build directories whose `build.meta.json` matches all four
creation paths. Overlay recovery verifies the pinned `rootfs.delta` and disk base;
full-copy recovery uses the rootfs declared by that exact build. Flat or reusable
build paths, missing metadata and inconsistent references are reported as
unresolved and left unchanged. Recover authoritative historical generation
references separately for those records; never choose the latest template.

### One-time operator procedure

Build `go build -o retained-storage-reconcile ./cmd/retained-storage-reconcile`
from the qualified revision and copy the binary to the selected host. Keep
`VMD_RETAINED_STORAGE_REPORTS` disabled. Schedule a short daemon maintenance
window: suspend host admission and lifecycle requests, let active template
builds finish, stop
`superserve-vmd.socket` and `superserve-vmd.service`, and prevent automation from
restarting them until reconciliation finishes. Leave `superserve-vms.service`
and sandbox units running. The deployed VMD service uses `KillMode=process` and
its shutdown preserves VMs; this procedure does not pause, wake or delete them.
Use the configured VMD state, run and snapshot paths, not copies of state or
inferred default directories. The tool refuses to open a missing state database
or one held by VMD. Bolt's process lock excludes VMD lifecycle writers throughout each invocation, without adding work to lifecycle paths.

With `DATABASE_URL` set to a read-only credential for the correct control-plane
cell, capture a private dry-run receipt (it contains host paths and owner IDs):

```sh
umask 077
./retained-storage-reconcile --host-id "$HOST_ID" \
  --state "$VMD_STATE_PATH" --run-dir "$RUN_DIR" --snapshot-dir "$SNAPSHOT_DIR" \
  > retained-plan.json
```

The default is read-only. Each receipt records the source creation row, local
creation/pause identity, verified build metadata path, proposed dependencies and
an `unchanged`, `would_update` or `unresolved` outcome. Review the receipt, then
run the same command with `--apply`, writing a new receipt. Apply patches only
verified disk dependency fields and preserves memory dependencies, pause files,
status, policy and unknown fields. It compares the captured local generation
again in the update transaction. Successful entries remain applied if another
entry is unresolved; repeat runs safely leave completed entries unchanged.
No billing rows or reports are written.

Apply re-reads durable state in fresh transactions and runs the common complete
physical inventory, including saved snapshots, before setting `host_ready`.
Unresolved owners, control-plane/local owner mismatches and incomplete physical
measurement keep readiness false and return exit status 2. Dry runs never claim
readiness; their inventory can fail because proposed changes have not been
applied. Check every receipt and `inventory_error`, then repeat apply after any
authoritative repair. Do not opt in on the basis of a successful metadata patch
alone. Restart the daemon/socket with the producer still disabled, verify normal
reattachment, and use the rollout checks above before opting in. Running guests
can change allocation during the offline scan; retry an unknown inventory rather
than pausing them for this tool. A complete offline inventory is a point-in-time
readiness check, not a guarantee about later allocations.

### Runner-owned Linux qualification

`scripts/validate-billing.sh` preserves the retained API regression selection.
On macOS it invokes `scripts/validate-retained-docker.sh` using the unit-test
route's `golang:1.26` image, repository mount and Go module cache. The runner must
supply `CODEX_SANDBOX_DB_CONTAINER` (or `DB_CONTAINER`) for its disposable migrated
PostgreSQL container and the corresponding local `DATABASE_URL`. The Linux test
container shares that database's network namespace; suites execute serially.

The Docker helper runs the refresh-race suite, then creates a disposable 1 GiB
loop-backed XFS image with reflink enabled, records `findmnt`/`xfs_info`, and sets
`RETAINED_STORAGE_TEST_DIR` for both physical tests. It requires privileged test
containers, XFS/loop support in the existing Docker Linux VM, and package access
for `xfsprogs`. Cleanup unmounts only its own image and detaches its loop device.
On native Linux the runner supplies an already-qualified disposable directory.
Missing prerequisites fail validation; there is no skip or substitute physical
measurement. Preserve the individual test results and filesystem evidence in the
canonical validation log. This validates disposable storage, not a production
filesystem migration or production reconciliation.
