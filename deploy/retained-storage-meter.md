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
Overlay-only producers can still deliver old payloads, but after cutover retained
quantities stay at their last accepted values until a compatible producer
returns. An older binary cannot drain a queued retained inventory: its empty
sandbox ID deliberately fails old-payload validation if the unknown inventory
field is dropped. Restore a compatible producer to drain that spool; do not
rewrite queued report identities. Do not roll back the schema or billing readers after a cutover.

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
not substitute apparent length or provisioned capacity. Lifecycle paths only
advance atomic counters; they never wait for the sampler. Receiver transactions
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
