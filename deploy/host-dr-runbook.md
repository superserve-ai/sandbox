# Host disaster recovery: rebuild a lost host from GCS + DB

Scope: a vmd host (or its local-SSD array) is unrecoverable. Every
sandbox it held comes back on a replacement host, cold-booted from its
newest completed backup generation. The recovery contract is
filesystem-only: files survive to the last pause or checkpoint, process
state does not. Sandbox restores are kernel-independent; only template
memory snapshots are kernel-sensitive, and those are rebuildable.

## 0. Decide and declare

- Confirm the host is actually gone (not a reboot: local SSD survives a
  reboot, and vmd's boot-time recovery handles that case itself).
- Freeze scheduling to the dead host: mark its `host` row unhealthy so
  the control plane stops placing new sandboxes.
- Note the incident start time; the RTO clock runs from here.

## 1. Provision the replacement

Per-cell specifics live in the infra envs (`infra/envs/production/*`):
machine type, zone, reservation, subnet. The known sharp edges from
prior bring-ups:

- Metal + local-SSD shapes need a matching reservation; check capacity
  before assuming the type is available in-zone.
- Verify egress works from the new host before anything else; downstream
  failures from missing egress are confusing to diagnose.
- Build the RAID array and mount it at the same path
  (`/mnt/localssd`), with the same `/var/lib/sandbox` layout.
- Deploy vmd via the normal workflow. Set `HOST_ID` to the DB row id of
  the DEAD host only at the remap step below, never while the old row
  still points at live state elsewhere.

## 2. Enumerate and dry-run

Run the bulk tool under the cell's restore identity
(`superserve-backup-ro-<cell>`, granted by an admin for the incident):

```
backup-restore -bucket <cell-backup-bucket> \
  -host-restore <dead-host-id> \
  -db-url "$DATABASE_URL" \
  -dest-root /var/lib/sandbox/snapshots \
  -concurrency 8
```

The default is a dry run. It produces the coverage ledger: every live
sandbox the DB pins to the dead host, classified as coverable (newest
completed generation present in the bucket) or uncovered. If the DB is
itself unreachable, pass `-sandboxes-file`: one sandbox id per line,
optionally followed by the latest pause's vmstate sha256 (export both
columns from a DB replica) so selection stays anchored to capture order
rather than upload-completion order.

Review the ledger before executing. The uncovered list is the
partial-failure playbook input, not a tool error.

## 3. Execute

```
backup-restore ... -execute
```

Each sandbox's newest generation materializes into
`<dest-root>/<sandbox-id>` through the single-restore path: sparse
rebuild, digest verification of every file, and a fsynced completion
marker. A destination without the marker was interrupted and must not
be consumed. Re-running is idempotent: destinations whose completion
marker already records the target generation are reported restored and
skipped. The JSON ledger lands in the dest root.

Restore is bandwidth-bound: estimate the window from your own
inventory (the dry-run ledger totals the bytes to move) against the
replacement's ingress bandwidth. Shared template bases spool once into
`<dest-root>/.base-cache` and serve every dependent sandbox from disk;
remove the cache directory after the exercise.

## 4. Validate a sample

Cold-boot a handful of restored sandboxes before the remap. The
executable path is the revive subcommand from the companion revival
PR: it is a hard prerequisite of this runbook, so treat the pair as
one deliverable and do NOT proceed to remap on a host without it. On
the replacement host, next to its vmd, write a manifest with one line
per sandbox and run it.

```
# manifest line shape. base= is the sandbox's RECONSTRUCTED base,
# which restore materializes inside the sandbox's own destination as
# base-<sha256>.ext4 (the .base-cache directory holds packed network
# blobs, NOT mountable images; never point base= at it):
#   <sandbox-id> <dest-root>/<id>/overlay.ext4 base=<dest-root>/<id>/base-<sha256>.ext4
#   <sandbox-id> <dest-root>/<id>/rootfs.ext4          # full-image sandboxes
backup-restore revive -manifest revive.txt -vmd 127.0.0.1:50051
```

Omitted vcpu/mem revive at the sandbox's recorded shape. The tool
prints per-sandbox notes for what it cannot restore from disk: env and
secret bindings re-inject through the control plane, and egress policy
rides allow=/deny=/domains= tokens or a control-plane reapply, both
before the row flips. Confirm the guest filesystem is the customer's
last pause. This is the step that turns "objects verified" into
"sandboxes recover".

## 5. Remap and reopen

- Set the host row to `draining` FIRST, before the replacement vmd
  starts heartbeating. The heartbeat auto-recovers `unhealthy` rows to
  `active` (the transient-outage path), and an active host is
  immediately placement-eligible; without the draining flip the remap
  silently reopens the host to new sandboxes before a single restore
  is validated. `draining` survives heartbeats, so it holds while the
  replacement reports in.
- Point the DB at the replacement: update the `host` row (or its
  `vmd_addr`) and set the replacement's `HOST_ID` to the dead host's row
  id. Host identity must match the row id exactly; a mismatch silently
  splits the fleet's view of which sandboxes exist.
- Restored generations carry no memory image by design, but snapshot
  rows still reference the dead host's mem paths, and the standard
  resume path expects one. Until the memoryless cold-boot resume is
  wired into vmd (tracked as the restore tooling's remaining
  acceptance), recovered sandboxes must be brought back through the
  validated manual cold-boot procedure from step 4, not by letting
  clients resume them. The enforceable gate is the sandbox row status:
  `BeginResume` only claims rows in `paused`, so leave recovered rows
  in the failed state the reconciler put them in at host death, and
  flip a row to `paused` only after its manual cold-boot validation.
  The host row's `draining` state does not gate resumes (host status
  is not consulted on the resume path), so the row status is the only
  real lock.
- Already-paused AND still-active rows need the same gate applied BY
  HAND: host death does not touch paused rows (the detector only marks
  the host unhealthy, and the reconciler leaves a paused row alone
  once its restored `vmstate.snap` exists), and the reconciler's
  auto-fail budget flips only a handful of active rows per hour, so a
  busy host leaves most rows `active` and client operations route to
  the remapped vmd the moment it heartbeats. Before starting the
  replacement, move the dead host's paused and active rows to `failed`
  with per-status compare-and-sets scoped to the host id, and flip
  each back only after its cold-boot validation, exactly like the rows
  that failed at host death.
- Sandboxes that were RUNNING at host death come back with their last
  generation's files; their timeline should show the recovery honestly
  rather than pretending continuity.
- Flip the row to `active` only at the very end, after the manual
  cold-boot validation has run: that flip is what reopens placement.

## 6. Partial-failure playbook

From the ledger:

- `uncovered`: the bucket holds no completed generation. These sandboxes'
  data did not survive. Identify the teams affected and notify with the
  last-known-good timestamp (none, for never-backed-up sandboxes).
- `failed`: the restore itself errored; retry these individually with
  the single-sandbox mode and escalate persistent integrity failures
  (they indicate bucket-side corruption, which versioning and soft
  delete can recover; that path is an admin operation).
- In-flight-at-death uploads appear as uncovered for their newest pause
  but usually have an older completed generation; `backup-restore
  -sandbox <id>` lists every restorable generation, newest first.
- Fallback restores are NOT uncovered: a sandbox whose newest pause
  never completed but which restored an older generation reports
  restored/coverable with a reason beginning `latest pause not in
  bucket` (older-capture anchor matches and completion-order fallbacks
  both carry it). Grep the ledger for that prefix to
  find every sandbox that came back on an older capture, and fold
  those teams into the same notification as the uncovered ones, with
  the restored generation's timestamp as the last-known-good.

## 7. Close out

Record measured RTO (incident start to scheduling reopened), attach the
ledger, and file follow-ups for every uncovered sandbox class the
backlog explains (for example, generations queued behind an uploader
backlog at the moment of death).
