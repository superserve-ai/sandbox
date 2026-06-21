# Durable `/state` mount — validated chain + the production-integration decision

Status: **every mechanism built and hardware-validated; the production boot-path
integration is a characterized architectural choice (below), not a thread-through.**

## What is built and proven on the staging KVM host

The durable `/state` is a **block device** — the Firecracker-native form, because
Firecracker has no directory-sharing transport (no virtio-fs). The full chain:

1. **`LocalBlockProvider`** (`internal/state/localblock.go`) — backs each durable
   identity with a formatted ext4 image (`state.img`); whole-image versioning
   (checkpoint = atomic copy, branch = fork, rollback = atomic swap).
   - Unit-tested `-race`. `mke2fs -F -q -t ext4 <file> NM` (what it runs) produces
     a mountable ext4 that data round-trips through — verified on the host.
2. **vmd attach** (`FirecrackerConfig.StateDiskPath` → `ConfigureMachine`) —
   attaches the image as the VM's second drive (vdb), non-root, rw.
3. **boxd mount** (`cmd/boxd/state.go`) — mounts `/dev/vdb` at `/state` on boot,
   `nosuid/nodev`, idempotent, mount-only (never mkfs's existing state).

**End-to-end proofs (raw Firecracker on the host):**
- Boot with the state drive → `state: mounted /dev/vdb at /state (durable)`, then
  in-guest `cat /state/marker` returns the pre-seeded contents. `/state` is real
  and durable inside the guest.
- **Snapshot survival (the load-bearing claim):** cold-boot a `/state`-bearing
  VM, write `pre-snapshot-v1` to `/state`, take a Full snapshot, restore in a
  **fresh** Firecracker → the restored guest resumes with `/state` mounted and
  `cat /state/marker` → `pre-snapshot-v1`. **A snapshot captures the `/state`
  drive in its device set, and `LoadSnapshot` re-opens it — `/state` survives
  hibernate intact.**

That proof resolves the design question for Actors: an Actor that boots **once**
with its `/state` drive keeps `/state` across every subsequent Tier-2 hibernation
(its own snapshots inherit the drive; restore preserves it).

## The remaining production-integration decision

Production sandboxes do **not** cold-boot — they boot by **restoring a shared
template snapshot** (`RestoreSnapshot`). Two facts constrain how per-identity
`/state` reaches them:

- Firecracker `LoadSnapshot` restores the **exact device set recorded in the
  snapshot**; `SnapshotLoadParams` exposes `NetworkOverrides` and `BlockDeltaDir`
  (rootfs overlay) but **no drive-path override**.
- `coldBootFromRootfs` (the only path that configures drives freely, via
  `ConfigureMachine`) is the **template-build** path — its VM is snapshotted into
  a *shared* template, so a `/state` drive baked there would be one placeholder
  shared by all sandboxes, not per-identity.

So per-identity `/state` needs a deliberate boot-path addition. The options:

1. **Per-identity cold boot for Actors** (recommended). Actors that need durable
   `/state` cold-boot once with their own `state.img` attached (a new
   Actor-boot path that calls the cold-boot primitive with `StateDiskPath`), then
   hibernate — validated above to preserve `/state`. Generic non-Actor sandboxes
   keep the fast template-restore path with no `/state`. Clean separation; uses
   only validated mechanisms; the first-boot cost amortizes over the Actor's life.
2. **Drive-repoint on restore.** Bake a `/state` placeholder drive into template
   snapshots and re-point it per-identity after `LoadSnapshot(resume=false)` via
   `PatchGuestDriveByID`, then resume. Avoids a second boot path but is
   boot-ordering-fragile: boxd mounts `/state` at boot, so the template snapshot
   would capture the placeholder *mounted* — swapping the backing under a mounted
   fs is unsafe. Would require deferring the `/state` mount until after
   restore+patch (a boxd/init ordering change) and is unvalidated.
3. **Firecracker drive-override-on-load** — a fork feature (Rust change) adding
   per-drive backing overrides to `LoadSnapshot`, mirroring `NetworkOverrides`.
   Cleanest long-term, but a firecracker-fork change + rebuild.

**Recommendation: option 1.** It is fully validated end-to-end today and needs
only controlplane wiring (resolve the Actor's identity → `provider.Mount(id)` →
cold-boot with `StateDiskPath`), exercisable against the live integrated stack.
