# Snapshot Architecture

Research and design notes for Superserve sandbox snapshot storage. Captured 2026-04-07.
Implementation is deferred — ship `sandbox-api-v2` first, then tackle this as a separate project.

---

## Current State (as of this writing)

### Where snapshots live

VMD writes two files per paused sandbox on the host's local NVMe disk:

```
/mnt/nvme/sandbox/snapshots/<vmID>/vmstate.snap   # CPU + device state
/mnt/nvme/sandbox/snapshots/<vmID>/mem.snap        # guest memory dump
```

These are produced by Firecracker's `CreateSnapshot` API call inside `internal/vm/manager.go`.

### What the DB tracks

The `snapshot` table has one row per sandbox with:
- `vm_id` (FK → sandbox)
- `path` (the local directory above)
- `host_id` — column exists, **never populated** (always NULL)
- `created_at`, `updated_at`

The `sandbox` table uses soft deletes (`destroyed_at`). The `snapshot` table uses hard deletes — but `DeleteSnapshot` (DB + disk removal) is **never called anywhere**. This is the leak.

### The VMD in-memory map

`internal/vm/manager.go` keeps a `m.vms map[string]*VM` in memory. This map is **not persisted**. If VMD restarts, the map is empty and any paused sandboxes become invisible to the resume path until they are explicitly rehydrated (which we also don't do yet).

---

## The Bugs / Gaps

### 1. Snapshot leak on delete

When `DELETE /sandboxes/:id` is called on a paused sandbox:
- `DestroySandbox` soft-deletes the `sandbox` row
- The snapshot files under `/mnt/nvme/sandbox/snapshots/<vmID>/` are **never removed**
- The `snapshot` DB row is **never deleted**

Over time, disk fills up with orphaned snapshot dirs.

**Fix:** In `destroyExpired` (reaper) and the `DeleteSandbox` handler, after VMD destroy succeeds, call `DeleteSnapshot(vmID)` which should:
1. `os.RemoveAll(snapshotDir/<vmID>)`
2. `DELETE FROM snapshot WHERE vm_id = $1`

### 2. No host tracking

`snapshot.host_id` is always NULL. When we add a second bare-metal host, there is no way to know which host holds which snapshot — the resume path would have to broadcast to all hosts or guess.

### 3. No VMD rehydration on restart

After a VMD crash or deploy, `m.vms` is empty. Paused sandboxes exist on disk and in the DB but the manager doesn't know about them. Resume requests will fail or create duplicate VMs.

---

## How E2B Does It (reference)

Studied from the e2b-infra repo at the time of this discussion.

- On every pause, Firecracker snapshot files are written to **local disk** (LRU cache), then **asynchronously uploaded to GCS**.
- GCS path: `gs://<bucket>/snapshots/<templateID>/<buildID>/...`
- On resume, if the snapshot is not in local LRU it is fetched from GCS.
- On sandbox delete: the `sandbox` DB row is deleted; FK cascade removes the `snapshot` row. **GCS files are NOT deleted** — this is a known TODO (`ENG-3477` in their issue tracker).
- Their snapshots are **layered diffs** (base template layer + per-sandbox diff layer), which complicates cleanup — you can't delete a base layer if other sandboxes still reference it.

### Key difference vs our setup

Our snapshots are **self-contained** — no base layer, no diffs, just the full vmstate + mem dump for one sandbox. This means:
- Cleanup is trivial: `rm -rf /mnt/nvme/sandbox/snapshots/<vmID>`
- No reference-counting needed
- We have the same disk-leak gap E2B has (GCS files not cleaned), but ours is local disk, and it is simpler to fix

---

## Proposed Architecture (3 Phases)

### Phase 1 — Fix the leak + host-aware storage (local disk, single host)

Scope: production-safe, no new infrastructure.

1. **Fix snapshot cleanup**: Call `DeleteSnapshot` from both `DeleteSandbox` handler and reaper `destroyExpired`.
2. **Populate `host_id`**: VMD reports its host ID (env var or instance metadata) when writing snapshot rows.
3. **VMD rehydration on startup**: On boot, query all `snapshot` rows where `host_id = self`, reload them into `m.vms` so resume works across restarts.
4. **Reaper safety**: Add `FOR UPDATE SKIP LOCKED` to `ListExpiredSandboxes` so multi-replica Cloud Run doesn't double-destroy.

Acceptance: no orphaned snapshot dirs accumulate; deploys don't break resume.

### Phase 2 — Object storage warm tier (multi-host ready)

Scope: adds GCS (or S3) as a warm tier for snapshots not on the local host.

1. **Async upload on pause**: After writing local snapshot, stream files to `gs://superserve-snapshots/<vmID>/`. Use a background goroutine; local disk remains the hot path.
2. **Fetch on cache miss**: If a resume request hits a host that doesn't have the snapshot locally (wrong host or after eviction), pull from GCS before calling Firecracker `LoadSnapshot`.
3. **Host-aware routing**: The control plane routes resume requests to the host that owns the snapshot (from `snapshot.host_id`). GCS fetch is the fallback, not the primary path.
4. **Cleanup on delete**: When a sandbox is destroyed, delete the GCS object (`storage.Object.Delete`) after local disk cleanup.

Storage layout:
```
gs://superserve-snapshots/<vmID>/vmstate.snap
gs://superserve-snapshots/<vmID>/mem.snap
```

### Phase 3 — Scale optimizations (future)

- LRU eviction of cold snapshots from local disk (keep only N most-recently-resumed per host)
- Pre-warming: after upload completes, keep snapshot in memory for N seconds for fast re-resume
- Snapshot deduplication if we ever move to template-based layering (not planned)

---

## Design Decisions Captured

| Decision | Choice | Rationale |
|---|---|---|
| Snapshot format | Full vmstate + mem dump (no layering) | Simpler cleanup; we don't share base layers across sandboxes |
| Local disk path | `/mnt/nvme/sandbox/snapshots/<vmID>/` | NVMe for speed; directory per vmID for easy `rm -rf` |
| Delete semantics | Hard delete on `snapshot` table + `os.RemoveAll` | No need to keep tombstones; snapshot is purely operational |
| Host-failure tolerance | Accept data loss for now | Single host today; Phase 2 GCS mitigates this |
| GCS cleanup | Delete on sandbox destroy | We can do better than E2B here since we have no layering |
| Multi-host resume routing | Route to owning host; GCS fallback | Avoids broadcast; GCS is the durability guarantee |

---

## Files to Touch (when we come back)

| File | Change |
|---|---|
| `internal/vm/manager.go` | `DestroyVM` → call `os.RemoveAll(snapshotDir/<vmID>)` |
| `internal/db/queries/snapshots.sql` | Add `DeleteSnapshot(vmID)` query |
| `internal/api/handlers.go` | `DeleteSandbox` handler calls `DeleteSnapshot` after VMD destroy |
| `internal/api/reaper.go` | `destroyExpired` calls `DeleteSnapshot` |
| `supabase/migrations/` | `snapshot.host_id NOT NULL` + backfill |
| `internal/vm/manager.go` | Startup rehydration from DB snapshot rows |
| `db/queries/sandboxes.sql` | `ListExpiredSandboxes` → add `FOR UPDATE SKIP LOCKED` |

---

## Open Questions (at time of deferral)

1. Should Phase 2 GCS upload be synchronous (safer, slower pause) or async (faster pause, window of data loss)?
2. What is the right LRU size for local hot cache? (Depends on NVMe capacity and typical sandbox size.)
3. Do we need snapshot versioning — i.e., update the snapshot on every pause rather than only the first? (Currently: yes, because `ResumeVM` calls `CreateSnapshot` again on the new state.)
4. Should we compress snapshot files before upload? Firecracker mem dumps compress well (~4:1 with zstd).
