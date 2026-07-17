-- Runtime checkpoints -------------------------------------------------------

-- name: CreateSnapshot :one
-- Legacy/internal runtime-checkpoint insert. Saved snapshots are admitted
-- through BeginSavedSnapshot so count, policy, lineage, and source ownership
-- are captured atomically.
INSERT INTO snapshot (sandbox_id, team_id, path, mem_path, size_bytes, trigger, kind, status)
VALUES ($1, $2, $3, $4, $5, $6, 'runtime_checkpoint', 'ready')
RETURNING *;

-- name: GetSnapshot :one
-- Team-scoped runtime-checkpoint lookup used by pause/resume handlers. Saved
-- snapshots have separate methods so a reusable snapshot can never be passed
-- accidentally to the same-sandbox resume path.
SELECT * FROM snapshot
WHERE id = $1
  AND team_id = $2
  AND kind = 'runtime_checkpoint';

-- name: GetSnapshotByID :one
-- Unscoped runtime-checkpoint lookup for internal host/reconciler paths.
SELECT * FROM snapshot
WHERE id = $1 AND kind = 'runtime_checkpoint';

-- name: ListSnapshotsBySandbox :many
-- Runtime-only compatibility method used by sandbox teardown.
SELECT * FROM snapshot
WHERE sandbox_id = $1 AND kind = 'runtime_checkpoint'
ORDER BY created_at DESC;

-- name: ListSnapshotsByTeam :many
SELECT * FROM snapshot
WHERE team_id = $1 AND kind = 'runtime_checkpoint'
ORDER BY created_at DESC;

-- name: DeleteSnapshot :exec
-- Runtime checkpoints are replaceable and may be hard-deleted. Saved rows use
-- the claim/finalize soft-delete flow below.
DELETE FROM snapshot
WHERE id = $1 AND kind = 'runtime_checkpoint';

-- name: DeleteSnapshotsOfDestroyedSandboxes :execrows
-- Backstop for destroy teardown that never ran. Never collect saved snapshots:
-- they have their own lineage-aware deletion/GC lifecycle.
DELETE FROM snapshot s
USING sandbox sb
WHERE s.sandbox_id = sb.id
  AND s.kind = 'runtime_checkpoint'
  AND sb.destroyed_at IS NOT NULL
  AND sb.destroyed_at < now() - interval '1 hour';

-- Saved snapshots -----------------------------------------------------------

-- name: GetSavedSnapshotByIdempotencyKey :one
-- Idempotency keys are scoped to the team + source endpoint and retained
-- across soft deletion.
-- Call this under the same transaction/advisory lock as BeginSavedSnapshot;
-- after a unique-violation it is also the authoritative adopt lookup.
SELECT * FROM snapshot
WHERE team_id = sqlc.arg(team_id)
  AND sandbox_id = sqlc.arg(sandbox_id)
  AND idempotency_key = sqlc.arg(idempotency_key)::text
  AND kind = 'saved';

-- name: BeginSavedSnapshot :one
-- Claim an active/paused source without changing its public lifecycle status,
-- then persist the creating intent and snapshot-time policy in one statement.
-- snapshot_operation_id excludes pause/resume/delete until finalize/fail clears
-- the claim. Callers that allow secret binding writes must first take
-- LockSandboxForSecretWrites in the same transaction so secret_bindings is an
-- exact snapshot of the source configuration.
--
-- Lock the host before claiming the source. This is the durable admission
-- boundary for a host drain: either capture owns the active-host lease first
-- (and drain waits, then observes snapshot_operation_id), or drain flips the
-- host first and this statement returns no row without touching host storage.
-- A fork's parent snapshot is then locked FOR KEY SHARE. Leaf deletion locks
-- the same row FOR UPDATE, so a child snapshot and parent deletion cannot both
-- win.
WITH host_admitted AS MATERIALIZED (
  SELECT h.id
  FROM sandbox source
  JOIN host h ON h.id = source.host_id
  WHERE source.id = sqlc.arg(sandbox_id)
    AND source.team_id = sqlc.arg(team_id)
    AND source.destroyed_at IS NULL
    AND h.status = 'active'
  FOR SHARE OF h
),
parent_locked AS MATERIALIZED (
  SELECT p.id
  FROM sandbox source
  JOIN snapshot p ON p.id = source.source_snapshot_id
  JOIN host_admitted admitted ON admitted.id = source.host_id
  WHERE source.id = sqlc.arg(sandbox_id)
    AND source.team_id = sqlc.arg(team_id)
    AND p.team_id = sqlc.arg(team_id)
    AND p.kind = 'saved'
    AND p.status = 'ready'
    AND p.deleted_at IS NULL
  FOR KEY SHARE OF p
),
claimed AS (
  UPDATE sandbox s
  SET snapshot_operation_id = sqlc.arg(snapshot_id),
      snapshot_operation_started_at = now(),
      updated_at = now()
  WHERE s.id = sqlc.arg(sandbox_id)
    AND s.team_id = sqlc.arg(team_id)
    AND s.destroyed_at IS NULL
    AND s.status IN ('active', 'paused')
    AND s.snapshot_operation_id IS NULL
    AND feature_enabled('sandbox_snapshots_v1', s.team_id)
    AND EXISTS (SELECT 1 FROM host_admitted)
    AND (s.source_snapshot_id IS NULL
         OR EXISTS (SELECT 1 FROM parent_locked))
  RETURNING s.*
)
INSERT INTO snapshot (
  id, sandbox_id, team_id, path, mem_path, size_bytes, trigger,
  kind, status, name, idempotency_key, parent_snapshot_id, source_status,
  template_id, template_snapshot_path, template_mem_path, base_path, delta_path,
  host_id, vcpu_count, memory_mib, disk_mib, network_config, timeout_seconds,
  auto_delete_seconds, secret_bindings, secret_env_keys
)
SELECT
  sqlc.arg(snapshot_id), c.id, c.team_id, '', NULL, 0, sqlc.arg(trigger),
  'saved', 'creating', sqlc.narg(name), sqlc.narg(idempotency_key),
  c.source_snapshot_id, c.status, c.template_id, c.snapshot_path, c.mem_path,
  c.base_path, c.delta_path, c.host_id, c.vcpu_count, c.memory_mib, c.disk_mib,
  c.network_config, c.timeout_seconds, c.auto_delete_seconds,
  COALESCE((
    SELECT jsonb_agg(
      jsonb_build_object(
        'env_key', ss.env_key,
        'secret_id', ss.secret_id,
        'secret_name', sec.name
      ) ORDER BY ss.env_key
    )
    FROM sandbox_secret ss
    JOIN secret sec ON sec.id = ss.secret_id
    WHERE ss.sandbox_id = c.id
  ), '[]'::jsonb), c.secret_env_keys
FROM claimed c
RETURNING snapshot.*;

-- name: FinalizeSavedSnapshot :one
-- Artifact commit and source-claim release become visible atomically. The
-- storage trigger serializes on the team row and raises SS004/SS005 if the
-- explicit storage quota is absent/exceeded; in that case neither update lands.
WITH source_locked AS MATERIALIZED (
  -- Keep lifecycle and quota-trigger lock ordering sandbox -> team. Without
  -- this explicit source lock, the storage trigger could lock team first and
  -- deadlock with DestroySandbox, whose quota trigger takes the reverse path.
  SELECT source.id
  FROM snapshot intent
  JOIN sandbox source
    ON source.id = intent.sandbox_id AND source.team_id = intent.team_id
  WHERE intent.id = sqlc.arg(snapshot_id)
    AND intent.team_id = sqlc.arg(team_id)
    AND intent.kind = 'saved'
    AND intent.status = 'creating'
    AND intent.deleted_at IS NULL
    AND source.snapshot_operation_id = intent.id
    AND source.destroyed_at IS NULL
    AND source.status = intent.source_status
  FOR UPDATE OF source
),
finalized AS (
  UPDATE snapshot s
  SET status = 'ready',
      path = sqlc.arg(path),
      mem_path = sqlc.arg(mem_path)::text,
      size_bytes = sqlc.arg(logical_size_bytes),
      manifest_path = sqlc.arg(manifest_path)::text,
      manifest_digest = sqlc.narg(manifest_digest),
      artifact_metadata = sqlc.arg(artifact_metadata),
      logical_size_bytes = sqlc.arg(logical_size_bytes),
      exclusive_size_bytes = sqlc.arg(exclusive_size_bytes),
      failure_reason = NULL,
      finalized_at = now(),
      updated_at = now()
  WHERE s.id = sqlc.arg(snapshot_id)
    AND s.team_id = sqlc.arg(team_id)
    AND s.kind = 'saved'
    AND s.status = 'creating'
    AND s.deleted_at IS NULL
    AND EXISTS (SELECT 1 FROM source_locked)
  RETURNING s.*
),
released AS (
  UPDATE sandbox source
  SET snapshot_operation_id = NULL,
      snapshot_operation_started_at = NULL,
      updated_at = now()
  FROM finalized f
  WHERE source.id = f.sandbox_id
    AND source.team_id = f.team_id
    AND source.snapshot_operation_id = f.id
  RETURNING source.id
)
SELECT finalized.* FROM finalized;

-- name: QueueSavedSnapshotCleanup :one
-- Preserve and meter a committed artifact set when it cannot be admitted
-- (for example, storage quota was exceeded) and immediate VMD cleanup failed.
-- The deleting supervisor retries host cleanup, while releasing the source
-- capture claim immediately keeps the source usable.
WITH source_locked AS MATERIALIZED (
  SELECT source.id
  FROM snapshot intent
  JOIN sandbox source
    ON source.id = intent.sandbox_id AND source.team_id = intent.team_id
  WHERE intent.id = sqlc.arg(snapshot_id)
    AND intent.team_id = sqlc.arg(team_id)
    AND intent.kind = 'saved'
    AND intent.status = 'creating'
    AND intent.deleted_at IS NULL
    AND source.snapshot_operation_id = intent.id
  FOR UPDATE OF source
),
queued AS (
  UPDATE snapshot s
  SET status = 'deleting',
      path = sqlc.arg(path),
      mem_path = sqlc.arg(mem_path)::text,
      size_bytes = sqlc.arg(logical_size_bytes),
      manifest_path = sqlc.arg(manifest_path)::text,
      manifest_digest = sqlc.narg(manifest_digest),
      artifact_metadata = sqlc.arg(artifact_metadata),
      logical_size_bytes = sqlc.arg(logical_size_bytes),
      exclusive_size_bytes = sqlc.arg(exclusive_size_bytes),
      failure_reason = sqlc.arg(failure_reason),
      finalized_at = now(),
      updated_at = now()
  WHERE s.id = sqlc.arg(snapshot_id)
    AND s.team_id = sqlc.arg(team_id)
    AND s.kind = 'saved'
    AND s.status = 'creating'
    AND s.deleted_at IS NULL
    AND EXISTS (SELECT 1 FROM source_locked)
  RETURNING s.*
),
released AS (
  UPDATE sandbox source
  SET snapshot_operation_id = NULL,
      snapshot_operation_started_at = NULL,
      updated_at = now()
  FROM queued q
  WHERE source.id = q.sandbox_id
    AND source.team_id = q.team_id
    AND source.snapshot_operation_id = q.id
  RETURNING source.id
)
SELECT queued.* FROM queued;

-- name: FailSavedSnapshot :one
-- Terminalize a failed capture and release only the matching source claim; a
-- stale worker therefore cannot clear a newer operation. Lock the source
-- before the snapshot so failure, finalization, cleanup, and cancellation all
-- use the same lifecycle lock order.
WITH source_locked AS MATERIALIZED (
  SELECT source.id
  FROM snapshot intent
  JOIN sandbox source
    ON source.id = intent.sandbox_id AND source.team_id = intent.team_id
  WHERE intent.id = sqlc.arg(snapshot_id)
    AND intent.team_id = sqlc.arg(team_id)
    AND intent.kind = 'saved'
    AND intent.status = 'creating'
    AND intent.deleted_at IS NULL
  FOR UPDATE OF source
),
failed AS (
  UPDATE snapshot s
  SET status = 'failed',
      failure_reason = sqlc.arg(failure_reason),
      finalized_at = now(),
      updated_at = now()
  WHERE s.id = sqlc.arg(snapshot_id)
    AND s.team_id = sqlc.arg(team_id)
    AND s.kind = 'saved'
    AND s.status = 'creating'
    AND s.deleted_at IS NULL
    AND EXISTS (SELECT 1 FROM source_locked)
  RETURNING s.*
),
released AS (
  UPDATE sandbox source
  SET snapshot_operation_id = NULL,
      snapshot_operation_started_at = NULL,
      updated_at = now()
  FROM failed f
  WHERE source.id = f.sandbox_id
    AND source.team_id = f.team_id
    AND source.snapshot_operation_id = f.id
  RETURNING source.id
)
SELECT failed.* FROM failed;

-- name: FailSavedSnapshotAndSource :one
-- A running capture that cannot resume its source leaves both resources in a
-- terminal state. Lock and update the source first, clear only the matching
-- operation claim, then fail the creating intent and close both usage interval
-- types in the same statement. Zero rows means the capture no longer owns the
-- source or is no longer creating.
WITH source_locked AS MATERIALIZED (
  SELECT source.id, source.team_id
  FROM snapshot intent
  JOIN sandbox source
    ON source.id = intent.sandbox_id AND source.team_id = intent.team_id
  WHERE intent.id = sqlc.arg(snapshot_id)
    AND intent.team_id = sqlc.arg(team_id)
    AND intent.kind = 'saved'
    AND intent.status = 'creating'
    AND intent.deleted_at IS NULL
    AND source.snapshot_operation_id = intent.id
    AND source.destroyed_at IS NULL
  FOR UPDATE OF source
),
failed_source AS (
  UPDATE sandbox source
  SET status = 'failed',
      auto_delete_at = NULL,
      snapshot_operation_id = NULL,
      snapshot_operation_started_at = NULL,
      updated_at = now()
  FROM source_locked locked
  WHERE source.id = locked.id
    AND source.team_id = locked.team_id
    AND source.snapshot_operation_id = sqlc.arg(snapshot_id)
    AND source.destroyed_at IS NULL
  RETURNING source.id, source.team_id
),
revoked_source AS (
  INSERT INTO sandbox_revocation (sandbox_id, expires_at)
  SELECT source.id, sqlc.arg(revocation_expires_at)
  FROM failed_source source
  ON CONFLICT (sandbox_id) DO UPDATE
  SET expires_at = GREATEST(sandbox_revocation.expires_at, EXCLUDED.expires_at)
  RETURNING sandbox_id
),
failed_snapshot AS (
  UPDATE snapshot intent
  SET status = 'failed',
      failure_reason = sqlc.arg(failure_reason),
      finalized_at = now(),
      updated_at = now()
  WHERE intent.id = sqlc.arg(snapshot_id)
    AND intent.team_id = sqlc.arg(team_id)
    AND intent.kind = 'saved'
    AND intent.status = 'creating'
    AND intent.deleted_at IS NULL
    AND EXISTS (
      SELECT 1 FROM failed_source source
      WHERE source.id = intent.sandbox_id
        AND source.team_id = intent.team_id
    )
  RETURNING intent.*
),
closed_active AS (
  UPDATE sandbox_active_interval interval
  SET ended_at = GREATEST(now(), interval.started_at),
      end_reason = 'failed'
  FROM failed_source source
  WHERE interval.sandbox_id = source.id
    AND interval.team_id = source.team_id
    AND interval.ended_at IS NULL
  RETURNING interval.sandbox_id
),
closed_compute AS (
  UPDATE sandbox_compute_billing_interval interval
  SET ended_at = GREATEST(now(), interval.started_at),
      end_reason = 'failed'
  FROM failed_source source
  WHERE interval.sandbox_id = source.id
    AND interval.team_id = source.team_id
    AND interval.ended_at IS NULL
  RETURNING interval.sandbox_id
)
SELECT failed_snapshot.* FROM failed_snapshot;

-- name: FailSavedSnapshotSourceAfterRevocation :one
-- Fallback for a source-resume failure when the compound transition above did
-- not return. A separately persisted, unexpired revocation is a prerequisite.
-- The source may still hold this capture's claim or a concurrent cancellation
-- may already have cleared it; the timestamp guard rejects an intervening
-- source lifecycle change, and a newer capture claim is never overwritten.
-- Returning the source ID proves that the failed state, claim release, and
-- usage-interval closures committed before callers tear down the host VM.
WITH source_locked AS MATERIALIZED (
  SELECT source.id, source.team_id, intent.source_status,
         intent.updated_at AS intent_updated_at
  FROM snapshot intent
  JOIN sandbox source
    ON source.id = intent.sandbox_id AND source.team_id = intent.team_id
  JOIN sandbox_revocation revocation
    ON revocation.sandbox_id = source.id AND revocation.expires_at > now()
  WHERE intent.id = sqlc.arg(snapshot_id)
    AND intent.team_id = sqlc.arg(team_id)
    AND intent.kind = 'saved'
    AND source.destroyed_at IS NULL
    AND (source.status = 'failed' OR source.status = intent.source_status)
    AND (source.snapshot_operation_id IS NULL
         OR source.snapshot_operation_id = intent.id)
    AND (source.status = 'failed'
         OR source.snapshot_operation_id = intent.id
         OR source.updated_at <= intent.updated_at)
  FOR UPDATE OF source
),
failed_source AS (
  UPDATE sandbox source
  SET status = 'failed',
      auto_delete_at = NULL,
      snapshot_operation_id = NULL,
      snapshot_operation_started_at = NULL,
      updated_at = now()
  FROM source_locked locked
  WHERE source.id = locked.id
    AND source.team_id = locked.team_id
    AND source.destroyed_at IS NULL
    AND (source.status = 'failed' OR source.status = locked.source_status)
    AND (source.snapshot_operation_id IS NULL
         OR source.snapshot_operation_id = sqlc.arg(snapshot_id))
    AND (source.status = 'failed'
         OR source.snapshot_operation_id = sqlc.arg(snapshot_id)
         OR source.updated_at <= locked.intent_updated_at)
  RETURNING source.id, source.team_id
),
failed_snapshot AS (
  UPDATE snapshot intent
  SET status = 'failed',
      failure_reason = sqlc.arg(failure_reason),
      finalized_at = now(),
      updated_at = now()
  WHERE intent.id = sqlc.arg(snapshot_id)
    AND intent.team_id = sqlc.arg(team_id)
    AND intent.kind = 'saved'
    AND intent.status = 'creating'
    AND intent.deleted_at IS NULL
    AND EXISTS (
      SELECT 1 FROM failed_source source
      WHERE source.id = intent.sandbox_id
        AND source.team_id = intent.team_id
    )
  RETURNING intent.id
),
closed_active AS (
  UPDATE sandbox_active_interval interval
  SET ended_at = GREATEST(now(), interval.started_at),
      end_reason = 'failed'
  FROM failed_source source
  WHERE interval.sandbox_id = source.id
    AND interval.team_id = source.team_id
    AND interval.ended_at IS NULL
  RETURNING interval.sandbox_id
),
closed_compute AS (
  UPDATE sandbox_compute_billing_interval interval
  SET ended_at = GREATEST(now(), interval.started_at),
      end_reason = 'failed'
  FROM failed_source source
  WHERE interval.sandbox_id = source.id
    AND interval.team_id = source.team_id
    AND interval.ended_at IS NULL
  RETURNING interval.sandbox_id
)
SELECT source.id FROM failed_source source;

-- name: MarkSavedSnapshotUnavailable :one
UPDATE snapshot
SET status = 'unavailable',
    failure_reason = sqlc.arg(failure_reason),
    updated_at = now()
WHERE id = sqlc.arg(snapshot_id)
  AND team_id = sqlc.arg(team_id)
  AND kind = 'saved'
  AND status = 'ready'
  AND deleted_at IS NULL
RETURNING *;

-- name: GetSavedSnapshot :one
SELECT * FROM snapshot
WHERE id = sqlc.arg(snapshot_id)
  AND team_id = sqlc.arg(team_id)
  AND kind = 'saved'
  AND deleted_at IS NULL;

-- name: GetSavedSnapshotForDelete :one
-- Team-scoped tombstone-aware lookup for idempotent DELETE. Retaining the team
-- predicate prevents an already-deleted snapshot from becoming an existence
-- oracle across tenants.
SELECT * FROM snapshot
WHERE id = sqlc.arg(snapshot_id)
  AND team_id = sqlc.arg(team_id)
  AND kind = 'saved';

-- name: GetSavedSnapshotByID :one
-- Unscoped internal lookup for host reconciliation only.
SELECT * FROM snapshot
WHERE id = sqlc.arg(snapshot_id)
  AND kind = 'saved'
  AND deleted_at IS NULL;

-- name: LockSavedSnapshotForFork :one
-- Hold this lock in the transaction that restores/inserts a fork. It conflicts
-- with ClaimDeleteSavedSnapshotIfLeaf and makes status='ready' stable until the
-- new sandbox reference commits.
SELECT * FROM snapshot
WHERE id = sqlc.arg(snapshot_id)
  AND team_id = sqlc.arg(team_id)
  AND kind = 'saved'
  AND status = 'ready'
  AND deleted_at IS NULL
  AND feature_enabled('sandbox_snapshots_v1', team_id)
FOR KEY SHARE;

-- name: ListSavedSnapshotsByTeam :many
SELECT * FROM snapshot
WHERE team_id = sqlc.arg(team_id)
  AND kind = 'saved'
  AND deleted_at IS NULL
  AND (sqlc.narg(source_sandbox_id)::uuid IS NULL
       OR sandbox_id = sqlc.narg(source_sandbox_id))
  AND (sqlc.narg(status)::text IS NULL
       OR status::text = sqlc.narg(status)::text)
ORDER BY created_at DESC, id DESC
LIMIT sqlc.narg(row_limit)::bigint
OFFSET COALESCE(sqlc.narg(row_offset)::bigint, 0);

-- name: CountSavedSnapshotsByTeam :one
SELECT count(*)::bigint FROM snapshot
WHERE team_id = sqlc.arg(team_id)
  AND kind = 'saved'
  AND deleted_at IS NULL
  AND (sqlc.narg(source_sandbox_id)::uuid IS NULL
       OR sandbox_id = sqlc.narg(source_sandbox_id))
  AND (sqlc.narg(status)::text IS NULL
       OR status::text = sqlc.narg(status)::text);

-- name: ListSavedSnapshotsBySandbox :many
SELECT * FROM snapshot
WHERE sandbox_id = sqlc.arg(sandbox_id)
  AND team_id = sqlc.arg(team_id)
  AND kind = 'saved'
  AND deleted_at IS NULL
ORDER BY created_at DESC, id DESC;

-- name: CountSavedSnapshotsBySource :one
SELECT count(*)::bigint FROM snapshot
WHERE sandbox_id = sqlc.arg(sandbox_id)
  AND team_id = sqlc.arg(team_id)
  AND kind = 'saved'
  AND deleted_at IS NULL
  AND status <> 'failed';

-- name: GetSavedSnapshotDependencyCounts :one
SELECT
  (SELECT count(*)::bigint
   FROM sandbox child
   WHERE child.source_snapshot_id = s.id
     AND child.team_id = s.team_id) AS child_sandbox_count,
  (SELECT count(*)::bigint
   FROM snapshot child
   WHERE child.parent_snapshot_id = s.id
     AND child.team_id = s.team_id
     AND child.kind = 'saved'
     AND child.deleted_at IS NULL) AS child_snapshot_count
FROM snapshot s
WHERE s.id = sqlc.arg(snapshot_id)
  AND s.team_id = sqlc.arg(team_id)
  AND s.kind = 'saved'
  AND s.deleted_at IS NULL;

-- name: ListSavedSnapshotChildSandboxIDs :many
SELECT id FROM sandbox
WHERE source_snapshot_id = sqlc.arg(snapshot_id)
  AND team_id = sqlc.arg(team_id)
ORDER BY created_at ASC, id ASC;

-- name: ListSavedSnapshotChildSnapshotIDs :many
SELECT id FROM snapshot
WHERE parent_snapshot_id = sqlc.arg(snapshot_id)
  AND team_id = sqlc.arg(team_id)
  AND kind = 'saved'
  AND deleted_at IS NULL
ORDER BY created_at ASC, id ASC;

-- name: ClaimDeleteSavedSnapshotIfLeaf :one
-- Host admission is locked before the source/snapshot rows. A drain that wins
-- first rejects a new delete before it can mutate host-local artifacts; a
-- delete that wins first makes drain wait and then exposes status='deleting'
-- to the drain convergence check.
-- Child creation holds FOR KEY SHARE on this row. This FOR UPDATE claim waits
-- for those inserts, then re-checks dependencies before making the snapshot
-- unavailable to new forks. The source is locked first to match capture
-- finalize/failure lock ordering. Cancelling a creating capture also releases
-- only its matching source operation claim in the same statement. Zero rows
-- means not found, non-leaf, or already deleting.
WITH host_admitted AS MATERIALIZED (
  SELECT h.id
  FROM snapshot target
  JOIN host h ON h.id = target.host_id
  WHERE target.id = sqlc.arg(snapshot_id)
    AND target.team_id = sqlc.arg(team_id)
    AND target.kind = 'saved'
    AND target.deleted_at IS NULL
    AND h.status = 'active'
  FOR SHARE OF h
),
source_locked AS MATERIALIZED (
  SELECT source.id
  FROM snapshot target
  JOIN sandbox source
    ON source.id = target.sandbox_id AND source.team_id = target.team_id
  JOIN host_admitted admitted ON admitted.id = target.host_id
  WHERE target.id = sqlc.arg(snapshot_id)
    AND target.team_id = sqlc.arg(team_id)
    AND target.kind = 'saved'
    AND target.deleted_at IS NULL
  FOR UPDATE OF source
),
locked AS MATERIALIZED (
  SELECT target.id
  FROM snapshot target
  JOIN source_locked source ON source.id = target.sandbox_id
  WHERE target.id = sqlc.arg(snapshot_id)
    AND target.team_id = sqlc.arg(team_id)
    AND target.kind = 'saved'
    AND target.deleted_at IS NULL
  FOR UPDATE OF target
),
claimable AS MATERIALIZED (
  SELECT target.id, target.sandbox_id, target.team_id
  FROM snapshot target
  JOIN locked ON locked.id = target.id
  WHERE target.status IN ('creating', 'ready', 'unavailable', 'failed')
    AND NOT EXISTS (
      SELECT 1 FROM sandbox child
      WHERE child.source_snapshot_id = target.id
        AND child.team_id = target.team_id
    )
    AND NOT EXISTS (
      SELECT 1 FROM snapshot child
      WHERE child.parent_snapshot_id = target.id
        AND child.team_id = target.team_id
        AND child.kind = 'saved'
        AND child.deleted_at IS NULL
    )
),
released AS (
  UPDATE sandbox source
  SET snapshot_operation_id = NULL,
      snapshot_operation_started_at = NULL,
      updated_at = now()
  FROM claimable c
  WHERE source.id = c.sandbox_id
    AND source.team_id = c.team_id
    AND source.snapshot_operation_id = c.id
  RETURNING source.id
)
UPDATE snapshot s
SET status = 'deleting', updated_at = now()
WHERE s.id IN (SELECT id FROM claimable)
RETURNING s.*;

-- name: FinalizeSavedSnapshotDelete :one
-- Logical deletion is the storage-usage end point. Artifact cleanup may happen
-- before this call or be retried by the reconciler while status is deleting.
UPDATE snapshot
SET deleted_at = now(), updated_at = now()
WHERE id = sqlc.arg(snapshot_id)
  AND team_id = sqlc.arg(team_id)
  AND kind = 'saved'
  AND status = 'deleting'
  AND deleted_at IS NULL
RETURNING *;

-- name: ListStaleCreatingSavedSnapshots :many
SELECT s.* FROM snapshot s
WHERE s.kind = 'saved'
  AND s.status = 'creating'
  AND s.deleted_at IS NULL
  AND s.updated_at < sqlc.arg(stale_before)
ORDER BY s.updated_at ASC
LIMIT sqlc.arg(row_limit);

-- name: ListSavedSnapshotsByHost :many
-- Authoritative host-local manifest/artifact pin set for VMD reconciliation.
-- Creating and deleting rows are included because their files may need commit
-- recovery or retryable cleanup even though they cannot launch forks.
SELECT * FROM snapshot
WHERE host_id = sqlc.arg(host_id)
  AND kind = 'saved'
  AND deleted_at IS NULL
ORDER BY created_at ASC, id ASC;

-- name: ListDeletingSavedSnapshots :many
-- Retry queue for logical deletes whose host artifact cleanup did not finish.
SELECT * FROM snapshot
WHERE kind = 'saved'
  AND status = 'deleting'
  AND deleted_at IS NULL
  AND updated_at < sqlc.arg(stale_before)
ORDER BY updated_at ASC, id ASC
LIMIT sqlc.arg(row_limit);

-- name: GetSavedSnapshotQuotaUsage :one
SELECT
  t.max_snapshots,
  t.max_snapshots_per_sandbox,
  t.snapshot_storage_quota_bytes,
  t.snapshot_storage_bytes,
  (SELECT count(*)::bigint FROM snapshot s
   WHERE s.team_id = t.id
     AND s.kind = 'saved'
     AND s.deleted_at IS NULL
     AND s.status <> 'failed') AS snapshot_count
FROM team t
WHERE t.id = sqlc.arg(team_id);

-- name: GetSavedSnapshotStorageUsage :one
-- Reconciliation source for shadow metering. This deliberately does not feed
-- team_billing_usage or invoice export.
SELECT COALESCE(sum(
  retained_exclusive_size_bytes + current_exclusive_size_bytes
), 0)::bigint
FROM snapshot_storage_layer
WHERE team_id = sqlc.arg(team_id)
  AND ended_at IS NULL;
