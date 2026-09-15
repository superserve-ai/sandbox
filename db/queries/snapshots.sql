-- name: CreateSnapshot :one
INSERT INTO snapshot (sandbox_id, team_id, path, mem_path, size_bytes, trigger)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetSnapshot :one
-- Team-scoped snapshot lookup for user-facing handlers. The join on
-- team_id enforces tenant isolation at the SQL layer so callers cannot
-- accidentally leak another team's snapshot metadata by forgetting the
-- in-Go team check.
SELECT * FROM snapshot
WHERE id = $1 AND team_id = $2;

-- name: GetSnapshotByID :one
-- Unscoped snapshot lookup for internal (host-scoped) code paths such as
-- the VMD reconciler. DO NOT call from user-facing handlers.
SELECT * FROM snapshot
WHERE id = $1;

-- name: ListSnapshotsBySandbox :many
SELECT * FROM snapshot
WHERE sandbox_id = $1
ORDER BY created_at DESC;

-- name: ListSnapshotsByTeam :many
SELECT * FROM snapshot
WHERE team_id = $1
ORDER BY created_at DESC;

-- name: DeleteSnapshot :exec
-- Invariant: only delete snapshots of destroyed sandboxes. fk_sandbox_snapshot
-- is ON DELETE SET NULL, so deleting a live/paused sandbox's snapshot silently
-- nulls its restore pointer (unrestorable) instead of erroring.
DELETE FROM snapshot
WHERE id = $1;

-- name: DeleteSnapshotsOfDestroyedSandboxes :execrows
-- Backstop for destroy teardown that never ran (crash/shutdown before
-- cleanupSandboxSnapshots). Driven from snapshot (joined to sandbox by PK) so
-- it scans only un-cleaned rows, not every accumulating soft-deleted sandbox.
-- Files fall to the vm reconciler's disk scan.
DELETE FROM snapshot s
USING sandbox sb
WHERE s.sandbox_id = sb.id
  AND sb.destroyed_at IS NOT NULL
  AND sb.destroyed_at < now() - interval '1 hour';
