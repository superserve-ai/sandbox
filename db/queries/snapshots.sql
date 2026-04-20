-- name: CreateSnapshot :one
INSERT INTO snapshot (sandbox_id, team_id, path, mem_path, size_bytes, saved, name, trigger)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
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

-- name: MarkSnapshotSaved :exec
UPDATE snapshot
SET saved = true
WHERE id = $1;

-- name: DeleteSnapshot :exec
DELETE FROM snapshot
WHERE id = $1;
