-- name: CreateSnapshot :one
INSERT INTO snapshot (sandbox_id, team_id, path, size_bytes, saved, name, trigger)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: GetSnapshot :one
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
