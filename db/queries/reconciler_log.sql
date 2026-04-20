-- name: InsertReconcilerLog :exec
INSERT INTO reconciler_log (host_id, sandbox_id, action, reason, drift_kind)
VALUES ($1, $2, $3, $4, $5);

-- name: ListReconcilerLogByHost :many
SELECT * FROM reconciler_log
WHERE host_id = $1
ORDER BY created_at DESC
LIMIT $2;
