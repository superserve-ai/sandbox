-- name: InsertNetFlow :exec
INSERT INTO net_flow (
    team_id, sandbox_id, protocol, host, dst_ip, dst_port,
    verdict, match_rule, bytes_sent, bytes_recv, duration_ms
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);

-- name: GetSandboxTeamID :one
-- Resolves team_id from sandbox_id for the flow writer (the egress proxy has
-- no team context). Cached per sandbox by the caller.
SELECT team_id FROM sandbox WHERE id = $1;

-- name: ListNetFlowEvents :many
-- Connection rows for the unified network log. Filtered by an optional time
-- window (before/since) and verdict; before doubles as the pagination cursor.
-- The merge with proxy_audit happens in the handler; the cursor is a timestamp
-- because the two tables have independent id sequences.
SELECT * FROM net_flow
WHERE sandbox_id = sqlc.arg('sandbox_id')
  AND (sqlc.narg('before')::timestamptz IS NULL OR ts < sqlc.narg('before')::timestamptz)
  AND (sqlc.narg('since')::timestamptz IS NULL OR ts >= sqlc.narg('since')::timestamptz)
  AND (sqlc.narg('verdict')::text IS NULL OR verdict = sqlc.narg('verdict')::text)
ORDER BY ts DESC
LIMIT sqlc.arg('row_limit');
