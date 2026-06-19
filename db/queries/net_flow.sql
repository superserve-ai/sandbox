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
-- Connection rows for the unified network log, optionally filtered by verdict.
-- Keyset-paginated by the (ts, kind, id) cursor; 'connection' is this source's
-- kind. The handler merges these with proxy_audit under the same total order.
SELECT * FROM net_flow
WHERE sandbox_id = sqlc.arg('sandbox_id')
  AND (sqlc.narg('since')::timestamptz IS NULL OR ts >= sqlc.narg('since')::timestamptz)
  AND (sqlc.narg('verdict')::text IS NULL OR verdict = sqlc.narg('verdict')::text)
  AND (sqlc.narg('cursor_ts')::timestamptz IS NULL
       OR (ts, 'connection', id) < (sqlc.narg('cursor_ts')::timestamptz, sqlc.narg('cursor_kind')::text, sqlc.narg('cursor_id')::bigint))
ORDER BY ts DESC, id DESC
LIMIT sqlc.arg('row_limit');
