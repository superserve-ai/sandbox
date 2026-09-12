-- name: InsertQMTenantEvent :one
INSERT INTO qm.tenant_events (tenant_id, step, status, message, detail)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: ListQMTenantEvents :many
SELECT * FROM qm.tenant_events
WHERE tenant_id = $1
ORDER BY at ASC, id ASC;
