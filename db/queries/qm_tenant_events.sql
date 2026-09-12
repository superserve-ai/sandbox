-- name: InsertQMTenantEvent :one
INSERT INTO qm.tenant_events (tenant_id, step, status, message, detail, seq)
VALUES ($1, $2, $3, $4, $5,
        (SELECT coalesce(max(seq), 0) + 1 FROM qm.tenant_events WHERE tenant_id = $1))
RETURNING *;

-- name: ListQMTenantEvents :many
SELECT * FROM qm.tenant_events
WHERE tenant_id = $1
ORDER BY seq ASC;
