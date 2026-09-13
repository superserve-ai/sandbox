-- name: InsertQMTenantEvent :one
-- Locks the tenant row for the rest of the transaction. Retirement
-- (SoftDeleteQMTenant) updates that same row, so the two serialize: an
-- insert that starts first commits before the tenant can become deleted, and
-- one that arrives during retirement waits, re-reads the row, and inserts
-- nothing. The row-level policy alone cannot give that guarantee, since it
-- evaluates the tenant's status on a snapshot. The lock also makes the seq
-- assignment safe against a concurrent insert for the same tenant. No row
-- means the tenant is retired.
INSERT INTO qm.tenant_events (tenant_id, step, status, message, detail, seq)
SELECT t.id, sqlc.arg(step)::text, sqlc.arg(status)::text, sqlc.narg(message)::text, sqlc.narg(detail)::jsonb,
       (SELECT coalesce(max(seq), 0) + 1 FROM qm.tenant_events WHERE tenant_id = t.id)
FROM qm.tenants t
WHERE t.id = sqlc.arg(tenant_id) AND t.status <> 'deleted'
FOR NO KEY UPDATE OF t
RETURNING *;

-- name: ListQMTenantEvents :many
SELECT * FROM qm.tenant_events
WHERE tenant_id = $1
ORDER BY seq ASC;
