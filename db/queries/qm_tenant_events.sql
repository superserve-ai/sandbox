-- name: InsertQMTenantEvent :one
-- Bumps the tenant's event counter in the same statement that writes the
-- event, which does three things at once. It locks the tenant row for the
-- rest of the transaction, so retirement (SoftDeleteQMTenant) and this
-- insert serialize: an insert that starts first commits before the tenant
-- can become deleted, and one that arrives during retirement waits, re-reads
-- the row, and inserts nothing. The row-level policy alone cannot give that
-- guarantee, since it evaluates the tenant's status on a snapshot. And it
-- assigns seq from a value the UPDATE re-reads after any lock wait, unlike
-- max(seq) over qm.tenant_events, which would be read on the snapshot the
-- statement took before waiting and so collide with the insert it waited
-- for. No row means the tenant is retired.
WITH live AS (
    UPDATE qm.tenants t
    SET event_seq = t.event_seq + 1
    WHERE t.id = sqlc.arg(tenant_id) AND t.status <> 'deleted'
    RETURNING t.id, t.event_seq
)
INSERT INTO qm.tenant_events (tenant_id, step, status, message, detail, seq)
SELECT live.id, sqlc.arg(step)::text, sqlc.arg(status)::text, sqlc.narg(message)::text, sqlc.narg(detail)::jsonb, live.event_seq
FROM live
RETURNING *;

-- name: ListQMTenantEvents :many
SELECT * FROM qm.tenant_events
WHERE tenant_id = $1
ORDER BY seq ASC;
