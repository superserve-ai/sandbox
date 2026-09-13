-- name: TryLockQMTenant :one
-- Non-blocking per-tenant lock held for a whole provisioner run; a second
-- run for the same tenant sees false and exits instead of queueing.
--
-- The key is the first 64 bits of an md5 over the namespaced tenant id, not
-- hashtext: hashtext is 32-bit, and two unrelated tenants sharing a key
-- would make one run exit as though the other were its own, leaving that
-- tenant in flight until the stale reclaim.
SELECT pg_try_advisory_xact_lock(
    ('x' || substr(md5('qm-tenant:' || sqlc.arg(tenant_id)::text), 1, 16))::bit(64)::bigint
)::boolean AS locked;
