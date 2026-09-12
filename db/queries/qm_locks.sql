-- name: TryLockQMTenant :one
-- Non-blocking per-tenant lock held for a whole provisioner run; a second
-- run for the same tenant sees false and exits instead of queueing.
SELECT pg_try_advisory_xact_lock(hashtext('qm-tenant:' || sqlc.arg(tenant_id)::text)::bigint)::boolean AS locked;
