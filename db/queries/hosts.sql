-- name: GetHost :one
SELECT * FROM host WHERE id = $1;

-- name: ListActiveHosts :many
SELECT * FROM host
WHERE status = 'active'
ORDER BY created_at ASC;

-- name: ListHosts :many
SELECT * FROM host
ORDER BY created_at ASC;

-- name: CreateHost :one
INSERT INTO host (id, vmd_addr, proxy_addr, region, capacity_memory_mib, capacity_vcpus)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: UpdateHostStatus :exec
UPDATE host
SET status = $2, updated_at = now()
WHERE id = $1;

-- name: UpdateHostHeartbeat :one
-- Returns the host row so the caller can verify the host exists. Also
-- re-activates unhealthy hosts that resume heartbeating — this is the
-- automatic recovery path after a transient network outage.
UPDATE host
SET last_heartbeat_at = now(),
    status = CASE WHEN status = 'unhealthy' THEN 'active' ELSE status END,
    updated_at = now()
WHERE id = $1
RETURNING *;

-- name: MarkHostUnhealthy :exec
UPDATE host
SET status = 'unhealthy', updated_at = now()
WHERE id = $1 AND status = 'active';

-- name: ListStaleHosts :many
-- Returns active hosts whose last heartbeat is older than the given
-- threshold. Used by the unhealthy-host detector.
SELECT * FROM host
WHERE status = 'active'
  AND last_heartbeat_at IS NOT NULL
  AND last_heartbeat_at < $1
ORDER BY last_heartbeat_at ASC;

-- name: ListActiveHostsByLoad :many
-- Returns active hosts sorted by current sandbox count (ascending).
-- The scheduler picks the first row (least loaded host). One query
-- replaces N per-host lookups.
SELECT h.id, h.vmd_addr, h.proxy_addr, h.region, h.status,
       h.capacity_memory_mib, h.capacity_vcpus,
       h.last_heartbeat_at, h.created_at, h.updated_at,
       COALESCE(COUNT(s.id), 0)::int AS active_sandbox_count
FROM host h
LEFT JOIN sandbox s ON s.host_id = h.id
  AND s.status IN ('active', 'starting')
  AND s.destroyed_at IS NULL
WHERE h.status = 'active'
GROUP BY h.id
ORDER BY COUNT(s.id) ASC;
