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

-- name: RegisterHost :one
-- Self-registration from a first heartbeat. Starts in 'provisioning' so the
-- scheduler never sees the host until an operator activates it. Stamps
-- last_heartbeat_at because capability attestation keys on it: without a
-- heartbeat time, InsertHostCapability is a silent no-op.
INSERT INTO host (id, vmd_addr, proxy_addr, region, status,
                  capacity_memory_mib, capacity_vcpus, last_heartbeat_at)
VALUES ($1, $2, $3, $4, 'provisioning', $5, $6, now())
RETURNING *;

-- name: GetHostForUpdate :one
-- Row-locked read for the heartbeat's identity check, so the guard and the
-- heartbeat update see the same row version inside one transaction.
SELECT * FROM host WHERE id = $1 FOR UPDATE;

-- name: UpdateHostAddresses :exec
-- Re-provision path: the identity is reclaiming its row from a new address
-- after the old holder went silent. Guarded by the handler's staleness check.
UPDATE host
SET vmd_addr = $2, proxy_addr = $3, region = $4,
    capacity_memory_mib = $5, capacity_vcpus = $6, updated_at = now()
WHERE id = $1;

-- name: UpdateHostStatus :one
UPDATE host
SET status = $2, updated_at = now()
WHERE id = $1
RETURNING *;

-- name: UpdateHostHeartbeat :one
-- Returns the host row so the caller can verify the host exists. Also
-- re-activates unhealthy hosts that resume heartbeating — this is the
-- automatic recovery path after a transient network outage. prev_status lets
-- the caller detect that transition and invalidate the scheduler's host cache
-- so recovered capacity is usable immediately instead of after the cache TTL.
-- The pre-image is read FOR UPDATE so it reflects the row version this
-- statement actually modifies; a plain snapshot read racing a concurrent
-- status write could report the transition as active→active and hide it.
WITH prev AS (
    SELECT h.id, h.status FROM host h WHERE h.id = $1 FOR UPDATE
)
UPDATE host
SET last_heartbeat_at = now(),
    status = CASE WHEN host.status = 'unhealthy' THEN 'active' ELSE host.status END,
    updated_at = now()
FROM prev
WHERE host.id = prev.id
RETURNING host.*, prev.status AS prev_status;

-- name: DeleteHostCapabilities :exec
DELETE FROM host_capability WHERE host_id = $1;

-- name: InsertHostCapability :exec
INSERT INTO host_capability (host_id, capability, heartbeat_at)
SELECT id, sqlc.arg(capability), last_heartbeat_at
FROM host
WHERE id = sqlc.arg(host_id) AND last_heartbeat_at IS NOT NULL
ON CONFLICT (host_id, capability)
DO UPDATE SET heartbeat_at = EXCLUDED.heartbeat_at;

-- name: HostHasCapabilities :one
-- Lock the one active host row whose heartbeat anchors this capability set.
-- Callers that run this in a mutation transaction keep the host stable until
-- VMD delivery and commit, while the relational division below proves that
-- every requested capability belongs to that exact heartbeat.
WITH target_host AS MATERIALIZED (
  SELECT id, last_heartbeat_at
  FROM host
  WHERE id = sqlc.arg('host_id')
    AND status = 'active'
    AND last_heartbeat_at IS NOT NULL
  FOR SHARE
)
SELECT EXISTS (
  SELECT 1
  FROM target_host h
  WHERE NOT EXISTS (
    SELECT 1
    FROM unnest(sqlc.arg('required_capabilities')::text[]) AS required(capability)
    WHERE NOT EXISTS (
      SELECT 1
      FROM host_capability hc
      WHERE hc.host_id = h.id
        AND hc.capability = required.capability
        AND hc.heartbeat_at = h.last_heartbeat_at
    )
  )
);

-- name: HostHasCapabilitiesUnlocked :one
-- HostHasCapabilities without the row lock, for standalone pre-flight reads
-- outside a mutation transaction: omitting the lock keeps concurrent checks
-- from serializing behind the host's heartbeat writer. Transactional callers
-- that must pin the host across a commit use HostHasCapabilities.
WITH target_host AS MATERIALIZED (
  SELECT id, last_heartbeat_at
  FROM host
  WHERE id = sqlc.arg('host_id')
    AND status = 'active'
    AND last_heartbeat_at IS NOT NULL
)
SELECT EXISTS (
  SELECT 1
  FROM target_host h
  WHERE NOT EXISTS (
    SELECT 1
    FROM unnest(sqlc.arg('required_capabilities')::text[]) AS required(capability)
    WHERE NOT EXISTS (
      SELECT 1
      FROM host_capability hc
      WHERE hc.host_id = h.id
        AND hc.capability = required.capability
        AND hc.heartbeat_at = h.last_heartbeat_at
    )
  )
);

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
  AND NOT EXISTS (
    SELECT 1
    FROM unnest(sqlc.arg('required_capabilities')::text[]) AS required(capability)
    WHERE NOT EXISTS (
      SELECT 1 FROM host_capability hc
      WHERE hc.host_id = h.id
        AND hc.capability = required.capability
        AND hc.heartbeat_at = h.last_heartbeat_at
    )
  )
GROUP BY h.id
ORDER BY COUNT(s.id) ASC;

-- name: ListHostsAdmin :many
-- Operator view (hostctl): every host regardless of status, with live
-- sandbox counts. Paused count is here for drain progress visibility.
SELECT h.id, h.vmd_addr, h.proxy_addr, h.region, h.status,
       h.capacity_memory_mib, h.capacity_vcpus,
       h.last_heartbeat_at, h.created_at, h.updated_at,
       COALESCE(COUNT(s.id) FILTER (WHERE s.status IN ('active', 'starting')
                                      AND s.destroyed_at IS NULL), 0)::int AS running_count,
       COALESCE(COUNT(s.id) FILTER (WHERE s.status = 'paused'
                                      AND s.destroyed_at IS NULL), 0)::int AS paused_count
FROM host h
LEFT JOIN sandbox s ON s.host_id = h.id
GROUP BY h.id
ORDER BY h.created_at ASC;
