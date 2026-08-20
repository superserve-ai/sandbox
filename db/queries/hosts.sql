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
                  capacity_memory_mib, capacity_vcpus, last_heartbeat_at,
                  identity_bound)
VALUES ($1, $2, $3, $4, 'provisioning', $5, $6, now(), true)
RETURNING *;

-- name: GetHostForUpdate :one
-- Row-locked read for the heartbeat's identity check, so the guard and the
-- heartbeat update see the same row version inside one transaction.
SELECT * FROM host WHERE id = $1 FOR UPDATE;

-- name: UpdateHostAddresses :exec
-- Re-provision path: the identity is reclaiming its row from a new address
-- after the old holder went silent. Guarded by the handler's staleness check.
-- The reclaim DEMOTES the row to provisioning in the same statement: an
-- address change is a re-registration, and every holder of the vmd-internal
-- token can trigger one after two minutes of silence — it must never leave
-- (or make) a host schedulable without the operator credential re-approving.
UPDATE host
SET vmd_addr = $2, proxy_addr = $3, region = $4,
    capacity_memory_mib = $5, capacity_vcpus = $6,
    status = 'provisioning', identity_bound = true, updated_at = now()
WHERE id = $1;

-- name: BindHostIdentity :exec
-- Opt-in: an existing (legacy) row whose holder sent a complete
-- self-description at its current address enters identity-bound mode.
UPDATE host
SET identity_bound = true, updated_at = now()
WHERE id = $1;

-- name: UpdateHostStatus :one
-- Activation requires a live heartbeat: a provisioning host that died
-- before the operator activated it must not become schedulable — the
-- unhealthy detector only watches active rows, so it would sit exposed to
-- placement until the detector's next pass. Non-active targets carry no
-- freshness requirement; draining a dead host is legitimate.
UPDATE host
SET status = $2, updated_at = now()
WHERE id = $1
  AND ($2 <> 'active'
       OR (last_heartbeat_at IS NOT NULL
           AND last_heartbeat_at > sqlc.arg(active_heartbeat_after)))
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

-- name: SyncHostCapabilities :exec
-- Refresh the advertised set in place and prune only capabilities omitted by
-- this heartbeat. Empty capabilities intentionally remove the entire set.
WITH current_host AS (
    SELECT id, last_heartbeat_at
    FROM host
    WHERE id = sqlc.arg(host_id) AND last_heartbeat_at IS NOT NULL
), advertised AS (
    SELECT DISTINCT unnest(COALESCE(sqlc.arg(capabilities)::text[], ARRAY[]::text[])) AS capability
), upserted AS (
    INSERT INTO host_capability (host_id, capability, heartbeat_at)
    SELECT h.id, a.capability, h.last_heartbeat_at
    FROM current_host h
    CROSS JOIN advertised a
    ON CONFLICT (host_id, capability)
    DO UPDATE SET heartbeat_at = EXCLUDED.heartbeat_at
    RETURNING capability
)
DELETE FROM host_capability hc
WHERE hc.host_id = sqlc.arg(host_id)
  AND NOT (hc.capability = ANY(COALESCE(sqlc.arg(capabilities)::text[], ARRAY[]::text[])));

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
-- sandbox counts for drain progress. transitional counts pausing/resuming
-- sandboxes whose lifecycle RPC is still using the host — a host is not
-- drained while any exist, even when running and paused both read zero.
SELECT h.id, h.vmd_addr, h.proxy_addr, h.region, h.status,
       h.capacity_memory_mib, h.capacity_vcpus,
       h.last_heartbeat_at, h.created_at, h.updated_at,
       COALESCE(COUNT(s.id) FILTER (WHERE s.status IN ('active', 'starting')
                                      AND s.destroyed_at IS NULL), 0)::int AS running_count,
       COALESCE(COUNT(s.id) FILTER (WHERE s.status IN ('pausing', 'resuming')
                                      AND s.destroyed_at IS NULL), 0)::int AS transitional_count,
       COALESCE(COUNT(s.id) FILTER (WHERE s.status = 'paused'
                                      AND s.destroyed_at IS NULL), 0)::int AS paused_count,
       -- Scalar subquery, not a second LEFT JOIN: joining two child tables
       -- would cross-multiply the per-host rows and corrupt the counts.
       COALESCE((SELECT COUNT(*) FROM template_build tb
                 WHERE tb.vmd_host_id = h.id
                   AND tb.status IN ('building', 'snapshotting')), 0)::int AS building_count,
       -- Paused sandboxes whose CURRENT pause has no durable backup: the
       -- ones whose only up-to-date copy lives on this host's local disk.
       -- Retiring the machine destroys them outright; even
       -- paused-with-coverage stays pinned here until cross-host restore
       -- exists, but unbacked is the irrecoverable class an operator must
       -- never retire past.
       --
       -- "Covers the current pause" reads the PERSISTED identity link the
       -- report handler writes (MarkSandboxBackupCovered): a generation
       -- counts only if its verified manifest matched the head snapshot's
       -- recorded digests at report time, under the same row lock the
       -- pause finalize takes — and the link names both the snapshot row
       -- and its per-pause generation counter, so a re-pause (which
       -- advances the counter even when the legacy finalize reuses the
       -- row id) unlinks every earlier generation. Nothing here infers
       -- identity from timestamps or manifest containment at read time:
       -- both misidentify a previous pause's generation under delayed
       -- outbox delivery. Errs conservative: a generation recorded before
       -- this linkage existed (or whose report predates the current
       -- pause) reads as unbacked until its next redelivery re-verifies
       -- it against the current manifest.
       COALESCE((SELECT COUNT(*) FROM sandbox s2
                 WHERE s2.host_id = h.id
                   AND s2.status = 'paused'
                   AND s2.destroyed_at IS NULL
                   AND NOT EXISTS (
                     SELECT 1
                     FROM backup_generation bg
                     JOIN snapshot snap ON snap.id = s2.snapshot_id
                     WHERE bg.sandbox_id = s2.id
                       AND bg.covered_snapshot_id = snap.id
                       AND bg.covered_snapshot_generation = snap.generation)), 0)::int AS paused_unbacked_count
FROM host h
LEFT JOIN sandbox s ON s.host_id = h.id
-- The optional id filter exists for drain polling: `hostctl drain --wait`
-- re-reads one host every few seconds, and the per-host counts (the
-- backup-coverage probe especially) must not be recomputed for the whole
-- fleet on every poll.
WHERE sqlc.narg(id)::text IS NULL OR h.id = sqlc.narg(id)
GROUP BY h.id
ORDER BY h.created_at ASC;
