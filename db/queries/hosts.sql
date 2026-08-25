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
                       AND bg.covered_snapshot_generation = snap.generation)), 0)::int AS paused_unbacked_count,
       -- Live pressure, when the host publishes it (NULL otherwise): the
       -- vmd-reported allocation view, alongside the DB-derived counts
       -- above. hp is 1:1 by primary key, so it cannot multiply the
       -- sandbox join's count rows.
       -- Unmaterialized capacity reservations within their lease: creates
       -- admitted onto this host whose VM does not exist yet, so they
       -- appear in NO other count. Drain tooling must treat them as busy
       -- work — a host can read zero sandboxes during the
       -- reservation-to-dispatch gap while a VM is about to launch.
       -- (Materialized rows are deliberately excluded: their sandbox row
       -- already exists and is counted above; they only await hygiene.)
       COALESCE((SELECT COUNT(*) FROM host_reservation hr
                 WHERE hr.host_id = h.id
                   AND hr.materialized_at IS NULL
                   AND hr.created_at > now() - make_interval(secs => sqlc.arg('reservation_lease_secs')::int)), 0)::int AS reserved_count,
       hp.allocated_memory_mib AS pressure_allocated_memory_mib,
       hp.allocated_vcpus AS pressure_allocated_vcpus,
       hp.running_sandboxes AS pressure_running_sandboxes,
       hp.provisioning_sandboxes AS pressure_provisioning_sandboxes,
       hp.used_net_slots AS pressure_used_net_slots,
       hp.warm_net_slots AS pressure_warm_net_slots,
       -- Non-zero means the allocation columns above are a known
       -- undercount, so an operator can tell an idle host from one that
       -- cannot yet describe itself.
       hp.unknown_allocation_vms AS pressure_unknown_allocation_vms,
       hp.reported_at AS pressure_reported_at
FROM host h
LEFT JOIN sandbox s ON s.host_id = h.id
LEFT JOIN host_pressure hp ON hp.host_id = h.id
-- The optional id filter exists for drain polling: `hostctl drain --wait`
-- re-reads one host every few seconds, and the per-host counts (the
-- backup-coverage probe especially) must not be recomputed for the whole
-- fleet on every poll.
WHERE sqlc.narg(id)::text IS NULL OR h.id = sqlc.narg(id)
GROUP BY h.id, hp.host_id
ORDER BY h.created_at ASC;

-- name: GetHostCapabilityDiagnostics :many
-- Snapshot the host heartbeat generation and every capability attestation for
-- best-effort diagnostics when capability enforcement rejects a request.
WITH host_snapshot AS (
  SELECT h.id,
         h.status,
         h.last_heartbeat_at,
         (
           h.status = 'active'
           AND h.last_heartbeat_at IS NOT NULL
           AND NOT EXISTS (
             SELECT 1
             FROM unnest(sqlc.arg('required_capabilities')::text[]) AS required(capability)
             WHERE NOT EXISTS (
               SELECT 1
               FROM host_capability required_hc
               WHERE required_hc.host_id = h.id
                 AND required_hc.capability = required.capability
                 AND required_hc.heartbeat_at = h.last_heartbeat_at
             )
           )
         ) AS capabilities_match
  FROM host h
  WHERE h.id = sqlc.arg('host_id')
)
SELECT hs.last_heartbeat_at,
       hs.status,
       hs.capabilities_match,
       hc.capability,
       hc.heartbeat_at
FROM host_snapshot hs
LEFT JOIN host_capability hc ON hc.host_id = hs.id
ORDER BY hc.capability ASC;

-- name: UpsertHostPressure :execrows
-- Records a host's live pressure report, identity-fenced: the write
-- lands only while the report's vmd_addr matches the host row, so a
-- daemon whose identity was reclaimed cannot overwrite the new
-- holder's numbers (mirrors the heartbeat's reclaim semantics). 0 rows
-- = unknown host or address mismatch; the handler disambiguates.
-- Last-write-wins wholesale, reported_at from the DATABASE clock: this
-- pair is the reconciliation contract (see the host_pressure table
-- comment).
INSERT INTO host_pressure (
    host_id, running_sandboxes, provisioning_sandboxes, paused_sandboxes,
    allocated_memory_mib, allocated_vcpus,
    used_net_slots, provisioning_net_slots, warm_net_slots,
    net_slot_ceiling, max_network_slots, max_sandboxes, unknown_allocation_vms,
    reported_at
)
SELECT h.id, @running_sandboxes, @provisioning_sandboxes, @paused_sandboxes,
       @allocated_memory_mib, @allocated_vcpus,
       @used_net_slots, @provisioning_net_slots, @warm_net_slots,
       @net_slot_ceiling, @max_network_slots, @max_sandboxes, @unknown_allocation_vms,
       now()
FROM host h
WHERE h.id = @host_id AND h.vmd_addr = @vmd_addr
-- FOR SHARE serializes the address check against an identity reclaim
-- (which takes the row FOR UPDATE): without it this statement could
-- evaluate the old address from its snapshot and insert stale pressure
-- AFTER the reclaim committed its delete. Locked, either the reclaim
-- waits for this write (then deletes it), or this write waits and
-- re-evaluates against the new address (then matches nothing).
FOR SHARE
ON CONFLICT (host_id) DO UPDATE SET
    running_sandboxes = EXCLUDED.running_sandboxes,
    provisioning_sandboxes = EXCLUDED.provisioning_sandboxes,
    paused_sandboxes = EXCLUDED.paused_sandboxes,
    allocated_memory_mib = EXCLUDED.allocated_memory_mib,
    allocated_vcpus = EXCLUDED.allocated_vcpus,
    used_net_slots = EXCLUDED.used_net_slots,
    provisioning_net_slots = EXCLUDED.provisioning_net_slots,
    warm_net_slots = EXCLUDED.warm_net_slots,
    net_slot_ceiling = EXCLUDED.net_slot_ceiling,
    max_network_slots = EXCLUDED.max_network_slots,
    max_sandboxes = EXCLUDED.max_sandboxes,
    unknown_allocation_vms = EXCLUDED.unknown_allocation_vms,
    reported_at = EXCLUDED.reported_at,
    -- The control-plane-owned fence counters are RECOMPUTED from the
    -- ledger against this report's own timestamp, never preserved and
    -- never reset to zero. Recomputing is what makes the fence
    -- self-healing: a missed decrement, a crashed replica's abandoned
    -- row, or a double charge all converge within one heartbeat
    -- interval. Resetting to zero instead would free capacity for VMs
    -- this report cannot yet see — a report SAMPLED before a VM entered
    -- vmd's instance map can ARRIVE after it, which is why a
    -- materialized reservation keeps charging until a report clears its
    -- materialization by the slack window.
    charged_count = (SELECT COUNT(*) FROM host_reservation r
                     WHERE r.host_id = EXCLUDED.host_id
                       AND r.created_at > now() - make_interval(secs => @lease_secs::int)
                       AND (r.materialized_at IS NULL
                            OR r.materialized_at + make_interval(secs => @slack_secs::int) > now())),
    charged_memory_mib = COALESCE((SELECT SUM(r.memory_mib) FROM host_reservation r
                     WHERE r.host_id = EXCLUDED.host_id
                       AND r.created_at > now() - make_interval(secs => @lease_secs::int)
                       AND (r.materialized_at IS NULL
                            OR r.materialized_at + make_interval(secs => @slack_secs::int) > now())), 0),
    charged_vcpus = COALESCE((SELECT SUM(r.vcpus) FROM host_reservation r
                     WHERE r.host_id = EXCLUDED.host_id
                       AND r.created_at > now() - make_interval(secs => @lease_secs::int)
                       AND (r.materialized_at IS NULL
                            OR r.materialized_at + make_interval(secs => @slack_secs::int) > now())), 0);

-- name: DeleteHostPressure :exec
-- Clears stored pressure when a host identity is reclaimed by a new
-- machine: the old machine's numbers are meaningless for the new
-- holder, and stale pressure must not survive into its tenure.
DELETE FROM host_pressure WHERE host_id = $1;

-- name: ReserveHostCapacity :one
-- The admission fence: atomically charges one create against the newest
-- pressure report plus every reservation still in flight, and records
-- the ledger row — one statement, one round trip, and the only
-- synchronous scheduling work on the create path.
--
-- The UPDATE is what makes concurrent replicas safe, and it must be an
-- UPDATE of the counters ON the pressure row rather than a COUNT over
-- host_reservation. Under READ COMMITTED a statement's snapshot is
-- taken before it blocks, so a replica waiting on a row lock would
-- still count the ledger as it stood BEFORE the winner inserted its
-- row — both would pass the same limit check and over-place. An UPDATE
-- instead re-evaluates its WHERE clause against the committed row
-- version after the lock is granted (EvalPlanQual), so the loser sees
-- the winner's charge and fails the check. That re-evaluation is why
-- the limits are tested against columns of this row.
--
-- Eligibility is fail-closed by construction: no pressure row, a stale
-- report, or a non-active host all make the UPDATE match nothing and
-- the INSERT insert nothing. A host whose publisher broke while its
-- heartbeat stays healthy must stop taking placements, not fall back to
-- counts admission cannot fence.
--
-- Hard admission checks are the OPERATOR limits the report carries
-- (max_sandboxes, max_network_slots) plus the kernel slot ceiling.
-- Memory and vcpus are deliberately NOT hard-capped: firecracker hosts
-- overcommit both by design (lazy faulting), so capping allocations at
-- physical capacity would refuse hosts that run fine today. They are
-- charged for ranking only, until an operator-configured allocation
-- limit exists.
--
-- Paused sandboxes count against max_sandboxes: resume is pinned to
-- this host, so every paused sandbox is capacity it must be able to
-- take back at any moment.
--
-- Slot arithmetic: warm slots are already-prepared inventory, so a
-- charge only implies a NEW slot once the warm pool is exhausted —
-- GREATEST(0, charged + 1 - warm) net-new on top of every slot that
-- already exists (used + provisioning + warm).
--
-- The same-sandbox guard makes a control-plane retry idempotent. It
-- reads the ledger from the statement snapshot, which is sound here
-- because retries of one sandbox are sequential from one replica, never
-- concurrent; a double charge would in any case self-heal at the next
-- report, which recomputes these counters from the ledger.
WITH held AS (
    -- An admission this sandbox already holds ON THIS HOST: the retry
    -- returns it unchanged rather than charging twice.
    SELECT r.sandbox_id FROM host_reservation r
    WHERE r.sandbox_id = @sandbox_id AND r.host_id = @host_id
), bumped AS (
    UPDATE host_pressure hp
    SET charged_count = hp.charged_count + 1,
        charged_memory_mib = hp.charged_memory_mib + @memory_mib::bigint,
        charged_vcpus = hp.charged_vcpus + @vcpus::bigint
    WHERE hp.host_id = @host_id
      AND hp.reported_at > now() - make_interval(secs => sqlc.arg('freshness_secs')::int)
      AND EXISTS (SELECT 1 FROM host h WHERE h.id = hp.host_id AND h.status = 'active')
      AND NOT EXISTS (SELECT 1 FROM host_reservation r WHERE r.sandbox_id = @sandbox_id)
      AND NOT EXISTS (SELECT 1 FROM held)
      AND (hp.max_sandboxes <= 0
           OR hp.running_sandboxes + hp.provisioning_sandboxes + hp.paused_sandboxes
              + hp.charged_count + 1 <= hp.max_sandboxes)
      AND (LEAST(NULLIF(hp.max_network_slots, 0), NULLIF(hp.net_slot_ceiling, 0)) IS NULL
           OR hp.used_net_slots + hp.provisioning_net_slots + hp.warm_net_slots
              + GREATEST(0, hp.charged_count + 1 - hp.warm_net_slots)
              <= LEAST(NULLIF(hp.max_network_slots, 0), NULLIF(hp.net_slot_ceiling, 0)))
    RETURNING hp.host_id
), inserted AS (
    INSERT INTO host_reservation (sandbox_id, host_id, memory_mib, vcpus)
    SELECT @sandbox_id, b.host_id, @memory_mib, @vcpus FROM bumped b
    -- A conflict means this sandbox is already admitted on a DIFFERENT
    -- host. Insert nothing and return nothing: the caller sees a
    -- rejection, which is the safe outcome — silently moving a
    -- reservation would leave the first host charging for a sandbox
    -- that will never land there, and a sandbox is bound to the host
    -- its first admission chose. (Unreachable through the scheduler,
    -- which admits once per create; the guard exists so it stays true.)
    ON CONFLICT (sandbox_id) DO NOTHING
    RETURNING sandbox_id
)
SELECT sandbox_id FROM inserted
UNION ALL
SELECT sandbox_id FROM held;

-- name: ReleaseHostReservation :exec
-- Frees a reservation whose create failed before the VM existed (vmd
-- rejected, INSERT failed, handler aborted): the ledger row goes and
-- its charge comes off the fence counters in the same statement, so the
-- capacity is available to the very next admission rather than at the
-- next report.
--
-- Clamped at zero and driven by the DELETE's own RETURNING, so it can
-- only ever decrement for a row that actually existed — a duplicated
-- abort (defer plus explicit call) deletes nothing the second time and
-- therefore decrements nothing.
WITH gone AS (
    DELETE FROM host_reservation
    WHERE sandbox_id = $1
    RETURNING host_id, memory_mib, vcpus
)
UPDATE host_pressure hp
SET charged_count = GREATEST(0, hp.charged_count - 1),
    charged_memory_mib = GREATEST(0, hp.charged_memory_mib - g.memory_mib),
    charged_vcpus = GREATEST(0, hp.charged_vcpus - g.vcpus)
FROM gone g
WHERE hp.host_id = g.host_id;

-- name: MaterializeHostReservation :exec
-- Stamps the moment the vmd create RPC returned: from here on the VM
-- provably exists in vmd's instance map, so any pressure report SAMPLED
-- after this instant includes it. The row keeps charging until a report
-- arrives slack-clear of this stamp (see the table comment), then
-- report-time hygiene deletes it.
UPDATE host_reservation SET materialized_at = now()
WHERE sandbox_id = $1 AND materialized_at IS NULL;

-- name: RetireHostReservations :exec
-- Report-time hygiene, run after every successful pressure upsert for
-- the reporting host (once per 30s, never on the create path): deletes
-- rows the charge predicate already ignores — materialized rows the
-- fresh report now provably covers, and unmaterialized rows whose lease
-- lapsed (the create crashed between reserve and dispatch). Correctness
-- never depends on this running; it only keeps the ledger from growing
-- one row per create forever.
DELETE FROM host_reservation r
WHERE r.host_id = sqlc.arg('host_id')
  AND ((r.materialized_at IS NOT NULL
        AND r.materialized_at + make_interval(secs => sqlc.arg('slack_secs')::int) < now())
       OR (r.materialized_at IS NULL
           AND r.created_at + make_interval(secs => sqlc.arg('lease_secs')::int) < now()));

-- name: ListCapacityCandidates :many
-- The capacity scheduler's candidate set, cached control-plane-side for
-- the scheduler TTL: every active host passing the capability filter,
-- with its newest pressure report, its live reservation charges, and
-- the legacy sandbox count (the ranking signal for hosts that predate
-- pressure publication). Freshness/eligibility policy lives in the
-- scheduler; this query only distinguishes "capable" (advertised
-- capacity_pressure_v1 on the CURRENT heartbeat) and reports the raw
-- timestamps.
--
-- Scalar subqueries, not joins, for the per-host counts: a second
-- one-to-many join would cross-multiply rows (same reasoning as
-- ListHostsAdmin).
SELECT h.id, h.region, h.capacity_memory_mib, h.capacity_vcpus,
       EXISTS (
         SELECT 1 FROM host_capability hc
         WHERE hc.host_id = h.id
           AND hc.capability = sqlc.arg('pressure_capability')::text
           AND hc.heartbeat_at = h.last_heartbeat_at
       ) AS pressure_capable,
       hp.reported_at,
       COALESCE(hp.running_sandboxes, 0)::int AS running_sandboxes,
       COALESCE(hp.provisioning_sandboxes, 0)::int AS provisioning_sandboxes,
       COALESCE(hp.paused_sandboxes, 0)::int AS paused_sandboxes,
       COALESCE(hp.allocated_memory_mib, 0)::bigint AS allocated_memory_mib,
       COALESCE(hp.allocated_vcpus, 0)::bigint AS allocated_vcpus,
       COALESCE(hp.used_net_slots, 0)::int AS used_net_slots,
       COALESCE(hp.provisioning_net_slots, 0)::int AS provisioning_net_slots,
       COALESCE(hp.warm_net_slots, 0)::int AS warm_net_slots,
       COALESCE(hp.net_slot_ceiling, 0)::int AS net_slot_ceiling,
       COALESCE(hp.max_network_slots, 0)::int AS max_network_slots,
       COALESCE(hp.max_sandboxes, 0)::int AS max_sandboxes,
       -- The fence counters, maintained on the pressure row itself
       -- (see ReserveHostCapacity): reading them here means the cached
       -- candidate view ranks and pre-filters on the same numbers the
       -- admission statement will test, with no per-host subqueries.
       COALESCE(hp.charged_count, 0)::int AS charged_count,
       COALESCE(hp.charged_memory_mib, 0)::bigint AS charged_memory_mib,
       COALESCE(hp.charged_vcpus, 0)::bigint AS charged_vcpus,
       COALESCE((
         SELECT COUNT(*) FROM sandbox s
         WHERE s.host_id = h.id
           AND s.status IN ('active', 'starting')
           AND s.destroyed_at IS NULL
       ), 0)::int AS active_sandbox_count
FROM host h
LEFT JOIN host_pressure hp ON hp.host_id = h.id
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
  );
