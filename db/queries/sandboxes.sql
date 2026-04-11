-- name: CreateSandbox :one
-- ID is supplied by the caller (generated in Go via uuid.New()) rather
-- than defaulted in SQL, so the caller can parallelize this INSERT with
-- the VMD CreateVM call — both need the same sandbox_id and generating
-- it client-side lets them run concurrently instead of strictly serially.
INSERT INTO sandbox (id, team_id, name, status, vcpu_count, memory_mib, host_id, ip_address, pid, snapshot_id, timeout_seconds, metadata)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
RETURNING *;

-- name: GetSandbox :one
SELECT * FROM sandbox
WHERE id = $1 AND team_id = $2 AND destroyed_at IS NULL;

-- name: ListSandboxesByTeam :many
SELECT * FROM sandbox
WHERE team_id = $1 AND destroyed_at IS NULL
ORDER BY created_at DESC;

-- name: ListSandboxesByTeamWithFilter :many
-- Same as ListSandboxesByTeam but additionally filters rows whose metadata
-- contains every key/value pair in $2 (jsonb @> containment). Pass an empty
-- object '{}'::jsonb to match everything — but prefer ListSandboxesByTeam
-- in that case so we don't pay the (still tiny) cost of the @> evaluation.
SELECT * FROM sandbox
WHERE team_id = $1
  AND destroyed_at IS NULL
  AND metadata @> $2
ORDER BY created_at DESC;

-- name: UpdateSandboxStatus :exec
UPDATE sandbox
SET status = $2, updated_at = now()
WHERE id = $1 AND team_id = $3 AND destroyed_at IS NULL;

-- name: UpdateSandboxHost :exec
UPDATE sandbox
SET host_id = $2, ip_address = $3, pid = $4, updated_at = now()
WHERE id = $1 AND team_id = $5 AND destroyed_at IS NULL;

-- name: ActivateSandbox :exec
UPDATE sandbox
SET status = 'active',
    vcpu_count = $2,
    memory_mib = $3,
    ip_address = $4,
    updated_at = now()
WHERE id = $1 AND team_id = $5 AND destroyed_at IS NULL;

-- name: UpdateSandboxLastActivity :exec
UPDATE sandbox
SET last_activity_at = now(), updated_at = now()
WHERE id = $1 AND team_id = $2 AND destroyed_at IS NULL;

-- name: SetSandboxSnapshot :exec
UPDATE sandbox
SET snapshot_id = $2, updated_at = now()
WHERE id = $1 AND team_id = $3 AND destroyed_at IS NULL;

-- name: DestroySandbox :exec
UPDATE sandbox
SET destroyed_at = now(), status = 'deleted', updated_at = now()
WHERE id = $1 AND team_id = $2 AND destroyed_at IS NULL;

-- name: SandboxExists :one
SELECT EXISTS(SELECT 1 FROM sandbox WHERE id = $1 AND team_id = $2 AND destroyed_at IS NULL);

-- name: ListSandboxesByHost :many
-- Used by the VMD reconciler to find all non-deleted sandboxes scheduled on
-- this host. Includes both active and idle sandboxes because the reconciler
-- needs to validate both states (active → systemd unit, idle → snapshot file).
SELECT * FROM sandbox
WHERE host_id = $1 AND destroyed_at IS NULL;

-- name: MarkSandboxFailed :exec
-- Used by the reconciler to mark a sandbox failed when VMD detects it is
-- actually gone. No team_id filter — the reconciler runs with host scope,
-- not team scope.
UPDATE sandbox
SET status = 'failed', updated_at = now()
WHERE id = $1 AND destroyed_at IS NULL;

-- name: BeginPause :one
-- Atomic ownership + state check + transition to 'pausing'. Replaces the
-- GetSandbox → check status → UpdateSandboxStatus sequence on the pause
-- hot path, collapsing two DB roundtrips into one. The WHERE clause
-- enforces the invariant (only active, non-deleted sandboxes owned by
-- this team can be paused); a 0-row result means "no such sandbox OR
-- wrong team OR not currently active", and the caller disambiguates via
-- a fallback GetSandbox in the rare error path.
UPDATE sandbox
SET status = 'pausing', updated_at = now()
WHERE id = $1 AND team_id = $2 AND destroyed_at IS NULL AND status = 'active'
RETURNING *;

-- name: FinalizePause :one
-- Atomically insert the snapshot row, link it to the sandbox, and flip
-- status from 'pausing' to 'idle'. Replaces the sequence
-- CreateSnapshot → SetSandboxSnapshot → UpdateSandboxStatus, collapsing
-- three DB roundtrips into one and making the entire post-VMD bookkeeping
-- atomic (no window where a snapshot file exists on disk without a
-- database row linking it to the sandbox).
WITH new_snapshot AS (
  INSERT INTO snapshot (sandbox_id, team_id, path, size_bytes, saved, name, trigger)
  VALUES ($1, $2, $3, $4, $5, $6, $7)
  RETURNING snapshot.id AS snap_id
)
UPDATE sandbox
SET snapshot_id = (SELECT snap_id FROM new_snapshot),
    status = 'idle',
    updated_at = now()
WHERE sandbox.id = $1 AND sandbox.team_id = $2 AND sandbox.destroyed_at IS NULL
RETURNING (SELECT snap_id FROM new_snapshot)::uuid AS snapshot_id;

-- name: ListIdleSandboxes :many
SELECT * FROM sandbox
WHERE status = 'idle'
  AND destroyed_at IS NULL
  AND last_activity_at < $1
ORDER BY last_activity_at ASC;

-- name: UpdateSandboxNetworkConfig :exec
UPDATE sandbox
SET network_config = $2, updated_at = now()
WHERE id = $1 AND team_id = $3 AND destroyed_at IS NULL;

-- name: UpdateSandboxMetadata :exec
UPDATE sandbox
SET metadata = $2, updated_at = now()
WHERE id = $1 AND team_id = $3 AND destroyed_at IS NULL;

-- name: GetSandboxNetworkConfig :one
SELECT network_config FROM sandbox
WHERE id = $1 AND team_id = $2 AND destroyed_at IS NULL;

-- name: ClaimExpiredSandboxes :many
-- Atomically claims active sandboxes whose hard timeout has elapsed and marks
-- them as 'pausing'. FOR UPDATE SKIP LOCKED lets concurrent reaper replicas
-- skip rows already being processed, so multi-replica Cloud Run deployments
-- do not double-process the same sandbox.
--
-- Only 'active' sandboxes are claimed — idle sandboxes are already stopped,
-- and transient states (starting, pausing) are skipped to avoid racing with
-- in-progress operations. The 60-second grace window prevents reaping a sandbox
-- that was just created with a very short timeout before it finishes starting up.
WITH expired AS (
  SELECT id, team_id, name, snapshot_id, host_id
  FROM sandbox
  WHERE destroyed_at IS NULL
    AND timeout_seconds IS NOT NULL
    AND status = 'active'
    AND created_at + (timeout_seconds || ' seconds')::interval < now()
    AND created_at < now() - interval '60 seconds'
  ORDER BY created_at ASC
  LIMIT $1
  FOR UPDATE SKIP LOCKED
)
UPDATE sandbox
SET status = 'pausing', updated_at = now()
FROM expired
WHERE sandbox.id = expired.id
RETURNING expired.id, expired.team_id, expired.name, expired.snapshot_id, expired.host_id;
