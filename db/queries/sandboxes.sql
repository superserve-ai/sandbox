-- name: CreateSandbox :one
INSERT INTO sandbox (team_id, name, status, vcpu_count, memory_mib, host_id, ip_address, pid, snapshot_id, timeout_seconds, metadata)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
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
