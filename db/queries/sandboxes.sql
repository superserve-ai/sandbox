-- name: CreateSandbox :one
INSERT INTO sandbox (team_id, name, status, vcpu_count, memory_mib, host_id, ip_address, pid, snapshot_id, timeout_seconds)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
RETURNING *;

-- name: GetSandbox :one
SELECT * FROM sandbox
WHERE id = $1 AND team_id = $2 AND destroyed_at IS NULL;

-- name: ListSandboxesByTeam :many
SELECT * FROM sandbox
WHERE team_id = $1 AND destroyed_at IS NULL
ORDER BY created_at DESC;

-- name: UpdateSandboxStatus :exec
UPDATE sandbox
SET status = $2, updated_at = now()
WHERE id = $1 AND team_id = $3 AND destroyed_at IS NULL;

-- name: UpdateSandboxHost :exec
UPDATE sandbox
SET host_id = $2, ip_address = $3, pid = $4, updated_at = now()
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

-- name: GetSandboxNetworkConfig :one
SELECT network_config FROM sandbox
WHERE id = $1 AND team_id = $2 AND destroyed_at IS NULL;

-- name: ListExpiredSandboxes :many
-- Sandboxes whose hard lifetime cap has elapsed. Includes all live states
-- (active, pausing, idle, starting) because `timeout_seconds` is a hard
-- cap measured from created_at — paused / idle sandboxes are not exempt.
-- Returns up to $1 rows per reaper cycle to bound work.
SELECT id, team_id, name, status, snapshot_id, host_id FROM sandbox
WHERE destroyed_at IS NULL
  AND timeout_seconds IS NOT NULL
  AND status != 'deleted'
  AND created_at + (timeout_seconds || ' seconds')::interval < now()
ORDER BY created_at ASC
LIMIT $1;
