-- name: CreateSandbox :one
INSERT INTO sandbox (team_id, name, status, vcpu_count, memory_mib, host_id, ip_address, pid, snapshot_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING *;

-- name: GetSandbox :one
SELECT * FROM sandbox
WHERE id = $1 AND destroyed_at IS NULL;

-- name: ListSandboxesByTeam :many
SELECT * FROM sandbox
WHERE team_id = $1 AND destroyed_at IS NULL
ORDER BY created_at DESC;

-- name: ListSandboxesByStatus :many
SELECT * FROM sandbox
WHERE status = $1 AND destroyed_at IS NULL
ORDER BY created_at DESC;

-- name: UpdateSandboxStatus :exec
UPDATE sandbox
SET status = $2, updated_at = now()
WHERE id = $1 AND destroyed_at IS NULL;

-- name: UpdateSandboxHost :exec
UPDATE sandbox
SET host_id = $2, ip_address = $3, pid = $4, updated_at = now()
WHERE id = $1 AND destroyed_at IS NULL;

-- name: UpdateSandboxLastActivity :exec
UPDATE sandbox
SET last_activity_at = now(), updated_at = now()
WHERE id = $1 AND destroyed_at IS NULL;

-- name: SetSandboxSnapshot :exec
UPDATE sandbox
SET snapshot_id = $2, updated_at = now()
WHERE id = $1 AND destroyed_at IS NULL;

-- name: DestroySandbox :exec
UPDATE sandbox
SET destroyed_at = now(), status = 'deleted', updated_at = now()
WHERE id = $1 AND destroyed_at IS NULL;

-- name: SandboxExists :one
SELECT EXISTS(SELECT 1 FROM sandbox WHERE id = $1 AND destroyed_at IS NULL);

-- name: ListIdleSandboxes :many
SELECT * FROM sandbox
WHERE status = 'idle'
  AND destroyed_at IS NULL
  AND last_activity_at < $1
ORDER BY last_activity_at ASC;
