-- name: GetAPIKeyByHash :one
SELECT id, team_id, key_hash, name, scopes, created_by, expires_at, revoked_at, last_used_at, created_at
FROM api_key
WHERE key_hash = $1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now());

-- name: CreateAPIKey :one
INSERT INTO api_key (team_id, key_hash, name, scopes, created_by)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: RevokeAPIKey :exec
UPDATE api_key
SET revoked_at = now()
WHERE id = $1 AND team_id = $2;

-- name: UpdateAPIKeyLastUsed :exec
UPDATE api_key
SET last_used_at = now()
WHERE id = $1;

-- name: ListAPIKeysByTeam :many
SELECT id, team_id, name, scopes, created_by, expires_at, revoked_at, last_used_at, created_at
FROM api_key
WHERE team_id = $1
ORDER BY created_at DESC;
