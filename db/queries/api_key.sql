-- name: CreateAPIKeyV2 :one
INSERT INTO api_key (team_id, key_hash, name, scopes, created_by, expires_at)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetAPIKeyByHashV2 :one
SELECT * FROM api_key
WHERE key_hash = $1 AND revoked_at IS NULL;

-- name: ListAPIKeysByTeam :many
SELECT * FROM api_key
WHERE team_id = $1
ORDER BY created_at DESC;

-- name: RevokeAPIKeyV2 :exec
UPDATE api_key
SET revoked_at = now()
WHERE id = $1 AND revoked_at IS NULL;

-- name: TouchAPIKeyLastUsed :exec
UPDATE api_key
SET last_used_at = now()
WHERE id = $1;

-- name: DeleteExpiredAPIKeys :exec
DELETE FROM api_key
WHERE expires_at IS NOT NULL AND expires_at < now();
