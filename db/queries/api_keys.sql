-- name: GetAPIKeyByHash :one
SELECT * FROM api_keys
WHERE key_hash = $1
  AND revoked = false
  AND (expires_at IS NULL OR expires_at > now());

-- name: CreateAPIKey :one
INSERT INTO api_keys (key_hash, name, team_id, scopes, expires_at)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: RevokeAPIKey :exec
UPDATE api_keys
SET revoked = true
WHERE id = $1;

-- name: TouchAPIKeyLastUsed :exec
UPDATE api_keys
SET last_used_at = now()
WHERE id = $1;
