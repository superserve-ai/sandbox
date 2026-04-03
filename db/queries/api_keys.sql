-- name: GetAPIKeyByHash :one
SELECT * FROM api_keys
WHERE key_hash = $1
  AND revoked = false
  AND (expires_at IS NULL OR expires_at > now());

-- name: UpdateAPIKeyLastUsed :exec
UPDATE api_keys
SET last_used_at = now()
WHERE id = $1;

-- name: CreateAPIKey :one
INSERT INTO api_keys (key_hash, name, expires_at, team_id, scopes)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: RevokeAPIKey :exec
UPDATE api_keys
SET revoked = true
WHERE id = $1;
