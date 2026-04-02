-- name: GetAPIKeyByHash :one
SELECT * FROM api_keys
WHERE key_hash = $1 AND revoked = false;

-- name: CreateAPIKey :one
INSERT INTO api_keys (key_hash, name, expires_at)
VALUES ($1, $2, $3)
RETURNING *;

-- name: RevokeAPIKey :exec
UPDATE api_keys
SET revoked = true
WHERE id = $1;
