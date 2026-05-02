-- name: CreateSecret :one
-- Caller has already encrypted the value (per-row DEK, KEK-wrapped). The
-- plaintext never reaches the DB.
INSERT INTO secret (team_id, name, provider, ciphertext, encrypted_dek, kek_id)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetSecretByName :one
SELECT * FROM secret
WHERE team_id = $1 AND name = $2 AND deleted_at IS NULL;

-- name: GetSecretByID :one
SELECT * FROM secret
WHERE id = $1 AND team_id = $2 AND deleted_at IS NULL;

-- name: ListSecretsForTeam :many
SELECT * FROM secret
WHERE team_id = $1 AND deleted_at IS NULL
ORDER BY created_at DESC;

-- name: UpdateSecretValue :one
-- Caller has already re-encrypted with a fresh DEK; rotation always
-- rewraps so old ciphertext can't be replayed against new metadata.
UPDATE secret
SET ciphertext = $3,
    encrypted_dek = $4,
    kek_id = $5,
    updated_at = now()
WHERE id = $1 AND team_id = $2 AND deleted_at IS NULL
RETURNING *;

-- name: TouchSecretLastUsed :exec
UPDATE secret
SET last_used_at = now()
WHERE id = $1;

-- name: SoftDeleteSecret :one
UPDATE secret
SET deleted_at = now(), updated_at = now()
WHERE id = $1 AND team_id = $2 AND deleted_at IS NULL
RETURNING *;

-- name: SoftDeleteSecretByName :one
UPDATE secret
SET deleted_at = now(), updated_at = now()
WHERE team_id = $1 AND name = $2 AND deleted_at IS NULL
RETURNING *;

-- ---------------------------------------------------------------------------
-- sandbox_secret join table
-- ---------------------------------------------------------------------------

-- name: AddSandboxSecret :exec
INSERT INTO sandbox_secret (sandbox_id, secret_id, env_key)
VALUES ($1, $2, $3);

-- name: ListSandboxSecrets :many
SELECT s.id, s.name, s.provider, ss.env_key, ss.secret_id
FROM sandbox_secret ss
JOIN secret s ON s.id = ss.secret_id
WHERE ss.sandbox_id = $1 AND s.deleted_at IS NULL;

-- name: ListSandboxesForSecret :many
-- Joins through sandbox so callers can skip already-destroyed rows
-- (cascade may lag a concurrent destroy). Returns host_id so callers
-- can group operations by host.
SELECT sb.id, sb.host_id
FROM sandbox_secret ss
JOIN sandbox sb ON sb.id = ss.sandbox_id
WHERE ss.secret_id = $1
  AND sb.destroyed_at IS NULL;

-- ---------------------------------------------------------------------------
-- proxy_audit
-- ---------------------------------------------------------------------------

-- name: InsertProxyAudit :exec
INSERT INTO proxy_audit (
    team_id, sandbox_id, secret_id, provider,
    method, path, status, upstream_status, latency_ms, error_code
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);

-- name: ListAuditForSandbox :many
-- Pass 0 for $2 to get the most recent rows; otherwise rows older than
-- that id, descending. id is monotonic so it doubles as a cursor.
SELECT * FROM proxy_audit
WHERE sandbox_id = $1
  AND ($2::bigint = 0 OR id < $2)
ORDER BY id DESC
LIMIT $3;
