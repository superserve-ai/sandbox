-- name: CreateSecret :one
-- Caller has already encrypted value; plaintext never reaches the DB.
INSERT INTO secret (
    team_id, name, auth_type, auth_config, provider_shortcut, hosts,
    ciphertext, encrypted_dek, kek_id
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING *;

-- name: GetSecretByName :one
SELECT * FROM secret
WHERE team_id = $1 AND name = $2 AND deleted_at IS NULL;

-- name: GetSecretByID :one
SELECT * FROM secret
WHERE id = $1 AND team_id = $2 AND deleted_at IS NULL;

-- name: GetSecretByIDForDecrypt :one
-- Daemon decrypt path. Team-scoped; excludes soft-deleted.
SELECT * FROM secret
WHERE id = $1 AND team_id = $2 AND deleted_at IS NULL;

-- name: ListSecretsForTeam :many
SELECT * FROM secret
WHERE team_id = $1 AND deleted_at IS NULL
ORDER BY created_at DESC;

-- name: UpdateSecretValue :one
-- Rotation: caller has re-encrypted with a fresh DEK.
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
-- Setting deleted_at both revokes and hides from new-binding listings.
UPDATE secret
SET deleted_at = now(), updated_at = now()
WHERE id = $1 AND team_id = $2 AND deleted_at IS NULL
RETURNING *;

-- name: SoftDeleteSecretByName :one
UPDATE secret
SET deleted_at = now(), updated_at = now()
WHERE team_id = $1 AND name = $2 AND deleted_at IS NULL
RETURNING *;

-- name: AddSandboxSecret :exec
INSERT INTO sandbox_secret (sandbox_id, secret_id, env_key)
VALUES ($1, $2, $3);

-- name: ListSandboxSecrets :many
-- Secret rows plus the env_key each is bound under for this sandbox.
SELECT s.*, ss.env_key
FROM sandbox_secret ss
JOIN secret s ON s.id = ss.secret_id
WHERE ss.sandbox_id = $1 AND s.deleted_at IS NULL;

-- name: ListSandboxSecretBindings :many
-- env_key → secret_name map for the sandbox detail response. Includes
-- bindings to soft-deleted secrets so the UI can show "(revoked)".
SELECT ss.env_key, s.name AS secret_name, (s.deleted_at IS NOT NULL)::bool AS secret_revoked
FROM sandbox_secret ss
JOIN secret s ON s.id = ss.secret_id
WHERE ss.sandbox_id = $1
ORDER BY ss.env_key;

-- name: ListSandboxesForSecret :many
-- Returns (sandbox_id, host_id) for non-destroyed sandboxes bound to this secret.
SELECT sb.id, sb.host_id
FROM sandbox_secret ss
JOIN sandbox sb ON sb.id = ss.sandbox_id
WHERE ss.secret_id = $1
  AND sb.destroyed_at IS NULL;

-- name: ListSandboxesBoundToSecret :many
-- For the secret-detail "bound to" panel: which living sandboxes use this
-- credential, under which env_var, and at what status.
SELECT sb.id, sb.name, sb.status, ss.env_key
FROM sandbox_secret ss
JOIN sandbox sb ON sb.id = ss.sandbox_id
WHERE ss.secret_id = $1
  AND sb.team_id = $2
  AND sb.destroyed_at IS NULL
ORDER BY sb.created_at DESC;

-- name: InsertProxyAudit :exec
INSERT INTO proxy_audit (
    team_id, sandbox_id, secret_id,
    method, host, path, status, upstream_status, latency_ms, error_code
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);

-- name: ListProxyAuditEvents :many
-- Request rows for the unified per-sandbox network log, filtered by an optional
-- time window (before/since); before doubles as the pagination cursor. Merged
-- with net_flow connection rows in the handler.
SELECT * FROM proxy_audit
WHERE sandbox_id = sqlc.arg('sandbox_id')
  AND (sqlc.narg('before')::timestamptz IS NULL OR ts < sqlc.narg('before')::timestamptz)
  AND (sqlc.narg('since')::timestamptz IS NULL OR ts >= sqlc.narg('since')::timestamptz)
ORDER BY ts DESC
LIMIT sqlc.arg('row_limit');

-- name: ListAuditForSecret :many
-- Per-secret audit with LEFT JOIN sandbox so the UI can render readable
-- sandbox names; null when the sandbox was deleted.
-- $3=0 returns the most recent rows; otherwise rows older than that id.
-- $4/$5 status bounds: 0/9999 = unfiltered.
SELECT pa.*, sb.name AS sandbox_name
FROM proxy_audit pa
LEFT JOIN sandbox sb ON sb.id = pa.sandbox_id
WHERE pa.secret_id = $1
  AND pa.team_id = $2
  AND ($3::bigint = 0 OR pa.id < $3)
  AND pa.status >= $4::int
  AND pa.status <= $5::int
ORDER BY pa.id DESC
LIMIT $6;
