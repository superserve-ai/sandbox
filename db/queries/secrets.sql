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

-- name: GetSecretsByNames :many
SELECT * FROM secret
WHERE team_id = $1 AND name = ANY($2::text[]) AND deleted_at IS NULL;

-- name: GetSecretByID :one
SELECT * FROM secret
WHERE id = $1 AND team_id = $2 AND deleted_at IS NULL;

-- name: GetSecretByIDForDecrypt :one
-- Daemon decrypt path. Team-scoped; excludes soft-deleted. Separate from
-- GetSecretByID so it can diverge later (audit, caching) without touching API reads.
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
WHERE id = $1 AND team_id = $2;

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

-- name: LockSandboxForSecretWrites :exec
-- Transaction-scoped advisory lock keyed on the sandbox so the binding-count cap
-- check and insert serialize across API instances, not just the in-process lock.
SELECT pg_advisory_xact_lock(hashtext($1)::bigint);

-- name: AddSandboxSecret :exec
INSERT INTO sandbox_secret (sandbox_id, secret_id, env_key, proxy_token)
VALUES ($1, $2, $3, $4);

-- name: ClaimSandboxSecretProxyToken :one
-- Persist a proxy token minted on the fly for a legacy (NULL-token) binding.
-- COALESCE keeps an existing token if a concurrent writer already set one; the
-- row lock serializes the two, and RETURNING gives whichever token is now stored
-- — so every caller injects the same revocable token, never a local unstored mint.
UPDATE sandbox_secret SET proxy_token = COALESCE(proxy_token, $3)
WHERE sandbox_id = $1 AND env_key = $2
RETURNING proxy_token;

-- name: AddSandboxSecrets :exec
-- Bulk-insert every (env_key -> secret) binding for a sandbox in one round trip;
-- the secret_ids, env_keys, and proxy_tokens arrays are paired by position.
INSERT INTO sandbox_secret (sandbox_id, secret_id, env_key, proxy_token)
SELECT @sandbox_id::uuid, (@secret_ids::uuid[])[i], (@env_keys::text[])[i], (@proxy_tokens::text[])[i]
FROM generate_subscripts(@secret_ids::uuid[], 1) AS g(i);

-- name: DeleteSandboxSecretBinding :one
-- Remove one binding by env_key; returns the secret_id and proxy token for re-mint.
DELETE FROM sandbox_secret WHERE sandbox_id = $1 AND env_key = $2
RETURNING secret_id, proxy_token;

-- name: DeleteSandboxSecrets :exec
-- Drop every secret binding for a sandbox (e.g. cleaning up a failed create).
DELETE FROM sandbox_secret WHERE sandbox_id = $1;

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

-- name: ListSandboxSecretBindingMeta :many
-- Per-binding auth shape, hosts, and proxy token for a sandbox; excludes
-- soft-deleted secrets.
SELECT s.id AS secret_id, ss.env_key, ss.proxy_token,
       s.auth_type, s.auth_config, s.provider_shortcut, s.hosts
FROM sandbox_secret ss
JOIN secret s ON s.id = ss.secret_id
WHERE ss.sandbox_id = $1 AND s.deleted_at IS NULL
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
-- Request rows for the unified per-sandbox network log. Keyset-paginated by the
-- (ts, kind, id) cursor; 'request' is this source's kind. The handler merges
-- these with net_flow connection rows under the same total order.
SELECT * FROM proxy_audit
WHERE sandbox_id = sqlc.arg('sandbox_id')
  AND (sqlc.narg('since')::timestamptz IS NULL OR ts >= sqlc.narg('since')::timestamptz)
  AND (sqlc.narg('cursor_ts')::timestamptz IS NULL
       OR (ts, 'request', id) < (sqlc.narg('cursor_ts')::timestamptz, sqlc.narg('cursor_kind')::text, sqlc.narg('cursor_id')::bigint))
ORDER BY ts DESC, id DESC
LIMIT sqlc.arg('row_limit');

-- name: ListAuditForSecret :many
-- Per-secret audit with LEFT JOIN sandbox so the UI can render readable sandbox
-- names; null when the sandbox was deleted. A null cursor returns the most
-- recent rows; otherwise rows older than that id.
SELECT pa.*, sb.name AS sandbox_name
FROM proxy_audit pa
LEFT JOIN sandbox sb ON sb.id = pa.sandbox_id
WHERE pa.secret_id = sqlc.arg('secret_id')
  AND pa.team_id = sqlc.arg('team_id')
  AND (sqlc.narg('cursor_id')::bigint IS NULL OR pa.id < sqlc.narg('cursor_id')::bigint)
  AND pa.status >= sqlc.arg('status_min')::int
  AND pa.status <= sqlc.arg('status_max')::int
ORDER BY pa.id DESC
LIMIT sqlc.arg('row_limit');
