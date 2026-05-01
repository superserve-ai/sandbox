-- name: CreateSecret :one
-- Insert a team-level secret. Caller has already encrypted the value with
-- envelope encryption (per-row DEK, KEK-wrapped DEK). The plaintext never
-- reaches the DB. Returns the row so the handler can echo metadata
-- (everything except the value).
INSERT INTO secret (team_id, name, provider, ciphertext, encrypted_dek, kek_id)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetSecretByName :one
-- Resolve a secret name to its row for the caller's team. Used at sandbox
-- create time. Returns 0 rows if the secret doesn't exist or was deleted.
SELECT * FROM secret
WHERE team_id = $1 AND name = $2 AND deleted_at IS NULL;

-- name: GetSecretByID :one
-- Fetch a secret by id, scoped to team. Used by audit-log lookups so a
-- crash-restart on the proxy can rebuild bindings from stable ids.
SELECT * FROM secret
WHERE id = $1 AND team_id = $2 AND deleted_at IS NULL;

-- name: ListSecretsForTeam :many
-- List a team's active secrets. Returns metadata only — handlers strip
-- ciphertext/encrypted_dek before responding to the customer.
SELECT * FROM secret
WHERE team_id = $1 AND deleted_at IS NULL
ORDER BY created_at DESC;

-- name: UpdateSecretValue :one
-- Rotate a secret's value. Caller has already re-encrypted with a fresh
-- DEK (rotation always rewraps). updated_at is bumped so the control
-- plane's rotation sweep can identify recently-changed rows.
UPDATE secret
SET ciphertext = $3,
    encrypted_dek = $4,
    kek_id = $5,
    updated_at = now()
WHERE id = $1 AND team_id = $2 AND deleted_at IS NULL
RETURNING *;

-- name: TouchSecretLastUsed :exec
-- Bumped by the audit-log writer (or a periodic sweep) so the dashboard
-- can show "last used N ago." Best-effort, never on the hot path.
UPDATE secret
SET last_used_at = now()
WHERE id = $1;

-- name: SoftDeleteSecret :one
-- Mark a secret deleted. Active sandboxes referencing it via
-- sandbox_secret keep working until the proxy revokes them out-of-band.
-- Returns the row so the handler knows whether anything was deleted.
UPDATE secret
SET deleted_at = now(), updated_at = now()
WHERE id = $1 AND team_id = $2 AND deleted_at IS NULL
RETURNING *;

-- name: SoftDeleteSecretByName :one
-- Convenience for the DELETE /secrets/:name handler.
UPDATE secret
SET deleted_at = now(), updated_at = now()
WHERE team_id = $1 AND name = $2 AND deleted_at IS NULL
RETURNING *;

-- ---------------------------------------------------------------------------
-- sandbox_secret join table
-- ---------------------------------------------------------------------------

-- name: AddSandboxSecret :exec
-- Record that a sandbox references a secret under a given env-var name.
-- Called inside the sandbox-create transaction so partial state isn't
-- visible if the create fails.
INSERT INTO sandbox_secret (sandbox_id, secret_id, env_key)
VALUES ($1, $2, $3);

-- name: ListSandboxSecrets :many
-- Bindings for one sandbox. Used at sandbox-create response time and by
-- the JWT refresh loop, which needs to know which secrets to re-mint
-- tokens for.
SELECT s.id, s.name, s.provider, ss.env_key, ss.secret_id
FROM sandbox_secret ss
JOIN secret s ON s.id = ss.secret_id
WHERE ss.sandbox_id = $1 AND s.deleted_at IS NULL;

-- name: ListSandboxesForSecret :many
-- Drives the eager rotation sweep. Joins through to sandbox so we can
-- skip rows whose sandbox has already been destroyed (the cascade may
-- not have caught up if the rotation lands mid-tear-down). Returns
-- (host_id, sandbox_id) so the control plane can group calls per VMD.
SELECT sb.id, sb.host_id
FROM sandbox_secret ss
JOIN sandbox sb ON sb.id = ss.sandbox_id
WHERE ss.secret_id = $1
  AND sb.destroyed_at IS NULL;

-- ---------------------------------------------------------------------------
-- proxy_audit
-- ---------------------------------------------------------------------------

-- name: InsertProxyAudit :exec
-- Append-only audit row written async by the proxy (off the request path).
-- Cost columns absent in MVP — see SECRETS_PROXY_PLAN.md decision 15.
INSERT INTO proxy_audit (
    team_id, sandbox_id, secret_id, provider,
    method, path, status, upstream_status, latency_ms, error_code
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);

-- name: ListAuditForSandbox :many
-- Customer-facing read. Pagination via id (descending) since rows are
-- monotonic; client passes the last id from the previous page.
-- Pass 0 for $3 to get the most recent rows.
SELECT * FROM proxy_audit
WHERE sandbox_id = $1
  AND ($2::bigint = 0 OR id < $2)
ORDER BY id DESC
LIMIT $3;
