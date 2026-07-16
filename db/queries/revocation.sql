-- name: ListActiveSandboxRevocations :many
SELECT sandbox_id FROM sandbox_revocation
WHERE expires_at > NOW();

-- name: UpsertSandboxRevocation :exec
-- Failed-create compensation can race a delete retry. Preserve whichever
-- caller supplies the longer token lifetime so an older retry cannot shorten
-- an already-persisted revocation.
INSERT INTO sandbox_revocation (sandbox_id, expires_at)
VALUES (sqlc.arg(sandbox_id), sqlc.arg(expires_at))
ON CONFLICT (sandbox_id) DO UPDATE
SET expires_at = GREATEST(sandbox_revocation.expires_at, EXCLUDED.expires_at);

-- name: DeleteExpiredSandboxRevocations :execrows
DELETE FROM sandbox_revocation
WHERE expires_at < NOW();

-- name: InsertRevokedProxyToken :exec
-- Idempotent: detaching the same binding twice is a no-op on the second call.
INSERT INTO revoked_proxy_token (sandbox_id, proxy_token, expires_at)
VALUES ($1, $2, $3)
ON CONFLICT (sandbox_id, proxy_token) DO NOTHING;

-- name: ListActiveRevokedProxyTokens :many
SELECT sandbox_id, proxy_token FROM revoked_proxy_token
WHERE expires_at > NOW();

-- name: DeleteExpiredRevokedProxyTokens :execrows
DELETE FROM revoked_proxy_token
WHERE expires_at < NOW();
