-- name: ListActiveSandboxRevocations :many
SELECT sandbox_id FROM sandbox_revocation
WHERE expires_at > NOW();

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
