-- name: InsertSandboxRevocation :exec
-- Idempotent: destroying a sandbox twice is a no-op on the second call.
INSERT INTO sandbox_revocation (sandbox_id, expires_at)
VALUES ($1, $2)
ON CONFLICT (sandbox_id) DO NOTHING;

-- name: ListActiveSandboxRevocations :many
SELECT sandbox_id FROM sandbox_revocation
WHERE expires_at > NOW();

-- name: DeleteExpiredSandboxRevocations :execrows
DELETE FROM sandbox_revocation
WHERE expires_at < NOW();
