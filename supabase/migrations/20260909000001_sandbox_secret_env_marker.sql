-- What the guest currently holds from the last secrets injection, so a
-- resume can tell whether the environment captured in the snapshot is still
-- the right one and skip the re-mint and guest round trip when it is.
-- Written after each successful injection; NULL means unknown, which a
-- resume treats as "inject".
ALTER TABLE sandbox
    ADD COLUMN IF NOT EXISTS secret_env_fingerprint text,
    ADD COLUMN IF NOT EXISTS secret_env_ip text,
    ADD COLUMN IF NOT EXISTS secret_env_injected_at timestamptz,
    ADD COLUMN IF NOT EXISTS secret_env_expires_at timestamptz;

COMMENT ON COLUMN sandbox.secret_env_fingerprint IS
    'Digest of the binding set last injected into the guest; a resume re-injects when the current set differs.';
COMMENT ON COLUMN sandbox.secret_env_ip IS
    'Guest IP the injected proxy JWT is bound to; a resume re-injects when the guest comes back on another.';
COMMENT ON COLUMN sandbox.secret_env_injected_at IS
    'When the last injection landed; only a snapshot taken after it holds the injected environment.';
COMMENT ON COLUMN sandbox.secret_env_expires_at IS
    'Expiry of the injected proxy JWT; a resume re-injects when it is near.';
