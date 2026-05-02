-- Team-level credentials encrypted at rest with envelope encryption:
-- a per-row AES-256-GCM data key wraps the value; the data key itself
-- is wrapped by a Cloud KMS KEK. Plaintext is never persisted and
-- never returned by any read endpoint.

CREATE TABLE secret (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id         uuid NOT NULL REFERENCES team(id),
    name            text NOT NULL,
    provider        text NOT NULL,
    -- nonce(12) || aes-256-gcm(value, dek) || tag(16) packed together,
    -- matching crypto/cipher.AEAD output with the nonce prefixed.
    ciphertext      bytea NOT NULL,
    -- DEK wrapped by the KMS KEK named in kek_id. Stored per row so
    -- KEK rotation or migration can decrypt rows wrapped by either key.
    encrypted_dek   bytea NOT NULL,
    kek_id          text NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    last_used_at    timestamptz,
    deleted_at      timestamptz
);

-- Active secrets are unique by (team, name). Soft-deleted rows are
-- excluded so a customer can recreate a secret with the same name after
-- deletion.
CREATE UNIQUE INDEX secret_team_name_unique
    ON secret (team_id, name) WHERE deleted_at IS NULL;

CREATE INDEX secret_team_idx ON secret (team_id) WHERE deleted_at IS NULL;

CREATE TABLE sandbox_secret (
    sandbox_id  uuid NOT NULL REFERENCES sandbox(id) ON DELETE CASCADE,
    secret_id   uuid NOT NULL REFERENCES secret(id),
    env_key     text NOT NULL,
    PRIMARY KEY (sandbox_id, env_key)
);

CREATE INDEX sandbox_secret_secret_idx ON sandbox_secret (secret_id);

CREATE TABLE proxy_audit (
    id              bigserial PRIMARY KEY,
    ts              timestamptz NOT NULL DEFAULT now(),
    team_id         uuid NOT NULL,
    sandbox_id      uuid NOT NULL,
    secret_id       uuid NOT NULL,
    provider        text NOT NULL,
    method          text NOT NULL,
    path            text NOT NULL,
    status          int NOT NULL,
    upstream_status int,
    latency_ms      int,
    error_code      text
);

CREATE INDEX proxy_audit_sandbox_ts_idx ON proxy_audit (sandbox_id, ts DESC);
CREATE INDEX proxy_audit_team_ts_idx ON proxy_audit (team_id, ts DESC);
