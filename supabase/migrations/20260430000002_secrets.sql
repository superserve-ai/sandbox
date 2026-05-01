-- Secrets proxy storage (see docs/SECRETS_PROXY_PLAN.md).
--
-- `secret` holds team-level credentials encrypted at rest with envelope
-- encryption: per-row AES-256-GCM data key wrapped by a Cloud KMS KEK.
-- Plaintext is only ever decrypted at sandbox-create time and held in
-- secretsproxy memory on the VMD host — never written back to disk and
-- never returned by any read endpoint.
--
-- `sandbox_secret` is the join between live sandboxes and the secrets
-- they reference. Used by the rotation sweep and the future per-secret
-- usage endpoint. Cascade on sandbox delete keeps it in sync without an
-- explicit cleanup path.
--
-- `proxy_audit` is the append-only log of every proxy forward attempt.

CREATE TABLE secret (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id         uuid NOT NULL REFERENCES team(id),
    name            text NOT NULL,
    provider        text NOT NULL,
    -- nonce(12) || aes-256-gcm(value, dek) || tag(16) packed together,
    -- matching the convention used by crypto/cipher.AEAD.
    ciphertext      bytea NOT NULL,
    -- DEK wrapped by the Cloud KMS KEK. KMS embeds the key version it
    -- used to wrap, so decrypt round-trips correctly across rotation.
    encrypted_dek   bytea NOT NULL,
    -- KMS resource name (projects/.../locations/.../keyRings/.../cryptoKeys/...).
    -- Stored per row for ops clarity and to support multi-region or
    -- per-environment KEKs without a global config table.
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
