-- Team-scoped credentials for the sandbox enforcement proxy.
-- Values are encrypted at rest with envelope encryption (per-row AES-256-GCM
-- DEK wrapped by a Cloud KMS KEK). Plaintext is never persisted.
--
-- Idempotent: re-running on a database that already has these objects is a no-op.

-- Team-level knobs:
--   credential_store_kind: 'builtin' (encrypted here) or 'external' (BYO vault).
--   unmatched_host_policy: 'passthrough' or 'deny' for hosts no credential covers.
ALTER TABLE team
    ADD COLUMN IF NOT EXISTS credential_store_kind   text   NOT NULL DEFAULT 'builtin'
        CHECK (credential_store_kind IN ('builtin', 'external')),
    ADD COLUMN IF NOT EXISTS credential_store_config jsonb,
    ADD COLUMN IF NOT EXISTS unmatched_host_policy   text   NOT NULL DEFAULT 'passthrough'
        CHECK (unmatched_host_policy IN ('passthrough', 'deny'));

CREATE TABLE IF NOT EXISTS secret (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id             uuid NOT NULL REFERENCES team(id),
    name                text NOT NULL,
    -- 'bearer', 'basic', 'api-key', or 'custom'.
    auth_type           text NOT NULL CHECK (auth_type IN ('bearer', 'basic', 'api-key', 'custom')),
    -- Type-specific config; e.g. api-key: {"header": "x-api-key", "prefix": ""}.
    auth_config         jsonb NOT NULL DEFAULT '{}'::jsonb,
    -- Provider shortcut name (e.g. 'anthropic'), null when raw auth_type was used.
    provider_shortcut   text,
    -- Upstream hosts this credential applies to.
    hosts               text[] NOT NULL,
    -- nonce(12) || aes-256-gcm(value, dek) || tag(16).
    ciphertext          bytea NOT NULL,
    -- DEK wrapped by the KMS key named in kek_id.
    encrypted_dek       bytea NOT NULL,
    kek_id              text  NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    last_used_at        timestamptz,
    -- Soft-delete + revocation; row retained for audit history.
    deleted_at          timestamptz
);

-- Unique by (team, name) among active rows; soft-deleted names are reusable.
CREATE UNIQUE INDEX IF NOT EXISTS secret_team_name_unique
    ON secret (team_id, name) WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS secret_team_idx ON secret (team_id) WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS sandbox_secret (
    sandbox_id  uuid NOT NULL REFERENCES sandbox(id) ON DELETE CASCADE,
    secret_id   uuid NOT NULL REFERENCES secret(id),
    env_key     text NOT NULL,
    PRIMARY KEY (sandbox_id, env_key)
);

CREATE INDEX IF NOT EXISTS sandbox_secret_secret_idx ON sandbox_secret (secret_id);

-- Append-only audit of every proxy-mediated request.
CREATE TABLE IF NOT EXISTS proxy_audit (
    id               bigserial PRIMARY KEY,
    ts               timestamptz NOT NULL DEFAULT now(),
    team_id          uuid NOT NULL,
    sandbox_id       uuid NOT NULL,
    -- Null when no credential was used (passthrough) or denied pre-resolution.
    secret_id        uuid,
    method           text NOT NULL,
    host             text NOT NULL,
    path             text NOT NULL,
    -- Status returned to the sandbox.
    status           int  NOT NULL,
    -- Null when the proxy short-circuited before reaching the upstream.
    upstream_status  int,
    latency_ms       int,
    -- Short proxy-reason code when status was proxy-side (e.g. 'host_not_allowed').
    error_code       text
);

CREATE INDEX IF NOT EXISTS proxy_audit_sandbox_ts_idx ON proxy_audit (sandbox_id, ts DESC);
CREATE INDEX IF NOT EXISTS proxy_audit_team_ts_idx    ON proxy_audit (team_id,    ts DESC);
CREATE INDEX IF NOT EXISTS proxy_audit_secret_ts_idx  ON proxy_audit (secret_id,  ts DESC) WHERE secret_id IS NOT NULL;

-- Internal tables — only the control plane (service_role) touches them. ENABLE RLS is idempotent.
ALTER TABLE public.secret         ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sandbox_secret ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.proxy_audit    ENABLE ROW LEVEL SECURITY;
