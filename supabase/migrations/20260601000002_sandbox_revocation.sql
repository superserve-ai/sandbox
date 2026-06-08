CREATE TABLE sandbox_revocation (
    sandbox_id uuid PRIMARY KEY,
    revoked_at timestamptz NOT NULL DEFAULT NOW(),
    expires_at timestamptz NOT NULL
);

CREATE INDEX sandbox_revocation_expires_at_idx ON sandbox_revocation (expires_at);

-- Internal table — only the control plane (service_role) touches it.
ALTER TABLE public.sandbox_revocation ENABLE ROW LEVEL SECURITY;
