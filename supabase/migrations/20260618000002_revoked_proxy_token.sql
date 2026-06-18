-- A detached binding's proxy token, recorded so the proxy refuses requests
-- carrying it even from a process still holding a JWT that lists the binding.
-- expires_at tracks the JWT lifetime; past it the row is reapable.
-- Idempotent: re-running on a database that already has these objects is a no-op.
CREATE TABLE IF NOT EXISTS revoked_proxy_token (
    sandbox_id uuid NOT NULL,
    proxy_token text NOT NULL,
    revoked_at timestamptz NOT NULL DEFAULT NOW(),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (sandbox_id, proxy_token)
);

CREATE INDEX IF NOT EXISTS revoked_proxy_token_expires_at_idx ON revoked_proxy_token (expires_at);

-- Internal table — only the control plane (service_role) touches it. ENABLE RLS is idempotent.
ALTER TABLE public.revoked_proxy_token ENABLE ROW LEVEL SECURITY;
