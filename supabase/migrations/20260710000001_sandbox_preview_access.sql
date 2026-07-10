-- Preview URL authentication with deny-by-default published ports.
--
-- preview_access gates the edge proxy's numeric-port routes
-- ({port}-{id}.<domain>):
--   'public'  — every listening port is routable with no auth (today's
--               behavior; the default, so existing sandboxes are unchanged).
--   'private' — deny-by-default: ONLY ports explicitly published (see
--               sandbox_published_port) are routable, and each requires a
--               per-port preview token. Every other port returns 404 at the
--               edge, even with a valid token for a different port.
--
-- The proxy never reads these tables directly: preview_access and the
-- published-port set are carried onto the vmd instance record (RestoreSnapshot
-- / UpdateSandboxPreviewPolicy) and served to the proxy by vmd's local
-- /instances endpoint. The DB rows are the intent; the vmd record is the
-- enforcement copy.
ALTER TABLE sandbox
    ADD COLUMN IF NOT EXISTS preview_access text NOT NULL DEFAULT 'public';

ALTER TABLE sandbox
    DROP CONSTRAINT IF EXISTS sandbox_preview_access_valid;

-- Defense in depth: a non-handler write path can't invent a third state. The
-- proxy treats any non-'private' value as public (legacy open), so a typo'd
-- value would silently expose a sandbox — reject it at the schema instead.
ALTER TABLE sandbox
    ADD CONSTRAINT sandbox_preview_access_valid
    CHECK (preview_access IN ('public', 'private'));

COMMENT ON COLUMN sandbox.preview_access IS
    'Preview URL access policy: ''public'' (unauthenticated, all ports, the '
    'default) or ''private'' (deny-by-default; only published ports route, '
    'each token-gated). Settable at create and via PATCH.';

-- One row per explicitly published preview port. A port is reachable on a
-- private sandbox only if it has a row here. token_version is the per-port
-- credential generation: bumping it (rotate) invalidates only that port's
-- outstanding tokens, never another port's.
CREATE TABLE IF NOT EXISTS sandbox_published_port (
    sandbox_id    uuid    NOT NULL REFERENCES sandbox (id) ON DELETE CASCADE,
    port          integer NOT NULL,
    token_version integer NOT NULL DEFAULT 1,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (sandbox_id, port),
    -- Mirror the edge proxy's routable range (privileged ports are refused
    -- there) and keep token_version always mintable.
    CONSTRAINT sandbox_published_port_range CHECK (port >= 1024 AND port <= 65535),
    CONSTRAINT sandbox_published_port_version_valid CHECK (token_version >= 1)
);

COMMENT ON TABLE sandbox_published_port IS
    'Explicitly published preview ports for a private sandbox. Presence of a '
    'row is what makes a port routable at the edge; token_version is the '
    'per-port credential generation used for independent rotation.';
