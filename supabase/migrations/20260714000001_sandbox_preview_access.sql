-- Preview URL authentication with deny-by-default published ports.
--
-- preview_access gates the edge proxy's numeric-port routes
-- ({port}-{id}.<domain>):
--   'legacy_public' — every listening port is routable with no auth. Reserved
--               for existing sandboxes and clients that omit the new policy.
--   'public'  — ONLY ports explicitly published (see sandbox_published_port)
--               are routable, with no token required.
--   'private' — ONLY ports explicitly published (see
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
    ADD COLUMN IF NOT EXISTS preview_access text NOT NULL DEFAULT 'legacy_public',
    -- Monotonic per-sandbox generation of the whole preview policy (access +
    -- published-port set). Bumped inside the same transaction as every preview
    -- mutation; carried to vmd on each push. vmd rejects any update whose
    -- revision is <= the one it already holds, so concurrent or reordered
    -- full-snapshot pushes can never reopen a port or revive a rotated token.
    ADD COLUMN IF NOT EXISTS preview_policy_revision bigint NOT NULL DEFAULT 0;

ALTER TABLE sandbox
    DROP CONSTRAINT IF EXISTS sandbox_preview_access_valid;

-- Defense in depth: a non-handler write path cannot invent a fourth state.
-- The proxy fails closed for unknown values, and the database rejects them.
ALTER TABLE sandbox
    ADD CONSTRAINT sandbox_preview_access_valid
    CHECK (preview_access IN ('legacy_public', 'public', 'private'));

COMMENT ON COLUMN sandbox.preview_access IS
    'Preview URL policy: ''legacy_public'' preserves pre-publication all-port '
    'routing; ''public'' and ''private'' require publication, with private '
    'token-gated. Callers may select public/private at create and via PATCH.';

-- One row per explicitly published preview port. A port is reachable on a
-- strict public/private sandbox only if it has a row here. token_version is the per-port
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
    'Explicitly published preview ports for strict public/private sandboxes. Presence of a '
    'row is what makes a port routable at the edge; token_version is the '
    'per-port credential generation used for independent rotation.';
