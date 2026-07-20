-- Per-port preview access, host capabilities, and preview rollout flags.
--
-- 1. sandbox_published_port.access makes the published port the primary
--    policy resource: each port is independently 'public' (routes without a
--    token) or 'private' (requires that port's token). The sandbox-level
--    preview_access keeps two jobs — 'legacy_public' still means "route every
--    listening port" for pre-feature sandboxes, and for strict sandboxes it is
--    only the DEFAULT access applied to newly published ports. Enforcement is
--    per port.
--
--    Existing rows predate the column and were created under the sandbox-wide
--    model, so they inherit the mode they were enforced with: ports of a
--    'public' sandbox backfill to 'public', everything else to 'private'
--    (fail closed).
ALTER TABLE sandbox_published_port
    ADD COLUMN IF NOT EXISTS access text;

UPDATE sandbox_published_port p
SET access = CASE WHEN s.preview_access = 'public' THEN 'public' ELSE 'private' END
FROM sandbox s
WHERE p.sandbox_id = s.id
  AND p.access IS NULL;

ALTER TABLE sandbox_published_port
    ALTER COLUMN access SET NOT NULL,
    ALTER COLUMN access SET DEFAULT 'private';

ALTER TABLE sandbox_published_port
    DROP CONSTRAINT IF EXISTS sandbox_published_port_access_valid;

-- Defense in depth: no write path can invent a third per-port mode. The proxy
-- additionally treats any unknown value as 'private'.
ALTER TABLE sandbox_published_port
    ADD CONSTRAINT sandbox_published_port_access_valid
    CHECK (access IN ('public', 'private'));

COMMENT ON COLUMN sandbox_published_port.access IS
    'Per-port preview mode: ''public'' routes without a token, ''private'' '
    'requires this port''s token. The sandbox''s preview_access is only the '
    'default for newly published ports.';

-- 2. Host capability advertisement. vmd reports what its data plane actually
--    enforces on every heartbeat; the API refuses to enable a preview policy
--    on a sandbox whose host does not advertise the matching capability, so a
--    partially deployed fleet yields a failed API call instead of a recorded
--    security policy that nothing enforces. An old vmd sends no capabilities
--    and therefore cannot host strict-preview sandboxes.
ALTER TABLE host
    ADD COLUMN IF NOT EXISTS capabilities text[] NOT NULL DEFAULT '{}';

COMMENT ON COLUMN host.capabilities IS
    'Data-plane capabilities the host''s running vmd/proxy pair advertises via '
    'heartbeat (e.g. preview_ports_v1, preview_port_tokens_v1). The control '
    'plane rejects enabling a policy the assigned host cannot enforce.';

-- 3. Rollout flags. These gate ENABLEMENT only — whether callers may opt
--    sandboxes/ports into the new model (strict policies, publishing, token
--    minting). They never weaken enforcement: a port already recorded as
--    private stays token-gated at the proxy regardless of flag state, and
--    revocation (unpublish, rotate) always works. feature_enabled() resolves
--    team_feature_flag over feature_flag and defaults to FALSE, so the
--    feature ships dark and is enabled per environment/team.
INSERT INTO feature_flag (key, enabled, description)
VALUES
    ('preview_port_publication_enabled', false,
     'Allow opting sandboxes into strict preview policies and publishing preview ports.'),
    ('preview_port_private_access_enabled', false,
     'Allow private (token-gated) preview ports and minting preview tokens. Requires preview_port_publication_enabled.')
ON CONFLICT (key) DO NOTHING;
