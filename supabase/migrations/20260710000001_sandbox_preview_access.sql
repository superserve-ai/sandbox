-- Preview URL authentication. preview_access gates the edge proxy's
-- numeric-port routes ({port}-{id}.<domain>): 'public' preserves today's
-- unauthenticated behavior; 'private' requires a preview token minted by the
-- control plane. preview_token_version is the token generation — rotating it
-- invalidates every previously minted preview token for the sandbox.
--
-- The proxy never reads this table: both values are carried onto the vmd
-- instance record (RestoreSnapshot / UpdateSandboxPreviewPolicy) and served
-- to the proxy by vmd's local /instances endpoint. The DB row is the intent;
-- the vmd record is the enforcement copy.
ALTER TABLE sandbox
    ADD COLUMN IF NOT EXISTS preview_access text NOT NULL DEFAULT 'public',
    ADD COLUMN IF NOT EXISTS preview_token_version integer NOT NULL DEFAULT 1;

ALTER TABLE sandbox
    DROP CONSTRAINT IF EXISTS sandbox_preview_access_valid;

-- Defense in depth: a non-handler write path can't invent a third state that
-- the proxy would fail closed on (any non-'private' value is treated as
-- public by the proxy, so a typo'd value would silently expose a sandbox —
-- reject it at the schema instead).
ALTER TABLE sandbox
    ADD CONSTRAINT sandbox_preview_access_valid
    CHECK (preview_access IN ('public', 'private'));

ALTER TABLE sandbox
    DROP CONSTRAINT IF EXISTS sandbox_preview_token_version_valid;

-- The proxy fails closed on version <= 0; keep the column always mintable.
ALTER TABLE sandbox
    ADD CONSTRAINT sandbox_preview_token_version_valid
    CHECK (preview_token_version >= 1);

COMMENT ON COLUMN sandbox.preview_access IS
    'Preview URL access policy: ''public'' (unauthenticated, the default) or '
    '''private'' (requires a preview token at the edge proxy). Settable at '
    'create and via PATCH.';
COMMENT ON COLUMN sandbox.preview_token_version IS
    'Preview token generation. Tokens embed this version; bumping it '
    '(POST /sandboxes/:id/preview-token/rotate) revokes all outstanding ones.';
