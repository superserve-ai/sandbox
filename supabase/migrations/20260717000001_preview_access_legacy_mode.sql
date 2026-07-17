-- Preserve the pre-publication routing contract for rows created before
-- strict public/private preview policies required explicit port publication.
-- This follow-up is intentionally separate because the feature migration may
-- already have been exercised in a non-production environment.
ALTER TABLE sandbox
    DROP CONSTRAINT IF EXISTS sandbox_preview_access_valid;

UPDATE sandbox
SET preview_access = 'legacy_public'
WHERE preview_access = 'public';

ALTER TABLE sandbox
    ALTER COLUMN preview_access SET DEFAULT 'legacy_public';

ALTER TABLE sandbox
    ADD CONSTRAINT sandbox_preview_access_valid
    CHECK (preview_access IN ('legacy_public', 'public', 'private'));

COMMENT ON COLUMN sandbox.preview_access IS
    'Preview URL policy: legacy_public preserves pre-publication all-port '
    'routing; public and private require publication, with private token-gated. '
    'Callers may select public/private at create and via PATCH.';
