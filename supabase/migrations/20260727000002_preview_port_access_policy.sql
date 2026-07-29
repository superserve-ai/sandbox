-- Phase 2: each published preview port has an independent public/private mode.
--
-- Phase 1 publications were all public, so the backfill preserves their exact
-- behavior. sandbox_preview_policy.access remains the Phase 1-visible wire
-- fallback, while default_access is the true Phase 2 API/default value. The
-- fallback is maintained by triggers so a rolled-back control plane can never
-- turn a mixed public/private bool allowlist into public routing.

ALTER TABLE sandbox_preview_policy
    DROP CONSTRAINT sandbox_preview_policy_access_valid,
    ADD CONSTRAINT sandbox_preview_policy_access_valid
        CHECK (access IN ('legacy_public', 'public', 'private')),
    ADD COLUMN default_access text;

UPDATE sandbox_preview_policy
SET default_access = access;

ALTER TABLE sandbox_preview_policy
    ALTER COLUMN default_access SET NOT NULL,
    ADD CONSTRAINT sandbox_preview_policy_default_access_valid
        CHECK (default_access IN ('legacy_public', 'public', 'private'));

COMMENT ON TABLE sandbox_preview_policy IS
    'Preview routing policy. default_access is the API default for new ports; '
    'access is a restrictive Phase 1-compatible wire fallback.';

ALTER TABLE sandbox_published_port
    ADD COLUMN access text;

UPDATE sandbox_published_port
SET access = 'public';

ALTER TABLE sandbox_published_port
    ALTER COLUMN access SET NOT NULL,
    ADD CONSTRAINT sandbox_published_port_access_valid
        CHECK (access IN ('public', 'private'));

COMMENT ON COLUMN sandbox_published_port.access IS
    'Per-port preview mode. public routes directly; private stays closed until '
    'the later token-authentication phase can authorize requests.';

COMMENT ON TABLE sandbox_published_port IS
    'Explicitly published preview ports with independent public/private modes.';

CREATE FUNCTION maintain_sandbox_preview_policy_fallback()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    -- Phase 1 INSERT statements know only access. With no column default,
    -- omitted default_access arrives NULL and inherits that legacy value.
    IF TG_OP = 'INSERT' AND NEW.default_access IS NULL THEN
        NEW.default_access := NEW.access;
    END IF;

    -- Ignore direct writes to access (including a rolled-back Phase 1 PATCH)
    -- and recompute it from the true default plus current per-port state.
    IF NEW.default_access = 'private' OR EXISTS (
        SELECT 1
        FROM sandbox_published_port pp
        WHERE pp.sandbox_id = NEW.sandbox_id
          AND pp.access IS DISTINCT FROM 'public'
    ) THEN
        NEW.access := 'private';
    ELSIF NEW.default_access = 'legacy_public' THEN
        NEW.access := 'legacy_public';
    ELSE
        NEW.access := 'public';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER sandbox_preview_policy_maintain_fallback
BEFORE INSERT OR UPDATE ON sandbox_preview_policy
FOR EACH ROW EXECUTE FUNCTION maintain_sandbox_preview_policy_fallback();

CREATE FUNCTION default_sandbox_published_port_access()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    -- A Phase 1 INSERT omits access. Derive it from the true Phase 2 default;
    -- legacy_public normalizes to public because per-port modes are strict-only.
    IF NEW.access IS NULL THEN
        SELECT CASE WHEN p.default_access = 'private' THEN 'private' ELSE 'public' END
        INTO NEW.access
        FROM sandbox_preview_policy p
        WHERE p.sandbox_id = NEW.sandbox_id;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER sandbox_published_port_default_access
BEFORE INSERT ON sandbox_published_port
FOR EACH ROW EXECUTE FUNCTION default_sandbox_published_port_access();

CREATE FUNCTION refresh_sandbox_preview_policy_fallback()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_sandbox_id uuid;
BEGIN
    IF TG_OP = 'DELETE' THEN
        target_sandbox_id := OLD.sandbox_id;
    ELSE
        target_sandbox_id := NEW.sandbox_id;
    END IF;
    UPDATE sandbox_preview_policy
    SET access = access, updated_at = now()
    WHERE sandbox_id = target_sandbox_id;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER sandbox_published_port_refresh_fallback
AFTER INSERT OR UPDATE OF access OR DELETE ON sandbox_published_port
FOR EACH ROW EXECUTE FUNCTION refresh_sandbox_preview_policy_fallback();
