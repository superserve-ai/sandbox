-- Versions are assigned by the database so old writers also revoke moved routes.
ALTER TABLE public.sandbox ADD COLUMN routing_version bigint NOT NULL DEFAULT 1;
ALTER TABLE public.sandbox ADD CONSTRAINT sandbox_routing_version_positive CHECK (routing_version > 0) NOT VALID;

-- Deliberately no sandbox FK: hard deletion must not remove a revocation.
CREATE TABLE public.sandbox_routing_revocation (
    sandbox_id uuid NOT NULL,
    routing_version bigint NOT NULL,
    expires_at timestamptz,
    PRIMARY KEY (sandbox_id, routing_version)
);
CREATE INDEX sandbox_routing_revocation_expiry ON public.sandbox_routing_revocation (expires_at);
ALTER TABLE public.sandbox_routing_revocation ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.sandbox_routing_revocation FROM PUBLIC, anon, authenticated;
GRANT SELECT ON public.sandbox_routing_revocation TO sandbox_proxy_router;
CREATE POLICY routing_revocation_reader ON public.sandbox_routing_revocation FOR SELECT TO sandbox_proxy_router USING (true);

CREATE SCHEMA IF NOT EXISTS routing_private;
REVOKE ALL ON SCHEMA routing_private FROM PUBLIC;
CREATE OR REPLACE FUNCTION routing_private.revoke_sandbox_route() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        NEW.routing_version := 1;
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF OLD.destroyed_at IS NOT NULL AND NEW.destroyed_at IS NULL THEN
            RAISE EXCEPTION 'deleted sandboxes cannot be restored';
        END IF;
        NEW.routing_version := OLD.routing_version;
        IF NEW.host_id IS DISTINCT FROM OLD.host_id THEN
            NEW.routing_version := OLD.routing_version + 1;
        ELSIF NOT (OLD.destroyed_at IS NULL AND NEW.destroyed_at IS NOT NULL) THEN
            RETURN NEW;
        END IF;
    END IF;
    INSERT INTO public.sandbox_routing_revocation(sandbox_id, routing_version)
    VALUES (OLD.id, OLD.routing_version) ON CONFLICT DO NOTHING;
    PERFORM pg_notify('sandbox_routing_revoked', OLD.id::text || ':' || OLD.routing_version::text);
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION routing_private.revoke_sandbox_route() FROM PUBLIC;
CREATE TRIGGER sandbox_route_version BEFORE INSERT OR UPDATE OF host_id, destroyed_at, routing_version OR DELETE
ON public.sandbox FOR EACH ROW EXECUTE FUNCTION routing_private.revoke_sandbox_route();

-- A different transaction first observes committed revocations, then starts
-- retention. A long-running delete cannot consume its own retention window.
CREATE OR REPLACE FUNCTION routing_private.prune_revocations(observed_at timestamptz) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE db_now timestamptz := clock_timestamp();
BEGIN
    -- An independent control-plane clock guards clock-step recovery: do not
    -- remove fences merely because the database clock temporarily jumps ahead.
    IF observed_at IS NULL OR abs(extract(epoch FROM (db_now - observed_at))) > 60 THEN
        RAISE EXCEPTION 'routing retention requires synchronized clocks';
    END IF;
    UPDATE public.sandbox_routing_revocation SET expires_at = db_now + interval '2 hours'
    WHERE (sandbox_id, routing_version) IN (
        SELECT sandbox_id, routing_version FROM public.sandbox_routing_revocation
        WHERE expires_at IS NULL LIMIT 10000 FOR UPDATE SKIP LOCKED
    );
    DELETE FROM public.sandbox_routing_revocation WHERE (sandbox_id, routing_version) IN (
        SELECT sandbox_id, routing_version FROM public.sandbox_routing_revocation
        WHERE expires_at < db_now LIMIT 10000 FOR UPDATE SKIP LOCKED
    );
END $$;
REVOKE ALL ON FUNCTION routing_private.prune_revocations(timestamptz) FROM PUBLIC;
GRANT USAGE ON SCHEMA routing_private TO service_role;
GRANT EXECUTE ON FUNCTION routing_private.prune_revocations(timestamptz) TO service_role;

-- Four ownership sessions plus one background session per proxy. The default
-- supports six hosts with both serving generations present; keep custom limits.
DO $$ BEGIN
    IF (SELECT rolconnlimit FROM pg_roles WHERE rolname = 'sandbox_proxy_router') = 32 THEN
        ALTER ROLE sandbox_proxy_router CONNECTION LIMIT 64;
    END IF;
END $$;
