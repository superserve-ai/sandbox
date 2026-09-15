-- Canonical non-secret proxy routing authorization contract.
-- Credentials are provisioned separately; no password belongs in this file.
DO $$
DECLARE role_options text;
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sandbox_proxy_router') THEN
        CREATE ROLE sandbox_proxy_router LOGIN NOINHERIT NOSUPERUSER NOCREATEDB
            NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 32;
    END IF;
    -- Even a no-op NOSUPERUSER requires a superuser. Change only drifted flags
    -- so an ordinary role administrator can reapply an already-safe contract.
    SELECT concat_ws(' ',
        CASE WHEN NOT rolcanlogin THEN 'LOGIN' END,
        CASE WHEN rolinherit THEN 'NOINHERIT' END,
        CASE WHEN rolsuper THEN 'NOSUPERUSER' END,
        CASE WHEN rolcreatedb THEN 'NOCREATEDB' END,
        CASE WHEN rolcreaterole THEN 'NOCREATEROLE' END,
        CASE WHEN rolreplication THEN 'NOREPLICATION' END,
        CASE WHEN rolbypassrls THEN 'NOBYPASSRLS' END
    ) INTO role_options FROM pg_roles WHERE rolname = 'sandbox_proxy_router';
    IF role_options <> '' THEN
        EXECUTE 'ALTER ROLE sandbox_proxy_router ' || role_options;
    END IF;
END
$$;
ALTER ROLE sandbox_proxy_router SET default_transaction_read_only = on;
ALTER ROLE sandbox_proxy_router SET statement_timeout = '500ms';
GRANT USAGE ON SCHEMA public TO sandbox_proxy_router;
-- Table-level REVOKE also removes direct column grants; unrelated objects
-- and grants to other roles are untouched (no CASCADE).
REVOKE SELECT ON public.sandbox, public.host FROM sandbox_proxy_router;
GRANT SELECT (id, host_id, destroyed_at) ON public.sandbox TO sandbox_proxy_router;
GRANT SELECT (id, vmd_addr, proxy_addr, incarnation_id, peer_generation, last_heartbeat_at)
    ON public.host TO sandbox_proxy_router;
DROP POLICY IF EXISTS proxy_routing_read ON public.sandbox;
CREATE POLICY proxy_routing_read ON public.sandbox FOR SELECT
    TO sandbox_proxy_router USING (true);
DROP POLICY IF EXISTS proxy_routing_read ON public.host;
CREATE POLICY proxy_routing_read ON public.host FOR SELECT
    TO sandbox_proxy_router USING (true);
