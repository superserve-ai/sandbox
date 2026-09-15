-- Run as the database administrator before enabling proxy routing.
-- Credentials are provisioned separately; no password belongs in this file.
BEGIN;
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sandbox_proxy_router') THEN
        CREATE ROLE sandbox_proxy_router LOGIN NOINHERIT NOSUPERUSER NOCREATEDB
            NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 32;
    END IF;
END
$$;
ALTER ROLE sandbox_proxy_router SET default_transaction_read_only = on;
ALTER ROLE sandbox_proxy_router SET statement_timeout = '500ms';
GRANT USAGE ON SCHEMA public TO sandbox_proxy_router;
GRANT SELECT (id, host_id, destroyed_at) ON public.sandbox TO sandbox_proxy_router;
GRANT SELECT (id, vmd_addr, proxy_addr, incarnation_id, peer_generation, last_heartbeat_at)
    ON public.host TO sandbox_proxy_router;
DROP POLICY IF EXISTS proxy_routing_read ON public.sandbox;
CREATE POLICY proxy_routing_read ON public.sandbox FOR SELECT
    TO sandbox_proxy_router USING (true);
DROP POLICY IF EXISTS proxy_routing_read ON public.host;
CREATE POLICY proxy_routing_read ON public.host FOR SELECT
    TO sandbox_proxy_router USING (true);
COMMIT;
