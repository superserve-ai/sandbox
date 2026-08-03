-- Read-only Postgres role for the Grafana dashboard connection, kept
-- distinct from the app's own database credentials (least privilege: no
-- app secrets end up in Grafana, and this role can't write or see schemas
-- outside analytics).
--
-- Grants target the analytics schema, not public: every public base table
-- has RLS enabled with no policy for this role, so a public grant would be
-- silently unreadable. analytics views are the dedicated reporting surface
-- (see 20260529000002_analytics_weekly_user_metrics.sql) and are not
-- security_invoker, so they run with the view owner's privileges and stay
-- readable through RLS.
--
-- Idempotent: re-running on a database that already has this role is a
-- no-op. The role is created with a random throwaway password — the actual
-- password used for the Grafana connection is set out-of-band (dashboard
-- SQL editor) and rotated independently of this migration, so no credential
-- ever lands in git history.

DO $$
DECLARE
    throwaway_password text := md5(random()::text || clock_timestamp()::text);
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'grafana_readonly') THEN
        EXECUTE format(
            'CREATE ROLE grafana_readonly WITH LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION',
            throwaway_password
        );
    END IF;
END
$$;

GRANT USAGE ON SCHEMA analytics TO grafana_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA analytics TO grafana_readonly;
ALTER DEFAULT PRIVILEGES IN SCHEMA analytics GRANT SELECT ON TABLES TO grafana_readonly;
