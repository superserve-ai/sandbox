-- Read-only Postgres role for the Grafana dashboard connection, kept
-- distinct from the app's own database credentials (least privilege: no
-- app secrets end up in Grafana, and this role can't write or see schemas
-- outside public).
--
-- Idempotent: re-running on a database that already has this role is a
-- no-op. The role is created with a random throwaway password — the actual
-- password used for the Grafana connection is set out-of-band (dashboard
-- SQL editor) and rotated independently of this migration, so no credential
-- ever lands in git history.

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'grafana_readonly') THEN
        CREATE ROLE grafana_readonly WITH LOGIN
            PASSWORD md5(random()::text || clock_timestamp()::text)
            NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO grafana_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO grafana_readonly;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO grafana_readonly;
