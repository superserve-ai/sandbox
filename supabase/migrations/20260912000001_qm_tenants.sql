-- qm schema: control-plane data model for hosted QM instances. One tenant
-- per customer team, each backed by its own QM stack (Cloud Run service,
-- database, bucket, service account). Kept out of public so the qm-api
-- service can run under a role that reaches nothing in public beyond the
-- few tables it needs to resolve team membership and the sandbox API key
-- a tenant was issued.
--
-- Idempotent: every object is created IF NOT EXISTS / OR REPLACE and the
-- role is guarded, so re-running on a database that already has the schema
-- is a no-op.

BEGIN;

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '10s';

CREATE SCHEMA IF NOT EXISTS qm;

-- Lets qm.tenants reference a key by (id, team_id) so a tenant can only ever
-- point at a sandbox API key owned by its own team; RLS does not take part in
-- foreign-key checks, so the constraint has to carry the team itself.
--
-- On a populated database this index must be pre-built CONCURRENTLY, by hand:
-- the migration runner wraps every file in a transaction, where CONCURRENTLY
-- cannot run, and a plain build blocks api_key writes (including
-- authentication's last_used_at updates) for the duration of the scan. Run
-- before merging:
--
--   CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS api_key_id_team_unique
--     ON public.api_key (id, team_id);
--
--   -- A failed concurrent build leaves an INVALID index that IF NOT EXISTS
--   -- would silently keep. Verify, and on false DROP INDEX + retry:
--   SELECT indisvalid FROM pg_index
--   WHERE indexrelid = 'api_key_id_team_unique'::regclass;
--
-- Pre-built, the statement below is a no-op; on a fresh or small database it
-- builds instantly. The timeouts above make a skipped pre-build fail the push
-- loudly with a bounded stall instead of blocking api_key writes.
DO $$
DECLARE
  actual_def text;
  expected_def text := 'CREATE UNIQUE INDEX api_key_id_team_unique ON public.api_key USING btree (id, team_id)';
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_index
    WHERE indexrelid = to_regclass('public.api_key_id_team_unique')
      AND NOT indisvalid
  ) THEN
    RAISE EXCEPTION 'api_key_id_team_unique exists but is INVALID (interrupted concurrent build); DROP INDEX api_key_id_team_unique, re-run the concurrent pre-build, then retry this push';
  END IF;

  SELECT pg_get_indexdef(oid) INTO actual_def
  FROM pg_class
  WHERE oid = to_regclass('public.api_key_id_team_unique');

  IF actual_def IS NOT NULL AND actual_def <> expected_def THEN
    RAISE WARNING 'api_key_id_team_unique exists with an unexpected definition; got %, expected %', actual_def, expected_def;
  END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS api_key_id_team_unique ON public.api_key (id, team_id);

CREATE TABLE IF NOT EXISTS qm.tenants (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id            uuid NOT NULL REFERENCES public.team(id),
    slug               text NOT NULL UNIQUE,
    org_name           text NOT NULL,
    admin_email        text NOT NULL,
    sign_in            text NOT NULL,
    model_provider     text NOT NULL,
    harness            text NOT NULL DEFAULT 'pi',
    status             text NOT NULL DEFAULT 'provisioning',
    public_url         text,
    image_tag          text,
    cloud_run_service  text,
    db_name            text,
    bucket_name        text,
    service_account    text,
    sandbox_api_key_id uuid,
    created_by         uuid REFERENCES public.profile(id),
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),

    -- The slug becomes a DNS label (subdomain), so it is held to RFC 1123
    -- label rules with a shorter 40-char ceiling to leave room for the
    -- environment prefix.
    CONSTRAINT qm_tenants_slug_dns_label
        CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$'),
    CONSTRAINT qm_tenants_sign_in_check
        CHECK (sign_in IN ('magic_link', 'slack')),
    CONSTRAINT qm_tenants_model_provider_check
        CHECK (model_provider IN ('anthropic', 'openai', 'openrouter')),
    CONSTRAINT qm_tenants_status_check
        CHECK (status IN ('provisioning', 'ready', 'failed', 'deprovisioning', 'deleted')),
    -- Expired keys are hard-deleted by the control plane's sweep; release the
    -- reference instead of blocking that sweep, leaving the team intact.
    CONSTRAINT qm_tenants_sandbox_api_key_team_fk
        FOREIGN KEY (sandbox_api_key_id, team_id) REFERENCES public.api_key (id, team_id)
        ON DELETE SET NULL (sandbox_api_key_id)
);

CREATE INDEX IF NOT EXISTS idx_qm_tenants_team ON qm.tenants(team_id);

-- One live stack per team for now; retired tenants do not count, so a team
-- can create again after deleting.
CREATE UNIQUE INDEX IF NOT EXISTS qm_tenants_one_active_per_team
    ON qm.tenants(team_id) WHERE status <> 'deleted';

CREATE TABLE IF NOT EXISTS qm.tenant_events (
    id        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES qm.tenants(id) ON DELETE CASCADE,
    step      text NOT NULL,
    status    text NOT NULL,
    message   text,
    detail    jsonb,
    -- clock_timestamp() so events written in one transaction still order.
    at        timestamptz NOT NULL DEFAULT clock_timestamp(),

    CONSTRAINT qm_tenant_events_status_check
        CHECK (status IN ('started', 'ok', 'failed', 'skipped'))
);

CREATE INDEX IF NOT EXISTS idx_qm_tenant_events_tenant_at ON qm.tenant_events(tenant_id, at);

-- secret_ref is a Secret Manager resource name, never a secret value; the
-- value only ever lives in Secret Manager and is resolved by the tenant's
-- own runtime identity.
CREATE TABLE IF NOT EXISTS qm.tenant_secrets (
    tenant_id  uuid NOT NULL REFERENCES qm.tenants(id) ON DELETE CASCADE,
    name       text NOT NULL,
    secret_ref text NOT NULL,
    PRIMARY KEY (tenant_id, name)
);

-- Application role for the qm-api service. Like grafana_readonly, it is
-- created with a throwaway password; the real password lives in Secret
-- Manager and is set out-of-band (ALTER ROLE qm_api PASSWORD ...), so no
-- credential lands in git history.
DO $$
DECLARE
    throwaway_password text := md5(random()::text || clock_timestamp()::text);
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'qm_api') THEN
        EXECUTE format(
            'CREATE ROLE qm_api WITH LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION',
            throwaway_password
        );
    END IF;
EXCEPTION WHEN duplicate_object THEN
    NULL;
END
$$;

-- Tenants are retired by status, never hard-deleted by the service, and the
-- event log is append-only; the grants say so rather than trusting the code.
GRANT USAGE ON SCHEMA qm TO qm_api;
GRANT SELECT, INSERT, UPDATE ON qm.tenants TO qm_api;
GRANT SELECT, INSERT ON qm.tenant_events TO qm_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON qm.tenant_secrets TO qm_api;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA qm TO qm_api;
ALTER DEFAULT PRIVILEGES IN SCHEMA qm GRANT USAGE, SELECT ON SEQUENCES TO qm_api;

-- The only public surface qm-api gets: enough to resolve a team, who is on
-- it, and the sandbox API key a tenant was issued. Nothing else in public
-- is granted, so e.g. SELECT on public.sandbox is a permission error.
GRANT USAGE ON SCHEMA public TO qm_api;
GRANT SELECT (id, name, created_at) ON public.team TO qm_api;
GRANT SELECT (id, team_id, user_id, status) ON public.team_memberships TO qm_api;
GRANT SELECT (id, team_id, name, expires_at, revoked_at, created_at) ON public.api_key TO qm_api;

-- Team scoping. qm_api has no BYPASSRLS (unlike the control plane's service
-- role), so it sees rows only for the team it has declared for the current
-- transaction via SELECT set_config('qm.team_id', <uuid>, true). With no
-- team declared, every qm table is empty and inserts are rejected, which
-- turns a forgotten scope into a visible failure rather than a leak.
CREATE OR REPLACE FUNCTION qm.current_team_id() RETURNS uuid
LANGUAGE sql STABLE
AS $$
    SELECT NULLIF(current_setting('qm.team_id', true), '')::uuid
$$;

-- Slug uniqueness spans every team, but qm_api's view of qm.tenants is
-- team-scoped, so the availability check runs as the definer to answer
-- for the whole table while exposing only a boolean.
CREATE OR REPLACE FUNCTION qm.slug_available(candidate text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
    SELECT NOT EXISTS (SELECT 1 FROM qm.tenants WHERE slug = candidate)
$$;

REVOKE ALL ON FUNCTION qm.slug_available(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION qm.slug_available(text) TO qm_api;

ALTER TABLE qm.tenants        ENABLE ROW LEVEL SECURITY;
ALTER TABLE qm.tenant_events  ENABLE ROW LEVEL SECURITY;
ALTER TABLE qm.tenant_secrets ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS qm_api_team_scope ON qm.tenants;
CREATE POLICY qm_api_team_scope ON qm.tenants
    FOR ALL TO qm_api
    USING (team_id = qm.current_team_id())
    WITH CHECK (team_id = qm.current_team_id());

DROP POLICY IF EXISTS qm_api_team_scope ON qm.tenant_events;
CREATE POLICY qm_api_team_scope ON qm.tenant_events
    FOR ALL TO qm_api
    USING (EXISTS (
        SELECT 1 FROM qm.tenants t
        WHERE t.id = tenant_id AND t.team_id = qm.current_team_id()
    ))
    WITH CHECK (EXISTS (
        SELECT 1 FROM qm.tenants t
        WHERE t.id = tenant_id AND t.team_id = qm.current_team_id()
    ));

DROP POLICY IF EXISTS qm_api_team_scope ON qm.tenant_secrets;
CREATE POLICY qm_api_team_scope ON qm.tenant_secrets
    FOR ALL TO qm_api
    USING (EXISTS (
        SELECT 1 FROM qm.tenants t
        WHERE t.id = tenant_id AND t.team_id = qm.current_team_id()
    ))
    WITH CHECK (EXISTS (
        SELECT 1 FROM qm.tenants t
        WHERE t.id = tenant_id AND t.team_id = qm.current_team_id()
    ));

-- Public tables have RLS enabled with no policy for qm_api, so the SELECT
-- grants above would be silently empty without these. Membership lookups
-- happen before a team is known (which teams is this user on?), so
-- team_memberships and team are readable outright; api_key stays team-scoped
-- because qm-api only ever resolves a key inside a tenant's team.
DROP POLICY IF EXISTS qm_api_read ON public.team;
CREATE POLICY qm_api_read ON public.team
    FOR SELECT TO qm_api
    USING (true);

DROP POLICY IF EXISTS qm_api_read ON public.team_memberships;
CREATE POLICY qm_api_read ON public.team_memberships
    FOR SELECT TO qm_api
    USING (true);

DROP POLICY IF EXISTS qm_api_read ON public.api_key;
CREATE POLICY qm_api_read ON public.api_key
    FOR SELECT TO qm_api
    USING (team_id = qm.current_team_id());

COMMIT;
