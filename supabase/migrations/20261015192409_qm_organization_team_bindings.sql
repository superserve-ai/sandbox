-- Installed explicitly on the central authority database by its deployment owner.
-- An empty or mismatched identity disables lookup as well as creation.
CREATE TABLE qm_team_service_authority (
    namespace text PRIMARY KEY CHECK (namespace ~ '^[a-z][a-z0-9-]{2,39}$'),
    authority_id uuid NOT NULL UNIQUE,
    home_region text NOT NULL CHECK (home_region IN ('use','usw'))
);
ALTER TABLE qm_team_service_authority ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON qm_team_service_authority FROM PUBLIC;
CREATE FUNCTION preserve_qm_team_service_authority() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$ BEGIN
    RAISE EXCEPTION 'team service authority is immutable' USING ERRCODE='23514';
END $$;
REVOKE ALL ON FUNCTION preserve_qm_team_service_authority() FROM PUBLIC;
CREATE TRIGGER qm_team_service_authority_immutable BEFORE UPDATE OR DELETE ON qm_team_service_authority
    FOR EACH ROW EXECUTE FUNCTION preserve_qm_team_service_authority();
CREATE TRIGGER qm_team_service_authority_no_truncate BEFORE TRUNCATE ON qm_team_service_authority
    FOR EACH STATEMENT EXECUTE FUNCTION preserve_qm_team_service_authority();
-- No team FK: a deleted team leaves permanent identity evidence, never a new create.
CREATE TABLE qm_organization_teams (
    namespace text NOT NULL CHECK (namespace ~ '^[a-z][a-z0-9-]{2,39}$'),
    qm_org_id uuid NOT NULL,
    idempotency_key text NOT NULL,
    authority_id uuid NOT NULL,
    team_id uuid NOT NULL UNIQUE,
    home_region text NOT NULL CHECK (home_region IN ('use','usw')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    deleted_at timestamptz,
    PRIMARY KEY(namespace, qm_org_id),
    CHECK (idempotency_key = 'qm-org:v1:' || qm_org_id::text)
);
ALTER TABLE qm_organization_teams ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON qm_organization_teams FROM PUBLIC;
DO $$ DECLARE r text; BEGIN
    FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname=r) THEN
            EXECUTE format('REVOKE ALL ON qm_organization_teams FROM %I',r);
            EXECUTE format('REVOKE ALL ON qm_team_service_authority FROM %I',r);
            IF r='service_role' THEN
                GRANT SELECT,INSERT ON qm_organization_teams TO service_role;
                CREATE POLICY qm_organization_teams_backend ON qm_organization_teams
                    TO service_role USING (true) WITH CHECK (true);
                GRANT SELECT ON qm_team_service_authority TO service_role;
                CREATE POLICY qm_team_service_authority_backend ON qm_team_service_authority
                    FOR SELECT TO service_role USING (true);
            END IF;
        END IF;
    END LOOP;
END $$;
CREATE FUNCTION preserve_qm_organization_team() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$ BEGIN
    IF TG_OP='UPDATE' AND (to_jsonb(NEW)-'deleted_at')=(to_jsonb(OLD)-'deleted_at')
       AND OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL THEN RETURN NEW; END IF;
    RAISE EXCEPTION 'organization team identity is permanent' USING ERRCODE='23514';
END $$;
REVOKE ALL ON FUNCTION preserve_qm_organization_team() FROM PUBLIC;
CREATE TRIGGER qm_organization_team_immutable BEFORE UPDATE OR DELETE ON qm_organization_teams
    FOR EACH ROW EXECUTE FUNCTION preserve_qm_organization_team();
CREATE TRIGGER qm_organization_team_no_truncate BEFORE TRUNCATE ON qm_organization_teams
    FOR EACH STATEMENT EXECUTE FUNCTION preserve_qm_organization_team();
CREATE FUNCTION tombstone_qm_organization_team() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$ BEGIN
    UPDATE public.qm_organization_teams SET deleted_at=clock_timestamp()
        WHERE team_id=OLD.id AND deleted_at IS NULL;
    RETURN OLD;
END $$;
REVOKE ALL ON FUNCTION tombstone_qm_organization_team() FROM PUBLIC;
CREATE TRIGGER qm_organization_team_deleted BEFORE DELETE ON team
    FOR EACH ROW EXECUTE FUNCTION tombstone_qm_organization_team();
