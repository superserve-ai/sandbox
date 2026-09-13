-- Issuing a tenant's Superserve API key.
--
-- Every tenant's QM creates sandboxes with a key of its own, so the
-- provisioner has to mint one. qm_api has no INSERT on api_key and should
-- not get one: that would let a tenant's control-plane credentials create
-- keys for anything in the team. The counterpart to qm.revoke_tenant_api_key
-- is therefore a definer function that can only issue a key for a tenant the
-- caller's own team owns, and that points the tenant row at it in the same
-- statement.
--
-- The atomicity is the point. A provisioner that inserted the key and then
-- recorded the reference separately could die in between and leave a live,
-- unreferenced credential on the team — one nothing would ever revoke,
-- because teardown revokes only what the tenant row points at.
--
-- Idempotent in both senses: re-running the migration replaces the function,
-- and calling it for a tenant that already has a key returns that key
-- instead of issuing a second one.

BEGIN;

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '10s';

DROP FUNCTION IF EXISTS qm.issue_tenant_api_key(uuid, text, text, text[]);
CREATE FUNCTION qm.issue_tenant_api_key(
    tenant uuid,
    key_hash text,
    key_name text,
    key_scopes text[]
)
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    target_team uuid;
    existing uuid;
    created uuid;
BEGIN
    -- FOR UPDATE serializes two runs racing for the same tenant: the second
    -- blocks on the row, then finds the first one's key and returns it
    -- rather than issuing a duplicate. A deleted tenant, or one belonging
    -- to another team, matches nothing.
    SELECT t.team_id, t.sandbox_api_key_id
      INTO target_team, existing
      FROM qm.tenants t
     WHERE t.id = tenant
       AND t.team_id = qm.current_team_id()
       AND t.status <> 'deleted'
       FOR UPDATE;

    IF NOT FOUND THEN
        -- Distinguishable from any other failure so the caller can report
        -- "the tenant is gone" rather than a generic database error.
        RAISE EXCEPTION 'no live qm tenant % for this team', tenant
            USING ERRCODE = 'no_data_found';
    END IF;

    IF existing IS NOT NULL THEN
        RETURN existing;
    END IF;

    INSERT INTO public.api_key (team_id, key_hash, name, scopes)
    VALUES (target_team, key_hash, key_name, COALESCE(key_scopes, '{}'::text[]))
    RETURNING id INTO created;

    UPDATE qm.tenants SET sandbox_api_key_id = created, updated_at = now()
     WHERE id = tenant;

    RETURN created;
END;
$$;

REVOKE ALL ON FUNCTION qm.issue_tenant_api_key(uuid, text, text, text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION qm.issue_tenant_api_key(uuid, text, text, text[]) TO qm_api;

COMMIT;
