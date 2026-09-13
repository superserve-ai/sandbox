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
-- The key inherits the tenant's creator as its actor, because that is how
-- the control plane resolves what a key may do: api_key.created_by names
-- the member whose team role the request is checked against. A tenant whose
-- creator later leaves the team therefore loses the ability to create
-- sandboxes; giving tenant keys a principal of their own is the follow-up,
-- and it belongs in the control plane's authorization, not here.
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
    target_actor uuid;
    existing uuid;
    created uuid;
BEGIN
    -- FOR UPDATE serializes two runs racing for the same tenant: the second
    -- blocks on the row, then finds the first one's key and returns it
    -- rather than issuing a duplicate. A deleted tenant, or one belonging
    -- to another team, matches nothing.
    SELECT t.team_id, t.created_by, t.sandbox_api_key_id
      INTO target_team, target_actor, existing
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

    -- The key inherits the tenant's creator as its actor. It has to have
    -- one: the control plane resolves a key's permissions through
    -- api_key.created_by, so a key with none authorizes nothing and the
    -- tenant it belongs to could not create a single sandbox with it.
    IF target_actor IS NULL THEN
        RAISE EXCEPTION 'qm tenant % has no creator to issue a sandbox key for', tenant
            USING ERRCODE = 'not_null_violation';
    END IF;

    INSERT INTO public.api_key (team_id, key_hash, name, scopes, created_by)
    VALUES (target_team, key_hash, key_name, COALESCE(key_scopes, '{}'::text[]), target_actor)
    RETURNING id INTO created;

    UPDATE qm.tenants SET sandbox_api_key_id = created, updated_at = now()
     WHERE id = tenant;

    RETURN created;
END;
$$;

REVOKE ALL ON FUNCTION qm.issue_tenant_api_key(uuid, text, text, text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION qm.issue_tenant_api_key(uuid, text, text, text[]) TO qm_api;

COMMIT;
