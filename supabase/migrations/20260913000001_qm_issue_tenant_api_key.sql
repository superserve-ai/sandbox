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
-- the member whose team role the request is checked against.
--
-- BLOCKER, and it is not solvable in this function: that makes the key
-- carry its creator's whole team role. The creator is usually an owner, and
-- internal/api aliases sandbox permissions onto settings:read/settings:write
-- (see rbac_phase3.go), so a tenant container whose SUPERSERVE_API_KEY leaks
-- can reach the team's secrets, templates and management endpoints — not
-- just the sandboxes it needs. The empty scope array does not help: ordinary
-- keys are authorized from created_by, not from scopes.
--
-- Closing it means giving sandbox endpoints a permission of their own and
-- enforcing it for the __qm_tenant__ key name, which is a change to the
-- shared auth path every control-plane request takes and belongs in its own
-- review. Do not run tenants in production until it lands. A secondary
-- consequence to fix with it: a tenant whose creator leaves the team loses
-- the ability to create sandboxes.
--
-- The key's name and its (empty) scopes are fixed here rather than passed
-- in: a definer function that let its caller choose them would hand qm_api
-- the ability to mint a key under any name with any scopes, which is a
-- larger privilege than the INSERT it is standing in for.
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
DROP FUNCTION IF EXISTS qm.issue_tenant_api_key(uuid, text);
CREATE FUNCTION qm.issue_tenant_api_key(
    tenant uuid,
    key_hash text
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

    -- The name and the scopes are the function's, not the caller's. A
    -- definer function that took them would let qm_api mint a key under a
    -- reserved name (the console's impersonation key, say) carrying
    -- whatever platform scopes it asked for — which is exactly the
    -- privilege this function exists to avoid granting.
    INSERT INTO public.api_key (team_id, key_hash, name, scopes, created_by)
    VALUES (target_team, key_hash, '__qm_tenant__', '{}'::text[], target_actor)
    RETURNING id INTO created;

    UPDATE qm.tenants SET sandbox_api_key_id = created, updated_at = now()
     WHERE id = tenant;

    RETURN created;
END;
$$;

REVOKE ALL ON FUNCTION qm.issue_tenant_api_key(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION qm.issue_tenant_api_key(uuid, text) TO qm_api;

COMMIT;
