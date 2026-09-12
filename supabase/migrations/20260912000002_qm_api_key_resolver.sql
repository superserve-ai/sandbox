-- Authentication and authorization for the qm-api service.
--
-- qm_api authenticates the console's X-API-Key but is deliberately not
-- granted api_key.key_hash, and its row policy on api_key is team-scoped,
-- which is circular before the key has told us the team. Rather than widen
-- the grant, a definer function answers the one question the middleware
-- has: "which live key has this hash?". Presenting a hash is proof of
-- possession of the key, so the function exposes nothing a caller does not
-- already hold; there is no way to enumerate keys or hashes through it.
--
-- Authorization likewise stays in the RBAC tables qm_api cannot read: a
-- second definer function answers "may this member do this in this team?"
-- with the control plane's own team-permission query, so a key's holder
-- gets exactly the access their role grants and nothing else. A third
-- records key usage, the only api_key write the service makes.
--
-- Idempotent: functions are dropped and recreated (a return-type change
-- cannot go through OR REPLACE), grants are re-applied; safe to re-run.

BEGIN;

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '10s';

DROP FUNCTION IF EXISTS qm.resolve_api_key(text);
CREATE FUNCTION qm.resolve_api_key(candidate_hash text)
RETURNS TABLE (id uuid, team_id uuid, name text, scopes text[], created_by uuid)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
    SELECT k.id, k.team_id, k.name, k.scopes, k.created_by
    FROM public.api_key k
    WHERE k.key_hash = candidate_hash
      AND k.revoked_at IS NULL
      AND (k.expires_at IS NULL OR k.expires_at > now())
$$;

REVOKE ALL ON FUNCTION qm.resolve_api_key(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION qm.resolve_api_key(text) TO qm_api;

-- Mirrors internal/authz's team permission check (an active membership plus
-- an unrevoked team-scoped role carrying the permission). Keep the two in
-- step: a change to one is a change to the other.
DROP FUNCTION IF EXISTS qm.actor_can_team(uuid, uuid, text);
CREATE FUNCTION qm.actor_can_team(actor_id uuid, team uuid, permission text)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM public.user_role_assignments ura
        JOIN public.roles r
          ON r.id = ura.role_id
         AND r.scope_type = 'team'
        JOIN public.role_permissions rp
          ON rp.role_id = r.id
        JOIN public.permissions p
          ON p.id = rp.permission_id
        JOIN public.team_memberships tm
          ON tm.team_id = ura.team_id
         AND tm.user_id = ura.user_id
         AND tm.status = 'active'
        WHERE ura.user_id = actor_id
          AND ura.team_id = team
          AND ura.scope_type = 'team'
          AND ura.revoked_at IS NULL
          AND p.name = permission
    )
$$;

REVOKE ALL ON FUNCTION qm.actor_can_team(uuid, uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION qm.actor_can_team(uuid, uuid, text) TO qm_api;

-- Keeps api_key.last_used_at honest for keys used against qm-api, the one
-- write the control plane's auth makes; qm_api has no UPDATE on api_key,
-- and this touches only the row of a key the caller has already presented.
DROP FUNCTION IF EXISTS qm.touch_api_key(uuid);
CREATE FUNCTION qm.touch_api_key(key uuid)
RETURNS void
LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
    UPDATE public.api_key SET last_used_at = now() WHERE id = key
$$;

REVOKE ALL ON FUNCTION qm.touch_api_key(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION qm.touch_api_key(uuid) TO qm_api;

COMMIT;
