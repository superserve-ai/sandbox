BEGIN;

-- The signed creation mode authorizes the creation flow, but never decides
-- promotion eligibility. The canonical claim authority remains the sole
-- source of grant/no-grant outcomes for both creation modes.
CREATE FUNCTION create_team_with_signup_trial(
    p_name text,
    p_user_id uuid,
    p_home_region text,
    p_policy_mode text
)
RETURNS team
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
DECLARE
    created_team team;
BEGIN
    IF p_user_id IS NULL THEN
        RAISE EXCEPTION 'signup trial requires a creator' USING ERRCODE = '22023';
    END IF;
    IF p_policy_mode IS NULL OR p_policy_mode NOT IN ('first_team', 'additional_team') THEN
        RAISE EXCEPTION 'unsupported team creation policy' USING ERRCODE = '22023';
    END IF;
    INSERT INTO team(name, home_region)
    VALUES (p_name, p_home_region)
    RETURNING * INTO created_team;
    PERFORM claim_team_signup_trial_with_device(created_team.id, p_user_id);
    DELETE FROM team_signup_trial_provenance WHERE team_id = created_team.id;
    RETURN created_team;
END;
$$;

REVOKE ALL ON FUNCTION create_team_with_signup_trial(text, uuid, text, text) FROM PUBLIC;
DO $$
DECLARE restricted_role text;
BEGIN
    FOREACH restricted_role IN ARRAY ARRAY['anon', 'authenticated'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = restricted_role) THEN
            EXECUTE format('REVOKE ALL ON FUNCTION create_team_with_signup_trial(text, uuid, text, text) FROM %I', restricted_role);
        END IF;
    END LOOP;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
        GRANT EXECUTE ON FUNCTION create_team_with_signup_trial(text, uuid, text, text) TO service_role;
    END IF;
END;
$$;

COMMIT;
