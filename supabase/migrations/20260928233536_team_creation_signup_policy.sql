BEGIN;

-- The signed creation mode can deny a grant even without a regional claim.
-- Existing overloads and legacy provisioning retain their eligibility rules.
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
    IF p_policy_mode = 'first_team' THEN
        INSERT INTO team(name, home_region)
        VALUES (p_name, p_home_region)
        RETURNING * INTO created_team;
        PERFORM claim_team_signup_trial_with_device(created_team.id, p_user_id);
        DELETE FROM team_signup_trial_provenance WHERE team_id = created_team.id;
        RETURN created_team;
    END IF;
    IF p_policy_mode IS DISTINCT FROM 'additional_team' THEN
        RAISE EXCEPTION 'unsupported team creation policy' USING ERRCODE = '22023';
    END IF;

    INSERT INTO team(name, home_region)
    VALUES (p_name, p_home_region)
    RETURNING * INTO created_team;
    INSERT INTO team_signup_trial_denial(team_id) VALUES(created_team.id);
    INSERT INTO team_signup_promotion_outcome(team_id, user_id, outcome, reason)
    VALUES(created_team.id, p_user_id, 'promotion_ineligible', 'additional_team');
    -- Retire the pending legacy claim before membership/RBAC triggers run.
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
