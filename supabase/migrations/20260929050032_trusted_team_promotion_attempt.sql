-- Retain attempt bindings and original results even after team/account deletion.
CREATE TABLE team_promotion_creation_attempt (
    attempt_id uuid PRIMARY KEY,
    team_id uuid NOT NULL UNIQUE,
    user_id uuid NOT NULL,
    name text NOT NULL,
    home_region text NOT NULL,
    authority_unavailable boolean NOT NULL,
    outcome text,
    reason text,
    created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE team_promotion_creation_attempt ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON team_promotion_creation_attempt FROM PUBLIC;
DO $$ DECLARE r text; BEGIN
    FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname=r) THEN
            EXECUTE format('REVOKE ALL ON team_promotion_creation_attempt FROM %I',r);
        END IF;
    END LOOP;
END $$;

CREATE OR REPLACE FUNCTION claim_team_signup_trial_with_device(p_team_id uuid, p_user_id uuid)
RETURNS TABLE(outcome text, reason text) LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_reason text; v_fingerprint text; v_outcome text; v_claim_reason text; v_actor uuid;
    v_provenance team_signup_trial_provenance;
BEGIN
    PERFORM 1 FROM team WHERE id = p_team_id FOR NO KEY UPDATE NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'signup team does not exist' USING ERRCODE = '22023'; END IF;
    SELECT o.user_id, o.outcome, o.reason INTO v_actor, v_outcome, v_claim_reason
        FROM team_signup_promotion_outcome o WHERE o.team_id = p_team_id;
    IF FOUND THEN
        IF v_actor <> p_user_id THEN
            RAISE EXCEPTION 'signup trial creator cannot change' USING ERRCODE = '22023';
        END IF;
        RETURN QUERY SELECT v_outcome, v_claim_reason;
        RETURN;
    END IF;
    SELECT * INTO v_provenance FROM team_signup_trial_provenance
        WHERE team_id = p_team_id FOR UPDATE;
    IF NOT FOUND OR v_provenance.completed_at IS NOT NULL THEN
        RETURN QUERY SELECT 'promotion_ineligible'::text, 'not_initial_creation'::text;
        RETURN;
    END IF;
    IF v_provenance.creator_bound_at IS NOT NULL
       AND v_provenance.creator_user_id IS DISTINCT FROM p_user_id THEN
        RAISE EXCEPTION 'signup trial creator cannot change' USING ERRCODE = '22023';
    END IF;
    IF p_user_id IS NULL THEN RAISE EXCEPTION 'signup trial requires a creator' USING ERRCODE = '22023'; END IF;
    IF EXISTS (SELECT 1 FROM team_promotion_creation_attempt a
        WHERE a.team_id=p_team_id AND a.user_id=p_user_id AND a.authority_unavailable) THEN
        v_reason := 'authority_unavailable';
    ELSE
        SET LOCAL lock_timeout = '5s';
        PERFORM pg_advisory_xact_lock(hashtext('stripe-promo-user:' || p_user_id::text)::bigint);
        PERFORM pg_advisory_xact_lock(hashtext('promotion-device-user:' || p_user_id::text)::bigint);
        BEGIN
            -- This read-only decision can time out on the policy row before any grant.
            v_reason := promotion_device_decision(p_user_id, 'signup');
        EXCEPTION WHEN SQLSTATE '55000' OR SQLSTATE '55P03' OR no_data_found THEN
            v_reason := 'authority_unavailable';
        END;
    END IF;
    IF v_reason <> 'eligible' THEN
        IF v_provenance.legacy_grant_id IS NULL THEN
            INSERT INTO team_signup_trial_denial(team_id) VALUES(p_team_id) ON CONFLICT DO NOTHING;
        END IF;
        INSERT INTO team_signup_promotion_outcome(team_id, user_id, outcome, reason)
            VALUES(p_team_id, p_user_id, 'promotion_ineligible', v_reason);
        UPDATE team_signup_trial_provenance SET creator_user_id = p_user_id,
            creator_bound_at = COALESCE(creator_bound_at, now()), completed_at = now()
            WHERE team_id = p_team_id;
        RETURN QUERY SELECT 'promotion_ineligible'::text, v_reason;
        RETURN;
    END IF;
    BEGIN
        SELECT c.outcome, c.reason INTO v_outcome, v_claim_reason
            FROM claim_team_signup_trial_without_device(p_team_id, p_user_id) c;
    EXCEPTION WHEN SQLSTATE '55000' OR no_data_found THEN
        -- 55000 also matches its SQLSTATE class, including retryable lock errors.
        IF SQLSTATE NOT IN ('55000', 'P0002') THEN RAISE; END IF;
        v_outcome := 'promotion_ineligible';
        v_claim_reason := 'authority_unavailable';
        IF v_provenance.legacy_grant_id IS NULL THEN
            INSERT INTO team_signup_trial_denial(team_id) VALUES(p_team_id) ON CONFLICT DO NOTHING;
        END IF;
        INSERT INTO team_signup_promotion_outcome(team_id, user_id, outcome, reason)
            VALUES(p_team_id, p_user_id, v_outcome, v_claim_reason);
        UPDATE team_signup_trial_provenance SET creator_user_id = p_user_id,
            creator_bound_at = COALESCE(creator_bound_at, now()), completed_at = now()
            WHERE team_id = p_team_id;
        RETURN QUERY SELECT v_outcome, v_claim_reason;
        RETURN;
    END;
    IF v_outcome = 'granted' THEN
        SELECT e.fingerprint INTO v_fingerprint FROM promotion_signup_device_evidence e WHERE e.user_id = p_user_id;
        INSERT INTO promotion_device_grant(promotion, user_id, team_id, fingerprint)
            VALUES('signup', p_user_id, p_team_id, v_fingerprint) ON CONFLICT DO NOTHING;
    END IF;
    RETURN QUERY SELECT v_outcome, v_claim_reason;
END $$;
REVOKE ALL ON FUNCTION claim_team_signup_trial_with_device(uuid,uuid) FROM PUBLIC;
DO $$ DECLARE r text; BEGIN
    FOREACH r IN ARRAY ARRAY['anon','authenticated'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
            EXECUTE format('REVOKE ALL ON FUNCTION claim_team_signup_trial_with_device(uuid,uuid) FROM %I', r);
        END IF;
    END LOOP;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
        GRANT EXECUTE ON FUNCTION claim_team_signup_trial_with_device(uuid,uuid) TO service_role;
    END IF;
END $$;

CREATE FUNCTION create_team_with_promotion_attempt(p_attempt_id uuid, p_team_id uuid,
    p_user_id uuid, p_name text, p_home_region text, p_authority_unavailable boolean)
RETURNS TABLE(team_id uuid, outcome text, reason text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_attempt team_promotion_creation_attempt; v_outcome text; v_reason text;
BEGIN
    IF p_attempt_id IS NULL OR p_team_id IS NULL OR p_user_id IS NULL
       OR NULLIF(BTRIM(p_name),'') IS NULL OR p_home_region NOT IN ('use','usw')
       OR p_home_region IS NULL OR p_authority_unavailable IS NULL THEN
        RAISE EXCEPTION 'invalid team creation attempt' USING ERRCODE='22023';
    END IF;
    INSERT INTO team_promotion_creation_attempt(attempt_id,team_id,user_id,name,home_region,authority_unavailable)
        VALUES(p_attempt_id,p_team_id,p_user_id,p_name,p_home_region,p_authority_unavailable)
        ON CONFLICT (attempt_id) DO NOTHING;
    SELECT * INTO STRICT v_attempt FROM team_promotion_creation_attempt a
        WHERE a.attempt_id=p_attempt_id FOR UPDATE;
    IF v_attempt.team_id<>p_team_id OR v_attempt.user_id<>p_user_id OR v_attempt.name<>p_name
       OR v_attempt.home_region<>p_home_region OR v_attempt.authority_unavailable<>p_authority_unavailable THEN
        RAISE EXCEPTION 'team creation attempt cannot change' USING ERRCODE='22023';
    END IF;
    IF v_attempt.outcome IS NOT NULL THEN
        RETURN QUERY SELECT v_attempt.team_id,v_attempt.outcome,v_attempt.reason;
        RETURN;
    END IF;
    -- An existing team is never adopted by a new attempt.
    INSERT INTO team(id,name,home_region) VALUES(p_team_id,p_name,p_home_region);
    SELECT c.outcome,c.reason INTO STRICT v_outcome,v_reason
        FROM claim_team_signup_trial(p_team_id,p_user_id) c;
    DELETE FROM team_signup_trial_provenance WHERE team_signup_trial_provenance.team_id=p_team_id;
    UPDATE team_promotion_creation_attempt a SET outcome=v_outcome,reason=v_reason
        WHERE a.attempt_id=p_attempt_id;
    RETURN QUERY SELECT p_team_id,v_outcome,v_reason;
END $$;
REVOKE ALL ON FUNCTION create_team_with_promotion_attempt(uuid,uuid,uuid,text,text,boolean) FROM PUBLIC;
DO $$ DECLARE r text; BEGIN
    FOREACH r IN ARRAY ARRAY['anon','authenticated'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname=r) THEN
            EXECUTE format('REVOKE ALL ON FUNCTION create_team_with_promotion_attempt(uuid,uuid,uuid,text,text,boolean) FROM %I',r);
        END IF;
    END LOOP;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN
        GRANT EXECUTE ON FUNCTION create_team_with_promotion_attempt(uuid,uuid,uuid,text,text,boolean) TO service_role;
    END IF;
END $$;
