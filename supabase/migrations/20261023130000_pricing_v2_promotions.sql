-- Pricing v2 has no signup trial and no card bonus. Both promotions take
-- their existing "denied, no credit" paths while the switch is on v2. With
-- the switch on legacy nothing changes.

-- The $5 signup trial: every team-creation path claims through this function.
CREATE OR REPLACE FUNCTION claim_team_signup_trial_with_device(p_team_id uuid, p_user_id uuid)
RETURNS TABLE(outcome text, reason text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
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
    IF billing_pricing_version() = 'v2' THEN
        v_reason := 'pricing_v2';
    ELSIF EXISTS (SELECT 1 FROM team_promotion_creation_attempt a
        WHERE a.team_id = p_team_id AND a.user_id = p_user_id AND a.authority_unavailable) THEN
        v_reason := 'authority_unavailable';
    ELSE
        SET LOCAL lock_timeout = '5s';
        PERFORM pg_advisory_xact_lock(hashtext('stripe-promo-user:' || p_user_id::text)::bigint);
        PERFORM pg_advisory_xact_lock(hashtext('promotion-device-user:' || p_user_id::text)::bigint);
        BEGIN
            v_reason := promotion_device_decision(p_user_id, 'signup');
        EXCEPTION WHEN SQLSTATE '55000' OR no_data_found THEN
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
    EXCEPTION WHEN SQLSTATE '55000' THEN
        -- A class condition also catches retryable lock errors such as 55P03.
        IF SQLSTATE <> '55000' THEN RAISE; END IF;
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
END;
$$;

REVOKE ALL ON FUNCTION claim_team_signup_trial_with_device(uuid,uuid) FROM PUBLIC;
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
        REVOKE ALL ON FUNCTION claim_team_signup_trial_with_device(uuid,uuid) FROM anon;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
        REVOKE ALL ON FUNCTION claim_team_signup_trial_with_device(uuid,uuid) FROM authenticated;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
        GRANT EXECUTE ON FUNCTION claim_team_signup_trial_with_device(uuid,uuid) TO service_role;
    END IF;
END $$;

-- The $95 card bonus: every reservation goes through this function. A
-- reservation taken before v2 was switched on settles as it began, so
-- retries stay idempotent.
ALTER FUNCTION reserve_stripe_promotion_with_device(uuid,uuid,text,text,timestamptz,boolean)
    RENAME TO reserve_stripe_promotion_before_pricing_v2;
CREATE OR REPLACE FUNCTION reserve_stripe_promotion_with_device(p_team_id uuid, p_user_id uuid,
    p_event_id text, p_subscription_id text, p_checkout_generation timestamptz,
    p_has_checkout_generation boolean)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    SET LOCAL lock_timeout = '5s';
    PERFORM pg_advisory_xact_lock(hashtext('stripe-promo-user:' || COALESCE(p_user_id::text, ''))::bigint);
    IF billing_pricing_version() = 'v2'
       AND NOT EXISTS (SELECT 1 FROM team_billing_account
           WHERE team_id = p_team_id AND stripe_activation_credit_reserved_at IS NOT NULL) THEN
        RETURN 'pricing_v2';
    END IF;
    RETURN reserve_stripe_promotion_before_pricing_v2(p_team_id, p_user_id, p_event_id,
        p_subscription_id, p_checkout_generation, p_has_checkout_generation);
END $$;

ALTER TABLE stripe_promotion_outcome DROP CONSTRAINT stripe_promotion_outcome_reason_check;
ALTER TABLE stripe_promotion_outcome ADD CONSTRAINT stripe_promotion_outcome_reason_check
 CHECK (reason IN ('ineligible','user_already_redeemed','owner_conflict','device_already_redeemed',
 'evidence_missing','device_reservation_pending','authority_unavailable','sponsored_onboarding','pricing_v2'));

REVOKE ALL ON FUNCTION reserve_stripe_promotion_with_device(uuid,uuid,text,text,timestamptz,boolean),
    reserve_stripe_promotion_before_pricing_v2(uuid,uuid,text,text,timestamptz,boolean) FROM PUBLIC;
DO $$ DECLARE r text; BEGIN
    FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
            EXECUTE format('REVOKE ALL ON FUNCTION reserve_stripe_promotion_before_pricing_v2(uuid,uuid,text,text,timestamptz,boolean) FROM %I', r);
        END IF;
    END LOOP;
    FOREACH r IN ARRAY ARRAY['anon','authenticated'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
            EXECUTE format('REVOKE ALL ON FUNCTION reserve_stripe_promotion_with_device(uuid,uuid,text,text,timestamptz,boolean) FROM %I', r);
        END IF;
    END LOOP;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
        GRANT EXECUTE ON FUNCTION reserve_stripe_promotion_with_device(uuid,uuid,text,text,timestamptz,boolean) TO service_role;
    END IF;
END $$;
