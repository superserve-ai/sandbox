-- Promotion policy failures may deny only the promotion. Paid activation and
-- legacy callers must never be able to mint a grant without a pinned actor.
CREATE OR REPLACE FUNCTION finalize_stripe_promotion(p_team_id uuid, p_user_id uuid, p_stripe_grant_id text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE v_account team_billing_account; v_history_key text;
BEGIN
    IF NULLIF(BTRIM(p_stripe_grant_id), '') IS NULL THEN
        RETURN;
    END IF;
    IF p_user_id IS NULL THEN
        RAISE EXCEPTION 'Stripe promotion finalization requires a pinned actor reservation'
            USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    PERFORM lock_stripe_promotion(p_team_id, p_user_id);
    SELECT * INTO v_account FROM team_billing_account WHERE team_id = p_team_id FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;
    IF v_account.stripe_activation_credit_grant_id IS NOT NULL
       OR v_account.stripe_activation_credit_granted_at IS NOT NULL THEN RETURN; END IF;
    IF v_account.stripe_activation_user_id IS DISTINCT FROM p_user_id
       OR v_account.stripe_activation_identity_key IS NULL
       OR NOT EXISTS (
           SELECT 1 FROM promotion_identity i
           WHERE i.identity_key = v_account.stripe_activation_identity_key
             AND i.stripe_reserved_team_id = p_team_id AND i.stripe_reserved_user_id = p_user_id
       ) THEN
        RAISE EXCEPTION 'Stripe promotion finalization requires its pinned reservation'
            USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    UPDATE promotion_identity
    SET stripe_redemption_at = COALESCE(stripe_redemption_at, now()),
        stripe_reserved_team_id = NULL, stripe_reserved_user_id = NULL
    WHERE identity_key = v_account.stripe_activation_identity_key;
    UPDATE user_promotion_entitlement
    SET stripe_redemption_at = COALESCE(stripe_redemption_at, now()),
        stripe_redemption_team_id = p_team_id,
        stripe_redemption_reserved_team_id = NULL, stripe_redemption_reserved_at = NULL,
        stripe_redemption_attempted_at = NULL, updated_at = now()
    WHERE user_id = p_user_id AND stripe_redemption_reserved_team_id = p_team_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Stripe promotion user reservation is missing'
            USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    UPDATE team_billing_account
    SET stripe_activation_credit_granted_at = now(), stripe_activation_credit_grant_id = p_stripe_grant_id,
        stripe_activation_credit_reserved_at = NULL, updated_at = now()
    WHERE team_id = p_team_id;
    IF v_account.stripe_activation_identity_key LIKE 'legacy:%' THEN
        v_history_key := 'stripe-transition:' || p_team_id::text || ':' || COALESCE(v_account.stripe_activation_credit_reservation_event_id, '');
        IF NOT EXISTS (SELECT 1 FROM promotion_identity_history WHERE history_key = v_history_key) THEN
            v_history_key := 'stripe-user:' || p_user_id::text;
        END IF;
        PERFORM record_promotion_identity_grant(v_history_key, 'stripe', p_user_id, p_team_id, now(), v_account.stripe_activation_identity_evidence_version);
    END IF;
    PERFORM record_stripe_promotion_device_grant(p_team_id, p_user_id);
    IF NOT EXISTS (SELECT 1 FROM team_credit_grant WHERE team_id = p_team_id AND reason = 'signup trial credit') THEN
        INSERT INTO team_credit_grant(team_id, amount_usd, remaining_usd, reason, created_by)
        VALUES (p_team_id, 95, 0, 'stripe promotional credit', p_user_id);
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION activate_team_billing(p_team_id uuid, p_user_id uuid, p_stripe_grant_id text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE v_settled boolean; v_account team_billing_account;
BEGIN
    SELECT stripe_activation_credit_reserved_at IS NULL
        AND (NULLIF(stripe_activation_credit_grant_id, '') IS NOT NULL
             OR stripe_activation_credit_granted_at IS NOT NULL)
    INTO v_settled FROM team_billing_account WHERE team_id = p_team_id;
    IF NULLIF(BTRIM(p_stripe_grant_id), '') IS NOT NULL AND NOT COALESCE(v_settled, false) THEN
        IF p_user_id IS NULL THEN
            RAISE EXCEPTION 'Stripe promotion activation requires a pinned actor reservation'
                USING ERRCODE = 'object_not_in_prerequisite_state';
        END IF;
        PERFORM lock_stripe_promotion(p_team_id, p_user_id);
    END IF;
    SELECT * INTO v_account FROM team_billing_account WHERE team_id = p_team_id FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;
    IF v_settled AND (v_account.stripe_activation_credit_reserved_at IS NOT NULL
        OR (NULLIF(v_account.stripe_activation_credit_grant_id, '') IS NULL
            AND v_account.stripe_activation_credit_granted_at IS NULL)) THEN
        RAISE EXCEPTION 'Stripe promotion settlement changed before paid activation'
            USING ERRCODE = 'serialization_failure';
    END IF;
    UPDATE team_billing_account
    SET trial_ended_at = COALESCE(trial_ended_at, now()), updated_at = now()
    WHERE team_id = p_team_id
      AND lower(coalesce(stripe_subscription_status, '')) IN ('active', 'trialing', 'past_due');
    IF NOT FOUND THEN RETURN; END IF;
    UPDATE team_credit_grant SET remaining_usd = 0, updated_at = now()
    WHERE team_id = p_team_id AND reason = 'signup trial credit';
    IF NULLIF(BTRIM(p_stripe_grant_id), '') IS NOT NULL AND NOT COALESCE(v_settled, false) THEN
        PERFORM finalize_stripe_promotion(p_team_id, p_user_id, p_stripe_grant_id);
    END IF;
END;
$$;

-- Keep the compatibility overload usable for paid-only activation, but make
-- any attempt to settle a promotion without an actor fail closed.
CREATE OR REPLACE FUNCTION activate_team_billing(p_team_id uuid, p_stripe_grant_id text)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    IF NULLIF(BTRIM(p_stripe_grant_id), '') IS NOT NULL THEN
        RAISE EXCEPTION 'legacy Stripe promotion activation requires a pinned actor reservation'
            USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    PERFORM activate_team_billing(p_team_id, NULL::uuid, p_stripe_grant_id);
END;
$$;

-- Never inherit EXECUTE from PUBLIC/default privileges for server-owned writers.
DO $$
DECLARE r text; f text;
BEGIN
    FOREACH f IN ARRAY ARRAY[
        'claim_team_signup_trial(uuid,uuid)',
        'claim_team_signup_trial_with_device(uuid,uuid)',
        'reserve_stripe_promotion_with_device(uuid,uuid,text,text,timestamptz,boolean)',
        'reserve_stripe_promotion_for_subscription_event_state_without_device(uuid,uuid,text,text,timestamptz,boolean)',
        'reserve_stripe_promotion_for_event_state(uuid,uuid,text)',
        'reserve_stripe_promotion_for_subscription_event_state(uuid,uuid,text,text,timestamptz,boolean)',
        'reserve_stripe_promotion_for_event(uuid,uuid,text)',
        'reserve_stripe_promotion(uuid,uuid)',
        'release_stripe_promotion_for_event(uuid,uuid,text)',
        'release_stripe_promotion(uuid,uuid)',
        'finalize_stripe_promotion(uuid,uuid,text)',
        'activate_team_billing(uuid,uuid,text)',
        'activate_team_billing(uuid,text)'
    ] LOOP
        EXECUTE 'REVOKE ALL ON FUNCTION ' || f || ' FROM PUBLIC';
        FOREACH r IN ARRAY ARRAY['anon','authenticated'] LOOP
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
                EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I', f, r);
            END IF;
        END LOOP;
    END LOOP;
END $$;

-- Grant-write contention and provisioning failures remain retryable. Only the
-- grant authority's explicit 55000 failure becomes a durable no-credit decision.
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
    IF EXISTS (SELECT 1 FROM team_promotion_creation_attempt a
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
