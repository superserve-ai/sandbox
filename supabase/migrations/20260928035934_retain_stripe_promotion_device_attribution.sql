CREATE OR REPLACE FUNCTION finalize_stripe_promotion(p_team_id uuid, p_user_id uuid, p_stripe_grant_id text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE v_account team_billing_account; v_history_key text;
BEGIN
    PERFORM lock_stripe_promotion(p_team_id, p_user_id);
    SELECT * INTO v_account FROM team_billing_account WHERE team_id = p_team_id FOR UPDATE;
    IF NOT FOUND OR NULLIF(BTRIM(p_stripe_grant_id), '') IS NULL THEN RETURN; END IF;
    IF v_account.stripe_activation_credit_grant_id IS NOT NULL
       OR v_account.stripe_activation_credit_granted_at IS NOT NULL THEN RETURN; END IF;
    IF p_user_id IS NULL THEN
        UPDATE team_billing_account
        SET stripe_activation_credit_granted_at = now(), stripe_activation_credit_grant_id = p_stripe_grant_id,
            stripe_activation_credit_reserved_at = NULL, updated_at = now()
        WHERE team_id = p_team_id;
        PERFORM record_promotion_identity_grant('stripe-team:' || p_team_id::text,
            'stripe', NULL, p_team_id, now(), NULL);
        RETURN;
    END IF;
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
    SET stripe_redemption_at = COALESCE(stripe_redemption_at, now()), stripe_redemption_team_id = p_team_id,
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
        PERFORM record_promotion_identity_grant(v_history_key,
            'stripe', p_user_id, p_team_id, now(), v_account.stripe_activation_identity_evidence_version);
    END IF;
    -- Keep actor attribution after profile deletion, including evidence-free grants.
    PERFORM record_stripe_promotion_device_grant(p_team_id, p_user_id);
    IF NOT EXISTS (SELECT 1 FROM team_credit_grant WHERE team_id = p_team_id AND reason = 'signup trial credit') THEN
        INSERT INTO team_credit_grant(team_id, amount_usd, remaining_usd, reason, created_by)
        VALUES (p_team_id, 95, 0, 'stripe promotional credit', p_user_id);
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION promotion_device_decision(p_user_id uuid, p_promotion text)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_policy promotion_device_policy; v_evidence promotion_signup_device_evidence; v_owner uuid; v_canonical boolean; v_stripe_decision text;
BEGIN
    IF p_user_id IS NULL OR p_promotion IS NULL OR p_promotion NOT IN ('signup', 'stripe') THEN
        RAISE EXCEPTION 'invalid promotion device decision' USING ERRCODE = '22023';
    END IF;
    v_canonical := canonical_promotion_identity_enabled();
    SELECT * INTO STRICT v_policy FROM promotion_device_policy WHERE singleton FOR SHARE;
    IF NOT v_canonical AND (v_policy.device_enforced OR v_policy.evidence_required) THEN
        RAISE EXCEPTION 'invalid promotion device configuration' USING ERRCODE = '55000';
    END IF;
    SELECT * INTO v_evidence FROM promotion_signup_device_evidence WHERE user_id = p_user_id;
    IF NOT FOUND THEN
        IF v_policy.evidence_required THEN RETURN 'evidence_missing'; END IF;
        RETURN 'eligible';
    END IF;
    IF v_policy.device_enforced THEN
        SELECT user_id INTO v_owner FROM promotion_device_owner WHERE fingerprint = v_evidence.fingerprint;
        IF v_owner IS NULL THEN RAISE EXCEPTION 'promotion device owner unavailable' USING ERRCODE = '55000'; END IF;
        IF v_owner <> p_user_id THEN RETURN 'owner_conflict'; END IF;
        IF EXISTS (SELECT 1 FROM promotion_device_grant WHERE promotion = p_promotion
            AND fingerprint = v_evidence.fingerprint AND user_id <> p_user_id) THEN
            RETURN 'device_already_redeemed';
        END IF;
        IF p_promotion = 'signup' AND EXISTS (
            SELECT 1 FROM promotion_signup_device_evidence e
            WHERE e.fingerprint = v_evidence.fingerprint AND e.user_id <> p_user_id
              AND (
                  EXISTS (SELECT 1 FROM promotion_device_grant g
                      WHERE g.user_id = e.user_id AND g.promotion = 'signup')
                  OR EXISTS (SELECT 1 FROM user_signup_trial_claim c WHERE c.user_id = e.user_id)
                  OR EXISTS (SELECT 1 FROM user_promotion_entitlement u
                      WHERE u.user_id = e.user_id AND u.signup_trial_claimed_at IS NOT NULL)
                  -- Legacy grant history survives profile and team deletion.
                  OR EXISTS (SELECT 1 FROM promotion_identity_history h
                      WHERE h.user_id = e.user_id AND h.promotion = 'signup' AND h.grant_state = 'granted')
              )
        ) THEN
            RETURN 'device_already_redeemed';
        END IF;
        IF p_promotion = 'stripe' THEN
            SELECT CASE
                WHEN EXISTS (
                    SELECT 1 FROM promotion_signup_device_evidence e
                    WHERE e.fingerprint = v_evidence.fingerprint AND e.user_id <> p_user_id
                      AND (
                          EXISTS (SELECT 1 FROM promotion_device_grant g
                              WHERE g.user_id = e.user_id AND g.promotion = 'stripe')
                          OR EXISTS (SELECT 1 FROM user_promotion_entitlement u
                              WHERE u.user_id = e.user_id AND u.stripe_redemption_at IS NOT NULL)
                          OR EXISTS (SELECT 1 FROM promotion_identity_binding b
                              JOIN promotion_identity i USING (identity_key)
                              WHERE b.user_id = e.user_id AND i.stripe_redemption_at IS NOT NULL)
                          OR EXISTS (SELECT 1 FROM promotion_identity_history h
                              WHERE h.user_id = e.user_id AND h.promotion = 'stripe' AND h.grant_state = 'granted')
                      )
                ) THEN 'device_already_redeemed'
                WHEN EXISTS (
                    SELECT 1 FROM user_promotion_entitlement u
                    WHERE u.stripe_device_fingerprint = v_evidence.fingerprint AND u.user_id <> p_user_id
                      AND u.stripe_redemption_reserved_team_id IS NOT NULL
                ) OR EXISTS (
                    -- Existing callers can reserve after registration without setting a device pin.
                    SELECT 1 FROM promotion_signup_device_evidence e
                    JOIN user_promotion_entitlement u ON u.user_id = e.user_id
                    WHERE e.fingerprint = v_evidence.fingerprint AND e.user_id <> p_user_id
                      AND u.stripe_redemption_reserved_team_id IS NOT NULL
                ) THEN 'device_reservation_pending'
            END INTO v_stripe_decision;
            IF v_stripe_decision IS NOT NULL THEN RETURN v_stripe_decision; END IF;
        END IF;
    END IF;
    RETURN 'eligible';
END $$;
