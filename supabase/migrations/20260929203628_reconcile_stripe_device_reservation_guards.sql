-- Keep cancellation and user-redemption guards behind the shared device reservation boundary.
CREATE OR REPLACE FUNCTION reserve_stripe_promotion_for_subscription_event_state_without_device(
    p_team_id uuid, p_user_id uuid, p_event_id text, p_subscription_id text,
    p_checkout_generation timestamptz, p_has_checkout_generation boolean
)
RETURNS text LANGUAGE plpgsql AS $$
DECLARE
    v_identity text;
    v_account team_billing_account;
    v_enabled boolean;
    v_evidence uuid;
    v_captured_identity text;
    v_checkout_account team_billing_account;
BEGIN
    SET LOCAL lock_timeout = '5s';
    v_enabled := canonical_promotion_identity_enabled();
    PERFORM pg_advisory_xact_lock(hashtext('stripe-promo-user:' || COALESCE(p_user_id::text, ''))::bigint);
    IF p_user_id IS NULL OR NOT EXISTS (SELECT 1 FROM profile WHERE id = p_user_id) THEN
        RETURN 'ineligible';
    END IF;
    SELECT * INTO v_account FROM team_billing_account WHERE team_id = p_team_id;
    IF NOT FOUND THEN RETURN 'blocked'; END IF;
    -- A cancellation marker is durable even when grant creation never began;
    -- once cancellation wins, later subscription retries cannot redeem again.
    IF EXISTS (SELECT 1 FROM stripe_activation_credit_revocation WHERE team_id = p_team_id) THEN
        RETURN 'ineligible';
    END IF;
    v_checkout_account := v_account;
    IF v_account.stripe_activation_credit_grant_id IS NOT NULL
       OR v_account.stripe_activation_credit_granted_at IS NOT NULL THEN
        RETURN 'ineligible';
    END IF;
    IF v_account.stripe_activation_credit_reserved_at IS NOT NULL THEN
        PERFORM lock_stripe_promotion(p_team_id, p_user_id);
        SELECT * INTO v_account FROM team_billing_account WHERE team_id = p_team_id FOR UPDATE;
        IF v_account.stripe_activation_user_id = p_user_id
           AND v_account.stripe_activation_credit_reservation_event_id IS NOT DISTINCT FROM p_event_id
           AND v_account.stripe_activation_identity_key IS NOT NULL
           AND EXISTS (
               SELECT 1 FROM promotion_identity i
               WHERE i.identity_key = v_account.stripe_activation_identity_key
                 AND i.stripe_reserved_team_id = p_team_id AND i.stripe_reserved_user_id = p_user_id
           ) THEN
            RETURN 'existing';
        END IF;
        RETURN 'blocked';
    END IF;

    IF EXISTS(SELECT 1 FROM stripe_promotion_migration_fence WHERE team_id=p_team_id) THEN
        RETURN 'ineligible';
    END IF;
    IF EXISTS (SELECT 1 FROM user_promotion_entitlement WHERE user_id = p_user_id AND stripe_redemption_at IS NOT NULL) THEN
        RETURN 'user_already_redeemed';
    END IF;
    IF v_account.stripe_checkout_actor_id = p_user_id
       AND (v_account.stripe_checkout_identity_evidence_version IS NOT NULL
           OR v_account.checkout_initializing_at IS NOT NULL OR v_account.checkout_subscription_id IS NOT NULL) THEN
        IF v_account.stripe_checkout_identity_evidence_version IS NOT NULL
           AND NULLIF(btrim(p_subscription_id), '') IS NOT NULL AND (
            (v_account.checkout_subscription_id IS NOT NULL AND v_account.checkout_subscription_id = p_subscription_id)
            OR (v_account.checkout_subscription_id IS NULL AND p_has_checkout_generation
                AND p_checkout_generation IS NOT NULL
                AND v_account.checkout_initializing_at = p_checkout_generation)
        ) THEN
            v_evidence := v_account.stripe_checkout_identity_evidence_version;
        ELSIF v_enabled THEN
            RETURN 'blocked';
        END IF;
    ELSIF p_has_checkout_generation THEN
        -- An unmatched generation cannot use a later identity observation,
        -- including after its original Checkout snapshot has been cleared.
        IF v_enabled THEN RETURN 'blocked'; END IF;
    ELSE
        v_evidence := capture_promotion_identity_evidence(p_user_id);
    END IF;
    IF v_evidence IS NOT NULL THEN
        v_captured_identity := resolve_promotion_identity_evidence(p_user_id, v_evidence);
    END IF;
    IF v_enabled THEN
        v_identity := v_captured_identity;
        IF v_identity IS NULL THEN RETURN 'ineligible'; END IF;
        IF promotion_identity_history_pending('stripe') THEN RETURN 'blocked'; END IF;
    ELSE
        v_identity := 'legacy:' || p_user_id::text;
        PERFORM pg_advisory_xact_lock(hashtext('promotion-identity:' || v_identity)::bigint);
        INSERT INTO promotion_identity(identity_key) VALUES(v_identity) ON CONFLICT DO NOTHING;
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('stripe-promo-team:' || p_team_id::text)::bigint);
    IF EXISTS(SELECT 1 FROM stripe_promotion_migration_fence WHERE team_id=p_team_id) THEN
        RETURN 'ineligible';
    END IF;
    SELECT * INTO v_account FROM team_billing_account WHERE team_id = p_team_id FOR UPDATE;
    IF NOT FOUND THEN RETURN 'blocked'; END IF;
    IF EXISTS (SELECT 1 FROM stripe_activation_credit_revocation WHERE team_id = p_team_id) THEN
        RETURN 'ineligible';
    END IF;
    IF (
        v_account.stripe_checkout_actor_id IS DISTINCT FROM v_checkout_account.stripe_checkout_actor_id
        OR v_account.stripe_checkout_identity_evidence_version IS DISTINCT FROM v_checkout_account.stripe_checkout_identity_evidence_version
        OR v_account.checkout_initializing_at IS DISTINCT FROM v_checkout_account.checkout_initializing_at
        OR v_account.checkout_subscription_id IS DISTINCT FROM v_checkout_account.checkout_subscription_id
    ) THEN
        RETURN 'blocked';
    END IF;
    IF v_account.stripe_activation_credit_grant_id IS NOT NULL
       OR v_account.stripe_activation_credit_granted_at IS NOT NULL THEN
        RETURN 'ineligible';
    END IF;
    IF v_account.stripe_activation_credit_reserved_at IS NOT NULL
       OR (v_account.stripe_activation_user_id IS NOT NULL AND v_account.stripe_activation_user_id <> p_user_id) THEN
        RETURN 'blocked';
    END IF;
    IF EXISTS (SELECT 1 FROM user_promotion_entitlement WHERE user_id = p_user_id AND stripe_redemption_at IS NOT NULL) THEN
        RETURN 'user_already_redeemed';
    END IF;
    IF EXISTS (SELECT 1 FROM promotion_identity WHERE identity_key = v_identity AND stripe_redemption_at IS NOT NULL) THEN
        RETURN 'ineligible';
    END IF;
    IF EXISTS (SELECT 1 FROM promotion_identity WHERE identity_key = v_identity AND stripe_reserved_team_id IS NOT NULL)
       OR EXISTS (SELECT 1 FROM user_promotion_entitlement WHERE user_id = p_user_id AND stripe_redemption_reserved_team_id IS NOT NULL) THEN
        RETURN 'blocked';
    END IF;
    INSERT INTO user_promotion_entitlement(user_id, stripe_redemption_reserved_team_id, stripe_redemption_reserved_at)
    VALUES (p_user_id, p_team_id, now())
    ON CONFLICT (user_id) DO UPDATE SET
        stripe_redemption_reserved_team_id = EXCLUDED.stripe_redemption_reserved_team_id,
        stripe_redemption_reserved_at = EXCLUDED.stripe_redemption_reserved_at,
        updated_at = now();
    UPDATE promotion_identity
    SET stripe_reserved_team_id = p_team_id, stripe_reserved_user_id = p_user_id
    WHERE identity_key = v_identity;
    UPDATE team_billing_account
    SET stripe_activation_user_id = p_user_id, stripe_activation_identity_key = v_identity,
        stripe_activation_identity_evidence_version = v_evidence,
        stripe_activation_credit_reserved_at = now(),
        stripe_activation_credit_reservation_event_id = p_event_id, updated_at = now()
    WHERE team_id = p_team_id;
    IF NOT v_enabled THEN
        PERFORM record_stripe_promotion_transition(p_team_id, p_user_id, p_event_id);
    END IF;
    RETURN 'acquired';
EXCEPTION WHEN foreign_key_violation THEN
    RETURN 'ineligible';
END;
$$;

CREATE OR REPLACE FUNCTION reserve_stripe_promotion_for_subscription_event_state(
    p_team_id uuid, p_user_id uuid, p_event_id text, p_subscription_id text,
    p_checkout_generation timestamptz, p_has_checkout_generation boolean)
RETURNS text LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT reserve_stripe_promotion_with_device(p_team_id,p_user_id,p_event_id,
        p_subscription_id,p_checkout_generation,p_has_checkout_generation)
$$;
CREATE OR REPLACE FUNCTION reserve_stripe_promotion_for_event_state(p_team_id uuid,p_user_id uuid,p_event_id text)
RETURNS text LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT reserve_stripe_promotion_with_device(p_team_id,p_user_id,p_event_id,NULL,NULL,false)
$$;
REVOKE ALL ON FUNCTION reserve_stripe_promotion_for_subscription_event_state(uuid,uuid,text,text,timestamptz,boolean) FROM PUBLIC;
REVOKE ALL ON FUNCTION reserve_stripe_promotion_for_event_state(uuid,uuid,text) FROM PUBLIC;
DO $$ DECLARE r text; BEGIN
    FOREACH r IN ARRAY ARRAY['anon','authenticated'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
            EXECUTE format('REVOKE ALL ON FUNCTION reserve_stripe_promotion_for_subscription_event_state(uuid,uuid,text,text,timestamptz,boolean) FROM %I', r);
            EXECUTE format('REVOKE ALL ON FUNCTION reserve_stripe_promotion_for_event_state(uuid,uuid,text) FROM %I', r);
        END IF;
    END LOOP;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN
        GRANT EXECUTE ON FUNCTION reserve_stripe_promotion_for_subscription_event_state(uuid,uuid,text,text,timestamptz,boolean) TO service_role;
        GRANT EXECUTE ON FUNCTION reserve_stripe_promotion_for_event_state(uuid,uuid,text) TO service_role;
    END IF;
END $$;


-- Retained actor redemption remains authoritative after profile deletion.
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
                          OR EXISTS (SELECT 1 FROM promotion_stripe_actor_redemption r
                              WHERE r.user_id = e.user_id)
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
