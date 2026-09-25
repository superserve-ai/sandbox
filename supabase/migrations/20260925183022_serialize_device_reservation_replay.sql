CREATE OR REPLACE FUNCTION reserve_stripe_promotion_with_device(p_team_id uuid, p_user_id uuid,
    p_event_id text, p_subscription_id text, p_checkout_generation timestamptz,
    p_has_checkout_generation boolean)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_decision text; v_result text; v_fingerprint text;
BEGIN
    SET LOCAL lock_timeout = '5s';
    -- Release holds this lock while clearing the reservation; the replay check must follow it.
    PERFORM pg_advisory_xact_lock(hashtext('stripe-promo-user:' || COALESCE(p_user_id::text, ''))::bigint);
    IF EXISTS (SELECT 1 FROM team_billing_account
        WHERE team_id = p_team_id AND stripe_activation_user_id = p_user_id
          AND stripe_activation_credit_reserved_at IS NOT NULL
          AND stripe_activation_credit_reservation_event_id IS NOT DISTINCT FROM p_event_id) THEN
        RETURN reserve_stripe_promotion_for_subscription_event_state(p_team_id, p_user_id,
            p_event_id, p_subscription_id, p_checkout_generation, p_has_checkout_generation);
    END IF;
    v_decision := promotion_device_decision(p_user_id, 'stripe');
    IF v_decision <> 'eligible' THEN RETURN v_decision; END IF;
    SELECT fingerprint INTO v_fingerprint FROM promotion_signup_device_evidence WHERE user_id = p_user_id;
    v_result := reserve_stripe_promotion_for_subscription_event_state(p_team_id, p_user_id,
        p_event_id, p_subscription_id, p_checkout_generation, p_has_checkout_generation);
    IF v_result = 'acquired' THEN
        UPDATE user_promotion_entitlement
        SET stripe_device_fingerprint = v_fingerprint
        WHERE user_id = p_user_id AND stripe_redemption_reserved_team_id = p_team_id;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'Stripe device reservation is missing' USING ERRCODE = '55000';
        END IF;
    END IF;
    RETURN v_result;
END $$;

CREATE OR REPLACE FUNCTION register_promotion_signup_device(p_user_id uuid, p_source_attempt_id uuid,
    p_source_event_id text, p_fingerprint text)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_existing promotion_signup_device_evidence; v_owner uuid;
BEGIN
    IF p_user_id IS NULL OR p_source_attempt_id IS NULL OR p_source_event_id IS NULL
       OR p_fingerprint IS NULL OR length(p_source_event_id) NOT BETWEEN 1 AND 256
       OR length(p_fingerprint) NOT BETWEEN 1 AND 256 THEN
        RAISE EXCEPTION 'invalid regional signup evidence' USING ERRCODE = '22023';
    END IF;
    SET LOCAL lock_timeout = '5s';
    -- Serialize late evidence with reservation so a pending grant gets its device pin.
    PERFORM pg_advisory_xact_lock(hashtext('stripe-promo-user:' || p_user_id::text)::bigint);
    PERFORM pg_advisory_xact_lock(hashtext('promotion-device-user:' || p_user_id::text)::bigint);
    SELECT * INTO v_existing FROM promotion_signup_device_evidence WHERE user_id = p_user_id;
    IF FOUND THEN
        IF v_existing.source_attempt_id <> p_source_attempt_id OR v_existing.source_event_id <> p_source_event_id
           OR v_existing.fingerprint <> p_fingerprint THEN
            RAISE EXCEPTION 'first signup evidence cannot be replaced' USING ERRCODE = '23505';
        END IF;
    ELSE
        INSERT INTO promotion_signup_device_evidence(user_id, source_attempt_id, source_event_id, fingerprint)
            VALUES(p_user_id, p_source_attempt_id, p_source_event_id, p_fingerprint);
    END IF;
    UPDATE user_promotion_entitlement
    SET stripe_device_fingerprint = p_fingerprint
    WHERE user_id = p_user_id AND stripe_redemption_reserved_team_id IS NOT NULL
      AND stripe_device_fingerprint IS NULL;
    INSERT INTO promotion_device_owner(fingerprint, user_id) VALUES(p_fingerprint, p_user_id)
        ON CONFLICT(fingerprint) DO NOTHING;
    SELECT user_id INTO STRICT v_owner FROM promotion_device_owner WHERE fingerprint = p_fingerprint;
    IF v_owner = p_user_id THEN RETURN 'owner'; END IF;
    RETURN 'owner_conflict';
END $$;
