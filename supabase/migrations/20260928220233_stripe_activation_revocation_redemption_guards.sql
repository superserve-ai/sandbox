-- Keep cancellation redemption guards effective on already-migrated databases.
CREATE OR REPLACE FUNCTION stripe_promotion_eligible(p_team_id uuid, p_user_id uuid)
RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE v_identity text; v_enabled boolean; v_evidence uuid;
BEGIN
    v_enabled := canonical_promotion_identity_enabled();
    IF p_user_id IS NULL OR NOT EXISTS (SELECT 1 FROM profile WHERE id = p_user_id) THEN
        RETURN false;
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('stripe-promo-user:' || p_user_id::text)::bigint);
    IF EXISTS (SELECT 1 FROM user_promotion_entitlement WHERE user_id = p_user_id AND stripe_redemption_at IS NOT NULL)
       OR EXISTS (SELECT 1 FROM team_billing_account WHERE team_id = p_team_id
           AND (stripe_activation_credit_grant_id IS NOT NULL OR stripe_activation_credit_granted_at IS NOT NULL))
       OR EXISTS (SELECT 1 FROM stripe_activation_credit_revocation WHERE team_id = p_team_id) THEN
        RETURN false;
    END IF;
    IF v_enabled THEN
        SELECT stripe_checkout_identity_evidence_version INTO v_evidence
        FROM team_billing_account WHERE team_id = p_team_id AND stripe_checkout_actor_id = p_user_id;
        IF v_evidence IS NOT NULL THEN
            RAISE EXCEPTION 'Stripe promotion eligibility requires checkout association evidence' USING ERRCODE = '55000';
        END IF;
        v_evidence := capture_promotion_identity_evidence(p_user_id);
        v_identity := resolve_promotion_identity_evidence(p_user_id, v_evidence);
        IF v_identity IS NULL THEN RETURN false; END IF;
        IF promotion_identity_history_pending('stripe') THEN
            RAISE EXCEPTION 'Stripe promotion history requires reconciliation' USING ERRCODE = '55000';
        END IF;
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('stripe-promo-team:' || p_team_id::text)::bigint);
    RETURN EXISTS (
        SELECT 1 FROM team_billing_account a
        WHERE a.team_id = p_team_id
          AND NOT EXISTS (SELECT 1 FROM stripe_activation_credit_revocation r WHERE r.team_id = a.team_id)
          AND NOT EXISTS (SELECT 1 FROM stripe_promotion_migration_fence WHERE team_id=p_team_id)
          AND a.stripe_activation_credit_grant_id IS NULL
          AND a.stripe_activation_credit_granted_at IS NULL
          AND a.stripe_activation_credit_reserved_at IS NULL
          AND (NOT v_enabled OR EXISTS (SELECT 1 FROM promotion_identity i WHERE i.identity_key = v_identity
              AND i.stripe_redemption_at IS NULL AND i.stripe_reserved_team_id IS NULL))
          AND NOT EXISTS (
              SELECT 1 FROM user_promotion_entitlement u WHERE u.user_id = p_user_id
                AND (u.stripe_redemption_at IS NOT NULL OR u.stripe_redemption_reserved_team_id IS NOT NULL)
          )
    );
END;
$$;

CREATE OR REPLACE FUNCTION reserve_stripe_promotion_for_subscription_event_state(
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
        RETURN 'ineligible';
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
    IF EXISTS (SELECT 1 FROM promotion_identity WHERE identity_key = v_identity AND stripe_redemption_at IS NOT NULL)
       OR EXISTS (SELECT 1 FROM user_promotion_entitlement WHERE user_id = p_user_id AND stripe_redemption_at IS NOT NULL) THEN
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
