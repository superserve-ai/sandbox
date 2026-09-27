ALTER TABLE team_billing_account
    ADD COLUMN stripe_activation_identity_key text REFERENCES promotion_identity(identity_key),
    ADD COLUMN stripe_checkout_identity_evidence_version uuid REFERENCES promotion_identity_evidence(evidence_version),
    ADD COLUMN stripe_activation_identity_evidence_version uuid REFERENCES promotion_identity_evidence(evidence_version);

-- Source-cell admission fence, not entitlement consumption. Retain it through
-- partial transfers and team deletion; it is never copied to the destination.
CREATE TABLE stripe_promotion_migration_fence (
    team_id uuid PRIMARY KEY,
    fenced_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE stripe_promotion_migration_fence ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON stripe_promotion_migration_fence FROM PUBLIC;
DO $$
DECLARE r text;
BEGIN
    FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
        IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=r) THEN
            EXECUTE format('REVOKE ALL ON stripe_promotion_migration_fence FROM %I',r);
        END IF;
    END LOOP;
    IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN
        GRANT SELECT ON stripe_promotion_migration_fence TO service_role;
    END IF;
END $$;

CREATE FUNCTION prepare_stripe_checkout_identity(p_team_id uuid, p_user_id uuid)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE v_enabled boolean; v_evidence uuid;
BEGIN
    v_enabled := canonical_promotion_identity_enabled();
    SELECT stripe_checkout_identity_evidence_version INTO v_evidence
    FROM team_billing_account WHERE team_id = p_team_id
        AND checkout_initializing_at IS NOT NULL AND stripe_checkout_actor_id = p_user_id;
    IF FOUND THEN
        IF v_enabled AND v_evidence IS NULL THEN
            RAISE EXCEPTION 'checkout generation has no captured identity evidence' USING ERRCODE = '55000';
        END IF;
        RETURN;
    END IF;
    PERFORM capture_promotion_identity_evidence(p_user_id);
END;
$$;

CREATE FUNCTION lock_stripe_checkout_identity(p_user_id uuid)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    PERFORM canonical_promotion_identity_enabled();
    PERFORM pg_advisory_xact_lock(hashtext('stripe-promo-user:' || COALESCE(p_user_id::text, ''))::bigint);
END;
$$;

CREATE FUNCTION record_stripe_promotion_transition(p_team_id uuid, p_user_id uuid, p_event_id text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE a public.team_billing_account;
BEGIN
    IF public.canonical_promotion_identity_enabled() THEN
        RAISE EXCEPTION 'legacy promotion transition requires disabled canonical enforcement' USING ERRCODE = '55000';
    END IF;
    PERFORM public.lock_stripe_promotion(p_team_id, p_user_id);
    SELECT * INTO a FROM public.team_billing_account WHERE team_id = p_team_id FOR UPDATE;
    IF NOT FOUND OR a.stripe_activation_user_id IS DISTINCT FROM p_user_id
       OR a.stripe_activation_credit_reservation_event_id IS DISTINCT FROM p_event_id
       OR a.stripe_activation_identity_key IS DISTINCT FROM 'legacy:' || p_user_id::text
       OR a.stripe_activation_credit_reserved_at IS NULL
       OR a.stripe_activation_credit_grant_id IS NOT NULL OR a.stripe_activation_credit_granted_at IS NOT NULL THEN
        RAISE EXCEPTION 'legacy promotion transition requires an owned reservation' USING ERRCODE = '55000';
    END IF;
    INSERT INTO public.promotion_identity_history(history_key, promotion, user_id, team_id, claimed_at,
        grant_state, status, evidence_reference, evidence_version)
    VALUES('stripe-transition:' || p_team_id::text || ':' || COALESCE(p_event_id, ''), 'stripe', p_user_id,
        p_team_id, now(), 'pending', 'pending', 'checkout evidence: ' || COALESCE(a.stripe_activation_identity_evidence_version::text, 'unavailable'),
        a.stripe_activation_identity_evidence_version)
    ON CONFLICT(history_key) DO UPDATE SET grant_state = 'pending', status = 'pending',
        claimed_at = EXCLUDED.claimed_at, evidence_reference = EXCLUDED.evidence_reference,
        evidence_version = EXCLUDED.evidence_version
    WHERE promotion_identity_history.grant_state <> 'granted';
END;
$$;

CREATE FUNCTION release_stripe_promotion_transition(p_team_id uuid, p_user_id uuid, p_event_id text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    PERFORM public.lock_stripe_promotion(p_team_id, p_user_id);
    IF NOT EXISTS (SELECT 1 FROM public.team_billing_account a WHERE a.team_id = p_team_id
        AND a.stripe_activation_user_id IS NULL
        AND a.stripe_activation_credit_reservation_event_id IS NULL
        AND a.stripe_activation_credit_granted_at IS NULL AND a.stripe_activation_credit_grant_id IS NULL
        AND a.stripe_activation_credit_reserved_at IS NULL)
       OR EXISTS (SELECT 1 FROM public.user_promotion_entitlement WHERE user_id = p_user_id
           AND (stripe_redemption_reserved_team_id IS NOT NULL OR stripe_redemption_at IS NOT NULL)) THEN
        RAISE EXCEPTION 'promotion transition release requires a released unconsumed reservation' USING ERRCODE = '55000';
    END IF;
    UPDATE public.promotion_identity_history SET grant_state = 'released', status = 'reconciled', reconciled_at = now()
    WHERE history_key = 'stripe-transition:' || p_team_id::text || ':' || COALESCE(p_event_id, '')
      AND user_id = p_user_id AND team_id = p_team_id AND grant_state = 'pending';
END;
$$;

-- Existing external attempts must be recoverable even when identity evidence
-- is unavailable. Their old user fence remains quarantined until reconciled.
INSERT INTO promotion_identity(identity_key, stripe_reserved_team_id, stripe_reserved_user_id)
SELECT 'legacy:' || user_id::text, stripe_redemption_reserved_team_id, user_id
FROM user_promotion_entitlement
WHERE stripe_redemption_reserved_team_id IS NOT NULL
ON CONFLICT (identity_key) DO NOTHING;

UPDATE team_billing_account a
SET stripe_activation_identity_key = 'legacy:' || u.user_id::text
FROM user_promotion_entitlement u
WHERE u.stripe_redemption_reserved_team_id = a.team_id
  AND a.stripe_activation_user_id = u.user_id
  AND a.stripe_activation_credit_grant_id IS NULL
  AND a.stripe_activation_credit_granted_at IS NULL;

INSERT INTO promotion_identity_history(
    history_key, promotion, user_id, team_id, claimed_at, status, identity_keys, evidence_reference, grant_state
)
SELECT 'stripe-user:' || user_id::text, 'stripe', user_id,
       stripe_redemption_reserved_team_id,
       COALESCE(stripe_redemption_reserved_at, created_at), 'pending', '{}',
       'preexisting Stripe reservation requires settlement before identity reconciliation', 'pending'
FROM user_promotion_entitlement
WHERE stripe_redemption_reserved_team_id IS NOT NULL
ON CONFLICT (history_key) DO NOTHING;

CREATE OR REPLACE FUNCTION lock_stripe_promotion(p_team_id uuid, p_user_id uuid)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_identity text;
    v_current_identity text;
    v_captured_identity text;
BEGIN
    PERFORM canonical_promotion_identity_enabled();
    PERFORM pg_advisory_xact_lock(hashtext('stripe-promo-user:' || COALESCE(p_user_id::text, ''))::bigint);
    SELECT a.stripe_activation_identity_key,
        promotion_identity_key(e.user_id, e.email, e.email_verified)
    INTO v_identity, v_captured_identity
    FROM team_billing_account a
    LEFT JOIN promotion_identity_evidence e ON e.evidence_version = a.stripe_activation_identity_evidence_version
    WHERE a.team_id = p_team_id;
    IF v_captured_identity IS NOT NULL THEN
        PERFORM pg_advisory_xact_lock(hashtext('promotion-identity:' || v_captured_identity)::bigint);
    END IF;
    IF v_identity IS NOT NULL THEN
        PERFORM pg_advisory_xact_lock(hashtext('promotion-identity:' || v_identity)::bigint);
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('stripe-promo-team:' || p_team_id::text)::bigint);
    SELECT stripe_activation_identity_key INTO v_current_identity
    FROM team_billing_account WHERE team_id = p_team_id;
    IF v_current_identity IS DISTINCT FROM v_identity THEN
        RAISE EXCEPTION 'Stripe promotion identity changed while acquiring its lock'
            USING ERRCODE = 'serialization_failure';
    END IF;
END;
$$;

CREATE FUNCTION stripe_promotion_eligible(p_team_id uuid, p_user_id uuid)
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
           AND (stripe_activation_credit_grant_id IS NOT NULL OR stripe_activation_credit_granted_at IS NOT NULL)) THEN
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

CREATE FUNCTION reserve_stripe_promotion_for_subscription_event_state(
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

CREATE OR REPLACE FUNCTION reserve_stripe_promotion_for_event_state(p_team_id uuid, p_user_id uuid, p_event_id text)
RETURNS text LANGUAGE sql AS $$
    SELECT reserve_stripe_promotion_for_subscription_event_state(p_team_id, p_user_id, p_event_id, NULL, NULL, false);
$$;

CREATE OR REPLACE FUNCTION reserve_stripe_promotion(p_team_id uuid, p_user_id uuid)
RETURNS boolean LANGUAGE sql AS $$
    SELECT reserve_stripe_promotion_for_event_state(p_team_id, p_user_id, NULL) IN ('acquired', 'existing');
$$;

CREATE OR REPLACE FUNCTION release_stripe_promotion(p_team_id uuid, p_user_id uuid)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE v_identity text; v_event text;
BEGIN
    PERFORM lock_stripe_promotion(p_team_id, p_user_id);
    SELECT stripe_activation_identity_key, stripe_activation_credit_reservation_event_id INTO v_identity, v_event
    FROM team_billing_account
    WHERE team_id = p_team_id AND stripe_activation_user_id = p_user_id
      AND stripe_activation_credit_grant_id IS NULL AND stripe_activation_credit_granted_at IS NULL
    FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;
    UPDATE promotion_identity
    SET stripe_reserved_team_id = NULL, stripe_reserved_user_id = NULL
    WHERE identity_key = v_identity AND stripe_reserved_team_id = p_team_id
      AND stripe_reserved_user_id = p_user_id AND stripe_redemption_at IS NULL;
    UPDATE user_promotion_entitlement
    SET stripe_redemption_reserved_team_id = NULL, stripe_redemption_reserved_at = NULL,
        stripe_redemption_attempted_at = NULL, updated_at = now()
    WHERE user_id = p_user_id AND stripe_redemption_reserved_team_id = p_team_id
      AND stripe_redemption_at IS NULL;
    UPDATE team_billing_account
    SET stripe_activation_user_id = NULL, stripe_activation_identity_key = NULL,
        stripe_activation_identity_evidence_version = NULL,
        stripe_activation_credit_reserved_at = NULL, stripe_activation_credit_reservation_event_id = NULL,
        updated_at = now()
    WHERE team_id = p_team_id;
    IF v_identity LIKE 'legacy:%' THEN
        PERFORM release_stripe_promotion_transition(p_team_id, p_user_id, v_event);
    END IF;
END;
$$;

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
    IF NOT EXISTS (SELECT 1 FROM team_credit_grant WHERE team_id = p_team_id AND reason = 'signup trial credit') THEN
        INSERT INTO team_credit_grant(team_id, amount_usd, remaining_usd, reason, created_by)
        VALUES (p_team_id, 95, 0, 'stripe promotional credit', p_user_id);
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION activate_team_billing(p_team_id uuid, p_user_id uuid, p_stripe_grant_id text)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    PERFORM lock_stripe_promotion(p_team_id, p_user_id);
    PERFORM 1 FROM team_billing_account WHERE team_id = p_team_id FOR UPDATE;
    UPDATE team_billing_account
    SET trial_ended_at = COALESCE(trial_ended_at, now()), updated_at = now()
    WHERE team_id = p_team_id
      AND lower(coalesce(stripe_subscription_status, '')) IN ('active', 'trialing', 'past_due');
    IF NOT FOUND THEN RETURN; END IF;
    UPDATE team_credit_grant SET remaining_usd = 0, updated_at = now()
    WHERE team_id = p_team_id AND reason = 'signup trial credit';
    PERFORM finalize_stripe_promotion(p_team_id, p_user_id, p_stripe_grant_id);
END;
$$;

DO $$
DECLARE v_function text; v_role text;
BEGIN
    FOREACH v_function IN ARRAY ARRAY[
        'lock_stripe_promotion(uuid,uuid)', 'stripe_promotion_eligible(uuid,uuid)',
        'prepare_stripe_checkout_identity(uuid,uuid)',
        'lock_stripe_checkout_identity(uuid)',
        'record_stripe_promotion_transition(uuid,uuid,text)', 'release_stripe_promotion_transition(uuid,uuid,text)',
        'reserve_stripe_promotion_for_event_state(uuid,uuid,text)',
        'reserve_stripe_promotion_for_subscription_event_state(uuid,uuid,text,text,timestamptz,boolean)',
        'reserve_stripe_promotion_for_event(uuid,uuid,text)', 'reserve_stripe_promotion(uuid,uuid)',
        'release_stripe_promotion_for_event(uuid,uuid,text)', 'release_stripe_promotion(uuid,uuid)',
        'finalize_stripe_promotion(uuid,uuid,text)', 'activate_team_billing(uuid,uuid,text)',
        'activate_team_billing(uuid,text)'
    ] LOOP
        EXECUTE 'REVOKE ALL ON FUNCTION ' || v_function || ' FROM PUBLIC';
        FOREACH v_role IN ARRAY ARRAY['anon', 'authenticated'] LOOP
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = v_role) THEN
                EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I', v_function, v_role);
            END IF;
        END LOOP;
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
            EXECUTE 'GRANT EXECUTE ON FUNCTION ' || v_function || ' TO service_role';
        END IF;
    END LOOP;
END;
$$;
