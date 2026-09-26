-- Keep the existing claim signature device-aware. Only the device wrapper
-- can call the base implementation under the regional service role.
ALTER FUNCTION claim_team_signup_trial(uuid, uuid) RENAME TO claim_team_signup_trial_without_device;
REVOKE ALL ON FUNCTION claim_team_signup_trial_without_device(uuid,uuid) FROM PUBLIC;
DO $$ DECLARE r text; BEGIN
    FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
            EXECUTE format('REVOKE ALL ON FUNCTION claim_team_signup_trial_without_device(uuid,uuid) FROM %I', r);
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
    SET LOCAL lock_timeout = '5s';
    PERFORM pg_advisory_xact_lock(hashtext('stripe-promo-user:' || p_user_id::text)::bigint);
    PERFORM pg_advisory_xact_lock(hashtext('promotion-device-user:' || p_user_id::text)::bigint);
    v_reason := promotion_device_decision(p_user_id, 'signup');
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
    SELECT c.outcome, c.reason INTO v_outcome, v_claim_reason
        FROM claim_team_signup_trial_without_device(p_team_id, p_user_id) c;
    IF v_outcome = 'granted' THEN
        SELECT e.fingerprint INTO v_fingerprint FROM promotion_signup_device_evidence e WHERE e.user_id = p_user_id;
        INSERT INTO promotion_device_grant(promotion, user_id, team_id, fingerprint)
            VALUES('signup', p_user_id, p_team_id, v_fingerprint) ON CONFLICT DO NOTHING;
    END IF;
    RETURN QUERY SELECT v_outcome, v_claim_reason;
END $$;

CREATE OR REPLACE FUNCTION claim_team_signup_trial(p_team_id uuid, p_user_id uuid)
RETURNS TABLE(outcome text, reason text) LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE v_existing_user uuid;
BEGIN
    RETURN QUERY SELECT c.outcome, c.reason
        FROM claim_team_signup_trial_with_device(p_team_id, p_user_id) c;
EXCEPTION WHEN OTHERS THEN
    IF SQLSTATE = '22023' THEN RAISE; END IF;
    -- The failed claim subtransaction has rolled back. Complete this initial
    -- creation without credit so the team can still be provisioned.
    PERFORM 1 FROM team WHERE id = p_team_id FOR NO KEY UPDATE;
    IF NOT FOUND OR p_user_id IS NULL THEN RAISE; END IF;
    SELECT o.user_id INTO v_existing_user FROM team_signup_promotion_outcome o WHERE o.team_id = p_team_id;
    IF FOUND THEN
        IF v_existing_user <> p_user_id THEN RAISE; END IF;
        RETURN QUERY SELECT o.outcome, o.reason FROM team_signup_promotion_outcome o
            WHERE o.team_id = p_team_id AND o.user_id = p_user_id;
        RETURN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM team_signup_trial_provenance p
        WHERE p.team_id = p_team_id AND p.completed_at IS NULL
          AND (p.creator_user_id IS NULL OR p.creator_user_id = p_user_id)) THEN
        RAISE;
    END IF;
    INSERT INTO team_signup_trial_denial(team_id) VALUES(p_team_id) ON CONFLICT DO NOTHING;
    INSERT INTO team_signup_promotion_outcome(team_id,user_id,outcome,reason)
        VALUES(p_team_id,p_user_id,'promotion_ineligible','authority_unavailable');
    UPDATE team_signup_trial_provenance SET creator_user_id=p_user_id,
        creator_bound_at=COALESCE(creator_bound_at,now()), completed_at=now()
        WHERE team_id=p_team_id;
    RETURN QUERY SELECT 'promotion_ineligible'::text, 'authority_unavailable'::text;
END $$;
REVOKE ALL ON FUNCTION claim_team_signup_trial(uuid,uuid) FROM PUBLIC;
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
        GRANT EXECUTE ON FUNCTION claim_team_signup_trial(uuid,uuid) TO service_role;
    END IF;
END $$;

CREATE OR REPLACE FUNCTION create_team_with_signup_trial(p_name text, p_user_id uuid, p_home_region text)
RETURNS team LANGUAGE plpgsql SECURITY INVOKER AS $$
DECLARE created_team team;
BEGIN
    INSERT INTO team(name, home_region) VALUES(p_name, p_home_region) RETURNING * INTO created_team;
    PERFORM claim_team_signup_trial(created_team.id, p_user_id);
    DELETE FROM team_signup_trial_provenance WHERE team_id = created_team.id;
    RETURN created_team;
END $$;

CREATE OR REPLACE FUNCTION complete_legacy_signup_trial()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER AS $$
BEGIN
    IF NEW.scope_type <> 'team' OR NEW.revoked_at IS NOT NULL
       OR NOT EXISTS (SELECT 1 FROM team_signup_trial_provenance
           WHERE team_id = NEW.team_id AND completed_at IS NULL)
       OR NOT EXISTS (SELECT 1 FROM roles
           WHERE id = NEW.role_id AND name = 'team_owner' AND scope_type = 'team') THEN
        RETURN NEW;
    END IF;
    PERFORM 1 FROM team WHERE id = NEW.team_id FOR NO KEY UPDATE NOWAIT;
    IF EXISTS (SELECT 1 FROM team_signup_trial_provenance
        WHERE team_id = NEW.team_id AND creator_user_id = NEW.user_id
          AND creator_bound_at IS NOT NULL AND completed_at IS NULL)
       AND EXISTS (SELECT 1 FROM team_member
           WHERE team_id = NEW.team_id AND profile_id = NEW.user_id
             AND LOWER(role) IN ('owner', 'team_owner'))
       AND EXISTS (SELECT 1 FROM team_memberships
           WHERE team_id = NEW.team_id AND user_id = NEW.user_id AND status = 'active') THEN
        PERFORM claim_team_signup_trial(NEW.team_id, NEW.user_id);
    END IF;
    RETURN NEW;
END $$;

ALTER FUNCTION reserve_stripe_promotion_for_subscription_event_state(uuid,uuid,text,text,timestamptz,boolean)
    RENAME TO reserve_stripe_promotion_for_subscription_event_state_without_device;
REVOKE ALL ON FUNCTION reserve_stripe_promotion_for_subscription_event_state_without_device(uuid,uuid,text,text,timestamptz,boolean) FROM PUBLIC;
DO $$ DECLARE r text; BEGIN
    FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
            EXECUTE format('REVOKE ALL ON FUNCTION reserve_stripe_promotion_for_subscription_event_state_without_device(uuid,uuid,text,text,timestamptz,boolean) FROM %I', r);
        END IF;
    END LOOP;
END $$;

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
        RETURN reserve_stripe_promotion_for_subscription_event_state_without_device(p_team_id, p_user_id,
            p_event_id, p_subscription_id, p_checkout_generation, p_has_checkout_generation);
    END IF;
    v_decision := promotion_device_decision(p_user_id, 'stripe');
    IF v_decision <> 'eligible' THEN RETURN v_decision; END IF;
    SELECT fingerprint INTO v_fingerprint FROM promotion_signup_device_evidence WHERE user_id = p_user_id;
    v_result := reserve_stripe_promotion_for_subscription_event_state_without_device(p_team_id, p_user_id,
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
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN
        GRANT EXECUTE ON FUNCTION reserve_stripe_promotion_for_subscription_event_state(uuid,uuid,text,text,timestamptz,boolean) TO service_role;
    END IF;
END $$;

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
    PERFORM record_stripe_promotion_device_grant(p_team_id, p_user_id);
END;
$$;

-- A notification snapshot observes local authority without creating a claim.
CREATE FUNCTION evaluate_signup_promotion_snapshot(p_user_id uuid)
RETURNS TABLE(ownership text, device_decision text, eligibility text, reason text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, extensions AS $$
DECLARE v_evidence promotion_signup_device_evidence; v_owner uuid;
    v_canonical boolean; v_policy promotion_device_policy;
    v_identity text; v_observation promotion_identity_evidence;
BEGIN
    IF p_user_id IS NULL THEN RAISE EXCEPTION 'signup snapshot requires an actor' USING ERRCODE='22023'; END IF;
    v_canonical := canonical_promotion_identity_enabled();
    SELECT * INTO STRICT v_policy FROM promotion_device_policy WHERE singleton FOR SHARE;
    IF NOT v_canonical AND (v_policy.device_enforced OR v_policy.evidence_required) THEN
        RAISE EXCEPTION 'invalid promotion device configuration' USING ERRCODE='55000';
    END IF;
    SELECT * INTO v_evidence FROM promotion_signup_device_evidence WHERE user_id=p_user_id;
    IF FOUND THEN
        SELECT user_id INTO v_owner FROM promotion_device_owner WHERE fingerprint=v_evidence.fingerprint;
        IF v_owner IS NULL THEN RAISE EXCEPTION 'promotion device owner unavailable' USING ERRCODE='55000'; END IF;
        ownership := CASE WHEN v_owner=p_user_id THEN 'owner' ELSE 'another_owner' END;
    ELSE
        ownership := 'evidence_missing';
    END IF;
    device_decision := promotion_device_decision(p_user_id, 'signup');
    IF device_decision <> 'eligible' THEN
        eligibility := 'ineligible'; reason := device_decision;
        RETURN NEXT; RETURN;
    END IF;
    IF EXISTS (SELECT 1 FROM user_signup_trial_claim WHERE user_id=p_user_id)
       OR EXISTS (SELECT 1 FROM user_promotion_entitlement
                  WHERE user_id=p_user_id AND signup_trial_claimed_at IS NOT NULL) THEN
        eligibility := 'ineligible'; reason := 'user_already_claimed';
        RETURN NEXT; RETURN;
    END IF;
    IF v_canonical THEN
        SELECT e.* INTO v_observation FROM promotion_identity_current c
            JOIN promotion_identity_evidence e USING(evidence_version)
            WHERE c.user_id=p_user_id;
        IF NOT FOUND OR v_observation.observed_at < clock_timestamp()-interval '5 minutes'
           OR v_observation.observed_at > clock_timestamp()+interval '30 seconds' THEN
            eligibility := 'unknown'; reason := 'verified_identity_missing';
            RETURN NEXT; RETURN;
        END IF;
        v_identity := promotion_identity_key(p_user_id,v_observation.email,v_observation.email_verified);
        IF v_identity IS NULL THEN
            eligibility := 'unknown'; reason := 'verified_identity_missing';
            RETURN NEXT; RETURN;
        END IF;
        IF EXISTS (SELECT 1 FROM promotion_identity WHERE identity_key=v_identity
                   AND signup_claimed_at IS NOT NULL) THEN
            eligibility := 'ineligible'; reason := 'identity_already_claimed';
            RETURN NEXT; RETURN;
        END IF;
        IF promotion_identity_history_pending('signup') THEN
            eligibility := 'unknown'; reason := 'historical_identity_unresolved';
            RETURN NEXT; RETURN;
        END IF;
    END IF;
    eligibility := 'unknown'; reason := 'team_checks_pending';
    RETURN NEXT;
END $$;
REVOKE ALL ON FUNCTION evaluate_signup_promotion_snapshot(uuid) FROM PUBLIC;
DO $$ DECLARE r text; BEGIN
    FOREACH r IN ARRAY ARRAY['anon','authenticated'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
            EXECUTE format('REVOKE ALL ON FUNCTION evaluate_signup_promotion_snapshot(uuid) FROM %I',r);
        END IF;
    END LOOP;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN
        GRANT EXECUTE ON FUNCTION evaluate_signup_promotion_snapshot(uuid) TO service_role;
    END IF;
END $$;
