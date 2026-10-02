-- Original signup evidence is published independently to each regional database.
CREATE TABLE promotion_signup_device_evidence (
    user_id uuid PRIMARY KEY,
    source_attempt_id uuid NOT NULL UNIQUE,
    source_event_id text NOT NULL UNIQUE CHECK(length(source_event_id) BETWEEN 1 AND 256),
    fingerprint text NOT NULL CHECK(length(fingerprint) BETWEEN 1 AND 256),
    registered_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE promotion_device_owner (
    fingerprint text PRIMARY KEY CHECK(length(fingerprint) BETWEEN 1 AND 256),
    user_id uuid NOT NULL,
    registered_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE promotion_device_grant (
    promotion text NOT NULL CHECK(promotion IN ('signup', 'stripe')),
    user_id uuid NOT NULL,
    team_id uuid NOT NULL,
    fingerprint text,
    granted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(promotion, user_id, team_id)
);
CREATE INDEX promotion_device_grant_fingerprint_idx ON promotion_device_grant(promotion, fingerprint)
    WHERE fingerprint IS NOT NULL;
CREATE TABLE promotion_device_policy (
    singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
    device_enforced boolean NOT NULL DEFAULT false,
    evidence_required boolean NOT NULL DEFAULT false,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
INSERT INTO promotion_device_policy(singleton) VALUES(true);
ALTER TABLE promotion_signup_device_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE promotion_device_owner ENABLE ROW LEVEL SECURITY;
ALTER TABLE promotion_device_grant ENABLE ROW LEVEL SECURITY;
ALTER TABLE promotion_device_policy ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON promotion_signup_device_evidence, promotion_device_owner,
    promotion_device_grant, promotion_device_policy FROM PUBLIC;

CREATE FUNCTION protect_promotion_device_fact()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'promotion device fact is immutable' USING ERRCODE = '55000';
END $$;
CREATE TRIGGER promotion_signup_device_evidence_immutable BEFORE UPDATE OR DELETE OR TRUNCATE
    ON promotion_signup_device_evidence FOR EACH STATEMENT EXECUTE FUNCTION protect_promotion_device_fact();
CREATE TRIGGER promotion_device_owner_immutable BEFORE UPDATE OR DELETE OR TRUNCATE
    ON promotion_device_owner FOR EACH STATEMENT EXECUTE FUNCTION protect_promotion_device_fact();
CREATE TRIGGER promotion_device_grant_immutable BEFORE UPDATE OR DELETE OR TRUNCATE
    ON promotion_device_grant FOR EACH STATEMENT EXECUTE FUNCTION protect_promotion_device_fact();

CREATE FUNCTION register_promotion_signup_device(p_user_id uuid, p_source_attempt_id uuid,
    p_source_event_id text, p_fingerprint text)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_existing promotion_signup_device_evidence; v_owner uuid;
BEGIN
    IF p_user_id IS NULL OR p_source_attempt_id IS NULL OR p_source_event_id IS NULL
       OR p_fingerprint IS NULL OR length(p_source_event_id) NOT BETWEEN 1 AND 256
       OR length(p_fingerprint) NOT BETWEEN 1 AND 256 THEN
        RAISE EXCEPTION 'invalid regional signup evidence' USING ERRCODE = '22023';
    END IF;
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
    INSERT INTO promotion_device_owner(fingerprint, user_id) VALUES(p_fingerprint, p_user_id)
        ON CONFLICT(fingerprint) DO NOTHING;
    SELECT user_id INTO STRICT v_owner FROM promotion_device_owner WHERE fingerprint = p_fingerprint;
    IF v_owner = p_user_id THEN RETURN 'owner'; END IF;
    RETURN 'owner_conflict';
END $$;

CREATE FUNCTION promotion_device_decision(p_user_id uuid, p_promotion text)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_policy promotion_device_policy; v_evidence promotion_signup_device_evidence; v_owner uuid; v_canonical boolean;
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
    END IF;
    RETURN 'eligible';
END $$;

CREATE FUNCTION set_promotion_device_policy(p_device_enforced boolean, p_evidence_required boolean)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    IF p_device_enforced IS NULL OR p_evidence_required IS NULL
       OR ((p_device_enforced OR p_evidence_required) AND NOT canonical_promotion_identity_enabled()) THEN
        RAISE EXCEPTION 'invalid promotion device configuration' USING ERRCODE = '22023';
    END IF;
    UPDATE promotion_device_policy SET device_enforced = p_device_enforced,
        evidence_required = p_evidence_required, updated_at = clock_timestamp() WHERE singleton;
    IF NOT FOUND THEN RAISE EXCEPTION 'promotion device policy unavailable' USING ERRCODE = '55000'; END IF;
END $$;

CREATE FUNCTION set_promotion_device_policy(p_device_enforced boolean)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    PERFORM set_promotion_device_policy(p_device_enforced, p_device_enforced);
END $$;

CREATE FUNCTION claim_team_signup_trial_with_device(p_team_id uuid, p_user_id uuid)
RETURNS TABLE(outcome text, reason text) LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_reason text; v_fingerprint text; v_outcome text; v_claim_reason text; v_actor uuid;
BEGIN
    SELECT o.user_id, o.outcome, o.reason INTO v_actor, v_outcome, v_claim_reason
        FROM team_signup_promotion_outcome o WHERE o.team_id = p_team_id;
    IF FOUND THEN
        IF v_actor <> p_user_id THEN
            RAISE EXCEPTION 'signup trial creator cannot change' USING ERRCODE = '22023';
        END IF;
        RETURN QUERY SELECT v_outcome, v_claim_reason;
        RETURN;
    END IF;
    v_reason := promotion_device_decision(p_user_id, 'signup');
    IF v_reason <> 'eligible' THEN
        RETURN QUERY SELECT 'promotion_ineligible'::text, v_reason;
        RETURN;
    END IF;
    SELECT c.outcome, c.reason INTO v_outcome, v_claim_reason
        FROM claim_team_signup_trial(p_team_id, p_user_id) c;
    IF v_outcome = 'granted' THEN
        SELECT e.fingerprint INTO v_fingerprint FROM promotion_signup_device_evidence e WHERE e.user_id = p_user_id;
        INSERT INTO promotion_device_grant(promotion, user_id, team_id, fingerprint)
            VALUES('signup', p_user_id, p_team_id, v_fingerprint) ON CONFLICT DO NOTHING;
    END IF;
    RETURN QUERY SELECT v_outcome, v_claim_reason;
END $$;

CREATE FUNCTION record_stripe_promotion_device_grant(p_team_id uuid, p_user_id uuid)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_fingerprint text;
BEGIN
    IF p_user_id IS NULL OR p_team_id IS NULL OR NOT EXISTS (
        SELECT 1 FROM team_billing_account a JOIN user_promotion_entitlement u
            ON u.user_id = p_user_id
        WHERE a.team_id = p_team_id AND a.stripe_activation_user_id = p_user_id
          AND a.stripe_activation_credit_grant_id IS NOT NULL
          AND u.stripe_redemption_team_id = p_team_id AND u.stripe_redemption_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'Stripe device grant requires settled local grant' USING ERRCODE = '55000';
    END IF;
    SELECT fingerprint INTO v_fingerprint FROM promotion_signup_device_evidence WHERE user_id = p_user_id;
    INSERT INTO promotion_device_grant(promotion, user_id, team_id, fingerprint)
        VALUES('stripe', p_user_id, p_team_id, v_fingerprint) ON CONFLICT DO NOTHING;
    RETURN 'recorded';
END $$;

-- The caller must reserve before contacting Stripe. Existing reservation states
-- and identity/generation pins remain authoritative; this adds a local check.
CREATE FUNCTION reserve_stripe_promotion_with_device(p_team_id uuid, p_user_id uuid,
    p_event_id text, p_subscription_id text, p_checkout_generation timestamptz,
    p_has_checkout_generation boolean)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_decision text;
BEGIN
    IF EXISTS (SELECT 1 FROM team_billing_account
        WHERE team_id = p_team_id AND stripe_activation_user_id = p_user_id
          AND stripe_activation_credit_reserved_at IS NOT NULL) THEN
        RETURN reserve_stripe_promotion_for_subscription_event_state(p_team_id, p_user_id,
            p_event_id, p_subscription_id, p_checkout_generation, p_has_checkout_generation);
    END IF;
    v_decision := promotion_device_decision(p_user_id, 'stripe');
    IF v_decision <> 'eligible' THEN RETURN v_decision; END IF;
    RETURN reserve_stripe_promotion_for_subscription_event_state(p_team_id, p_user_id,
        p_event_id, p_subscription_id, p_checkout_generation, p_has_checkout_generation);
END $$;

REVOKE ALL ON FUNCTION protect_promotion_device_fact(),
    register_promotion_signup_device(uuid,uuid,text,text), promotion_device_decision(uuid,text),
    set_promotion_device_policy(boolean,boolean), set_promotion_device_policy(boolean),
    claim_team_signup_trial_with_device(uuid,uuid),
    reserve_stripe_promotion_with_device(uuid,uuid,text,text,timestamptz,boolean),
    record_stripe_promotion_device_grant(uuid,uuid) FROM PUBLIC;
DO $$ DECLARE r text; BEGIN
    FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
            EXECUTE format('REVOKE ALL ON promotion_signup_device_evidence,promotion_device_owner,promotion_device_grant,promotion_device_policy FROM %I', r);
            EXECUTE format('REVOKE ALL ON FUNCTION protect_promotion_device_fact(),register_promotion_signup_device(uuid,uuid,text,text),promotion_device_decision(uuid,text),set_promotion_device_policy(boolean,boolean),set_promotion_device_policy(boolean),claim_team_signup_trial_with_device(uuid,uuid),reserve_stripe_promotion_with_device(uuid,uuid,text,text,timestamptz,boolean),record_stripe_promotion_device_grant(uuid,uuid) FROM %I', r);
        END IF;
    END LOOP;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
        GRANT EXECUTE ON FUNCTION register_promotion_signup_device(uuid,uuid,text,text),
            promotion_device_decision(uuid,text),claim_team_signup_trial_with_device(uuid,uuid),
            reserve_stripe_promotion_with_device(uuid,uuid,text,text,timestamptz,boolean),
            record_stripe_promotion_device_grant(uuid,uuid) TO service_role;
    END IF;
END $$;
