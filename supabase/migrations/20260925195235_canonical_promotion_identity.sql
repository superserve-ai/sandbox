BEGIN;

LOCK TABLE team, team_member, team_memberships, user_role_assignments,
    team_credit_grant, user_signup_trial_claim, user_promotion_entitlement
    IN SHARE ROW EXCLUSIVE MODE;

-- Evidence is supplied by the trusted profile writer, never inferred from a
-- profile row. UUID versions remain addressable when a checkout moves cells.
CREATE TABLE promotion_identity_evidence (
    evidence_version uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL,
    email text,
    email_verified boolean NOT NULL,
    auth_updated_at timestamptz NOT NULL,
    observed_at timestamptz NOT NULL,
    UNIQUE(user_id, evidence_version)
);
CREATE TABLE promotion_identity_current (
    user_id uuid PRIMARY KEY,
    evidence_version uuid NOT NULL,
    FOREIGN KEY(user_id, evidence_version)
        REFERENCES promotion_identity_evidence(user_id, evidence_version)
);
CREATE TABLE promotion_identity_enforcement (
    singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
    enabled boolean NOT NULL DEFAULT false,
    enabled_at timestamptz,
    readiness_reference text,
    CHECK (enabled = (enabled_at IS NOT NULL AND readiness_reference IS NOT NULL))
);
INSERT INTO promotion_identity_enforcement(singleton) VALUES(true);

CREATE FUNCTION protect_promotion_identity_evidence()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'promotion identity evidence is immutable' USING ERRCODE = '55000';
END $$;
CREATE TRIGGER promotion_identity_evidence_immutable
    BEFORE UPDATE OR DELETE ON promotion_identity_evidence
    FOR EACH ROW EXECUTE FUNCTION protect_promotion_identity_evidence();
CREATE TRIGGER promotion_identity_evidence_no_truncate
    BEFORE TRUNCATE ON promotion_identity_evidence
    FOR EACH STATEMENT EXECUTE FUNCTION protect_promotion_identity_evidence();

CREATE FUNCTION protect_canonical_promotion_identity_gate()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF TG_OP <> 'UPDATE' OR OLD.enabled THEN
        RAISE EXCEPTION 'canonical promotion enforcement cannot be reversed' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER promotion_identity_enforcement_irreversible
    BEFORE UPDATE OR DELETE ON promotion_identity_enforcement
    FOR EACH ROW EXECUTE FUNCTION protect_canonical_promotion_identity_gate();
CREATE TRIGGER promotion_identity_enforcement_no_truncate
    BEFORE TRUNCATE ON promotion_identity_enforcement
    FOR EACH STATEMENT EXECUTE FUNCTION protect_canonical_promotion_identity_gate();

CREATE FUNCTION canonical_promotion_identity_enabled()
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_enabled boolean;
BEGIN
    SELECT enabled INTO STRICT v_enabled FROM promotion_identity_enforcement WHERE singleton FOR SHARE;
    RETURN v_enabled;
END $$;

CREATE FUNCTION upsert_profile_with_promotion_identity(p_user_id uuid, p_email text,
    p_email_verified boolean, p_auth_updated_at timestamptz, p_observed_at timestamptz)
RETURNS TABLE(outcome text, evidence_version uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, extensions AS $$
DECLARE previous promotion_identity_evidence; v_version uuid; v_now timestamptz := clock_timestamp();
BEGIN
    IF p_user_id IS NULL OR p_email_verified IS NULL OR p_auth_updated_at IS NULL OR p_observed_at IS NULL
       OR NOT isfinite(p_auth_updated_at) OR NOT isfinite(p_observed_at) THEN
        RAISE EXCEPTION 'invalid or stale promotion identity observation' USING ERRCODE = '22023';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('stripe-promo-user:' || p_user_id::text)::bigint);
    v_now := clock_timestamp();
    IF p_observed_at < v_now - interval '5 minutes' OR p_observed_at > v_now + interval '30 seconds'
       OR p_auth_updated_at > v_now + interval '30 seconds'
       OR p_auth_updated_at > p_observed_at + interval '30 seconds' THEN
        RAISE EXCEPTION 'invalid or stale promotion identity observation' USING ERRCODE = '22023';
    END IF;
    SELECT e.* INTO previous FROM promotion_identity_current c
    JOIN promotion_identity_evidence e USING(evidence_version) WHERE c.user_id = p_user_id;
    IF FOUND THEN
        IF p_auth_updated_at < previous.auth_updated_at
           OR (p_auth_updated_at = previous.auth_updated_at
               AND (p_email IS DISTINCT FROM previous.email OR p_email_verified <> previous.email_verified)) THEN
            RAISE EXCEPTION 'promotion identity source revision regressed or conflicted' USING ERRCODE = '22023';
        END IF;
        IF p_auth_updated_at = previous.auth_updated_at AND p_observed_at <= previous.observed_at THEN
            INSERT INTO profile(id, email) VALUES(p_user_id, COALESCE(p_email, ''))
            ON CONFLICT(id) DO UPDATE SET email = COALESCE(p_email, profile.email), updated_at = now();
            RETURN QUERY SELECT 'replayed'::text, previous.evidence_version;
            RETURN;
        END IF;
    END IF;
    INSERT INTO profile(id, email) VALUES(p_user_id, COALESCE(p_email, ''))
    ON CONFLICT(id) DO UPDATE SET email = COALESCE(p_email, profile.email), updated_at = now();
    INSERT INTO promotion_identity_evidence(user_id, email, email_verified, auth_updated_at, observed_at)
    VALUES(p_user_id, p_email, p_email_verified, p_auth_updated_at, p_observed_at)
    RETURNING promotion_identity_evidence.evidence_version INTO v_version;
    INSERT INTO promotion_identity_current(user_id, evidence_version) VALUES(p_user_id, v_version)
    ON CONFLICT(user_id) DO UPDATE SET evidence_version = EXCLUDED.evidence_version;
    RETURN QUERY SELECT 'applied'::text, v_version;
END $$;

CREATE FUNCTION capture_promotion_identity_evidence(p_user_id uuid)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE evidence promotion_identity_evidence; v_enabled boolean; v_now timestamptz := clock_timestamp();
BEGIN
    v_enabled := canonical_promotion_identity_enabled();
    IF p_user_id IS NOT NULL THEN
        PERFORM pg_advisory_xact_lock(hashtext('stripe-promo-user:' || p_user_id::text)::bigint);
        SELECT e.* INTO evidence FROM promotion_identity_current c
        JOIN promotion_identity_evidence e USING(evidence_version) WHERE c.user_id = p_user_id;
    END IF;
    v_now := clock_timestamp();
    IF evidence.evidence_version IS NULL OR evidence.observed_at < v_now - interval '5 minutes'
       OR evidence.observed_at > v_now + interval '30 seconds' THEN
        IF v_enabled THEN
            RAISE EXCEPTION 'fresh promotion identity evidence unavailable' USING ERRCODE = '55000';
        END IF;
        RETURN NULL;
    END IF;
    RETURN evidence.evidence_version;
END $$;

-- No profile foreign key: deleting an account cannot erase mailbox consumption.
CREATE TABLE promotion_identity (
    identity_key text PRIMARY KEY,
    signup_claimed_at timestamptz,
    stripe_redemption_at timestamptz,
    stripe_reserved_team_id uuid REFERENCES team(id) ON DELETE RESTRICT,
    stripe_reserved_user_id uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((stripe_reserved_team_id IS NULL) = (stripe_reserved_user_id IS NULL))
);
CREATE TABLE promotion_identity_binding (
    user_id uuid NOT NULL,
    identity_key text NOT NULL REFERENCES promotion_identity(identity_key),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(user_id, identity_key)
);
CREATE INDEX promotion_identity_binding_key_idx ON promotion_identity_binding(identity_key);
CREATE INDEX promotion_identity_reserved_team_idx ON promotion_identity(stripe_reserved_team_id)
    WHERE stripe_reserved_team_id IS NOT NULL;

CREATE TABLE promotion_identity_history (
    history_key text PRIMARY KEY,
    promotion text NOT NULL CHECK (promotion IN ('signup', 'stripe')),
    user_id uuid,
    team_id uuid,
    claimed_at timestamptz NOT NULL,
    grant_state text NOT NULL DEFAULT 'granted' CHECK (grant_state IN ('granted', 'pending', 'released')),
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'reconciled')),
    identity_keys text[] NOT NULL DEFAULT '{}',
    evidence_reference text,
    reconciled_at timestamptz
);
CREATE INDEX promotion_identity_history_pending_idx ON promotion_identity_history(promotion)
    WHERE status = 'pending';
ALTER TABLE promotion_identity_history ADD COLUMN evidence_version uuid
    REFERENCES promotion_identity_evidence(evidence_version);
CREATE TABLE team_signup_promotion_outcome (
    team_id uuid PRIMARY KEY REFERENCES team(id) ON DELETE CASCADE,
    user_id uuid NOT NULL,
    identity_key text REFERENCES promotion_identity(identity_key),
    outcome text NOT NULL CHECK (outcome IN ('granted', 'already_claimed', 'promotion_ineligible')),
    reason text NOT NULL,
    decided_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE promotion_identity ENABLE ROW LEVEL SECURITY;
ALTER TABLE promotion_identity_binding ENABLE ROW LEVEL SECURITY;
ALTER TABLE promotion_identity_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE team_signup_promotion_outcome ENABLE ROW LEVEL SECURITY;
ALTER TABLE promotion_identity_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE promotion_identity_current ENABLE ROW LEVEL SECURITY;
ALTER TABLE promotion_identity_enforcement ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON promotion_identity,promotion_identity_binding,promotion_identity_history,team_signup_promotion_outcome FROM PUBLIC;

CREATE FUNCTION promotion_identity_key(p_user_id uuid, p_email text, p_verified boolean)
RETURNS text LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, public, extensions AS $$
DECLARE address text; local_part text; domain text;
BEGIN
    IF p_user_id IS NULL OR p_verified IS DISTINCT FROM true THEN RETURN NULL; END IF;
    address := lower(btrim(p_email));
    IF address IS NULL OR address !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$' THEN
        RETURN NULL;
    END IF;
    local_part := split_part(address, '@', 1);
    domain := split_part(address, '@', 2);
    IF domain LIKE '.%' OR domain LIKE '%.' OR domain LIKE '%..%' THEN RETURN NULL; END IF;
    IF domain IN ('gmail.com', 'googlemail.com') THEN
        local_part := replace(split_part(local_part, '+', 1), '.', '');
        IF local_part = '' OR local_part !~ '^[a-z0-9]+$' THEN RETURN NULL; END IF;
        RETURN 'gmail:' || encode(digest(local_part || '@gmail.com', 'sha256'), 'hex');
    END IF;
    RETURN 'user:' || p_user_id::text;
END $$;

CREATE FUNCTION promotion_identity_history_pending(p_promotion text)
RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT EXISTS (SELECT 1 FROM promotion_identity_history
                   WHERE promotion = p_promotion AND status = 'pending');
$$;

CREATE FUNCTION resolve_promotion_identity_evidence(p_user_id uuid, p_evidence_version uuid)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, extensions AS $$
DECLARE v_email text; v_verified boolean; v_key text; v_signup timestamptz; v_stripe timestamptz;
BEGIN
    IF p_user_id IS NULL THEN RETURN NULL; END IF;
    PERFORM canonical_promotion_identity_enabled();
    PERFORM pg_advisory_xact_lock(hashtext('stripe-promo-user:' || p_user_id::text)::bigint);
    SELECT email, email_verified INTO v_email, v_verified FROM promotion_identity_evidence
    WHERE evidence_version = p_evidence_version AND user_id = p_user_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'captured promotion identity evidence unavailable for actor' USING ERRCODE = '55000';
    END IF;
    v_key := promotion_identity_key(p_user_id, v_email, v_verified);
    IF v_key IS NULL THEN RETURN NULL; END IF;
    PERFORM pg_advisory_xact_lock(hashtext('promotion-identity:' || v_key)::bigint);
    SELECT min(signup_at), min(stripe_at) INTO v_signup, v_stripe FROM (
        SELECT i.signup_claimed_at AS signup_at, i.stripe_redemption_at AS stripe_at
        FROM promotion_identity_binding b JOIN promotion_identity i USING (identity_key)
        WHERE b.user_id = p_user_id
        UNION ALL
        SELECT signup_trial_claimed_at, stripe_redemption_at FROM user_promotion_entitlement WHERE user_id = p_user_id
        UNION ALL
        SELECT claimed_at, NULL::timestamptz FROM user_signup_trial_claim WHERE user_id = p_user_id
    ) consumed;
    INSERT INTO promotion_identity(identity_key, signup_claimed_at, stripe_redemption_at)
    VALUES(v_key, v_signup, v_stripe)
    ON CONFLICT (identity_key) DO UPDATE SET
        signup_claimed_at = COALESCE(promotion_identity.signup_claimed_at, EXCLUDED.signup_claimed_at),
        stripe_redemption_at = COALESCE(promotion_identity.stripe_redemption_at, EXCLUDED.stripe_redemption_at);
    INSERT INTO promotion_identity_binding(user_id, identity_key) VALUES(p_user_id, v_key)
    ON CONFLICT DO NOTHING;
    RETURN v_key;
END $$;

CREATE FUNCTION resolve_promotion_identity(p_user_id uuid)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_version uuid;
BEGIN
    v_version := capture_promotion_identity_evidence(p_user_id);
    IF v_version IS NULL THEN RETURN NULL; END IF;
    RETURN resolve_promotion_identity_evidence(p_user_id, v_version);
END $$;

CREATE FUNCTION record_promotion_identity_grant(p_history_key text, p_promotion text,
    p_user_id uuid, p_team_id uuid, p_claimed_at timestamptz, p_evidence_version uuid DEFAULT NULL)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_key text; previous promotion_identity_history;
BEGIN
    PERFORM canonical_promotion_identity_enabled();
    IF NULLIF(btrim(p_history_key), '') IS NULL OR p_promotion NOT IN ('signup', 'stripe')
       OR p_promotion IS NULL OR p_claimed_at IS NULL THEN
        RAISE EXCEPTION 'invalid promotion grant history' USING ERRCODE = '22023';
    END IF;
    INSERT INTO promotion_identity_history(history_key, promotion, user_id, team_id, claimed_at, evidence_version)
    VALUES(p_history_key, p_promotion, p_user_id, p_team_id, p_claimed_at, p_evidence_version)
    ON CONFLICT(history_key) DO NOTHING;
    SELECT * INTO previous FROM promotion_identity_history WHERE history_key = p_history_key FOR UPDATE;
    IF previous.promotion <> p_promotion OR previous.user_id IS DISTINCT FROM p_user_id
       OR previous.team_id IS DISTINCT FROM p_team_id THEN
        RAISE EXCEPTION 'promotion history attribution cannot change' USING ERRCODE = '22023';
    END IF;
    IF previous.status = 'reconciled' THEN RETURN; END IF;
    -- Only the immutable snapshot captured before this grant may resolve it.
    -- A subsequent login cannot supply the mailbox for an older obligation.
    IF previous.evidence_version IS NOT NULL THEN
        v_key := resolve_promotion_identity_evidence(p_user_id, previous.evidence_version);
    END IF;
    IF v_key IS NULL THEN
        UPDATE promotion_identity_history SET grant_state = 'granted' WHERE history_key = p_history_key;
        RETURN;
    END IF;
    UPDATE promotion_identity SET
        signup_claimed_at = CASE WHEN p_promotion = 'signup' THEN COALESCE(signup_claimed_at, p_claimed_at) ELSE signup_claimed_at END,
        stripe_redemption_at = CASE WHEN p_promotion = 'stripe' THEN COALESCE(stripe_redemption_at, p_claimed_at) ELSE stripe_redemption_at END
    WHERE identity_key = v_key;
    UPDATE promotion_identity_history SET status = 'reconciled', identity_keys = ARRAY[v_key],
        evidence_reference = 'trusted local evidence:' || previous.evidence_version::text,
        grant_state = 'granted', reconciled_at = now() WHERE history_key = p_history_key;
END $$;

CREATE FUNCTION enable_canonical_promotion_identity(p_readiness_reference text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE readiness jsonb; v_enabled boolean;
BEGIN
    BEGIN
        readiness := p_readiness_reference::jsonb;
    EXCEPTION WHEN invalid_text_representation THEN
        RAISE EXCEPTION 'readiness requires a JSON attestation' USING ERRCODE = '22023';
    END;
    IF readiness IS NULL OR jsonb_typeof(readiness) <> 'object'
       OR readiness->'all_writers_ready' IS DISTINCT FROM 'true'::jsonb
       OR readiness->'rollback_ready' IS DISTINCT FROM 'true'::jsonb
       OR jsonb_typeof(readiness->'reference') IS DISTINCT FROM 'string'
       OR NULLIF(btrim(readiness->>'reference'), '') IS NULL THEN
        RAISE EXCEPTION 'all writers and rollback readiness must be explicitly attested' USING ERRCODE = '22023';
    END IF;
    SELECT enabled INTO STRICT v_enabled FROM promotion_identity_enforcement WHERE singleton FOR UPDATE;
    IF v_enabled THEN RETURN; END IF;
    IF EXISTS (SELECT 1 FROM promotion_identity_history WHERE status = 'pending')
       OR EXISTS (SELECT 1 FROM user_promotion_entitlement WHERE stripe_redemption_reserved_team_id IS NOT NULL)
       OR EXISTS (SELECT 1 FROM promotion_identity WHERE stripe_reserved_team_id IS NOT NULL)
       OR EXISTS (SELECT 1 FROM team_billing_account
           WHERE stripe_activation_credit_reserved_at IS NOT NULL
              OR checkout_initializing_at IS NOT NULL OR checkout_completed_at IS NOT NULL) THEN
        RAISE EXCEPTION 'promotion history and pending checkouts must be settled before enforcement' USING ERRCODE = '55000';
    END IF;
    UPDATE promotion_identity_enforcement SET enabled = true, enabled_at = now(),
        readiness_reference = p_readiness_reference WHERE singleton;
END $$;

-- Current Auth state is not proof of the mailbox used for an old grant. Keep
-- the consumed user/team facts, and require explicit historical evidence.
INSERT INTO promotion_identity_history(history_key, promotion, user_id, team_id, claimed_at)
SELECT 'signup-user:' || user_id, 'signup', user_id, team_id, claimed_at FROM user_signup_trial_claim;
INSERT INTO promotion_identity_history(history_key, promotion, user_id, team_id, claimed_at)
SELECT 'signup-user:' || user_id, 'signup', user_id, signup_trial_team_id, signup_trial_claimed_at
FROM user_promotion_entitlement WHERE signup_trial_claimed_at IS NOT NULL
ON CONFLICT DO NOTHING;
INSERT INTO promotion_identity_history(history_key, promotion, user_id, team_id, claimed_at)
SELECT 'signup-team:' || g.team_id, 'signup', NULL, g.team_id, min(g.created_at)
FROM team_credit_grant g WHERE g.reason = 'signup trial credit'
AND NOT EXISTS (SELECT 1 FROM user_signup_trial_claim c WHERE c.team_id = g.team_id)
GROUP BY g.team_id;
INSERT INTO promotion_identity_history(history_key, promotion, user_id, team_id, claimed_at, grant_state)
SELECT 'stripe-user:' || user_id, 'stripe', user_id,
    COALESCE(stripe_redemption_team_id, stripe_redemption_reserved_team_id),
    COALESCE(stripe_redemption_at, stripe_redemption_reserved_at, created_at),
    CASE WHEN stripe_redemption_at IS NULL THEN 'pending' ELSE 'granted' END
FROM user_promotion_entitlement
WHERE stripe_redemption_at IS NOT NULL OR stripe_redemption_reserved_team_id IS NOT NULL;
INSERT INTO promotion_identity_history(history_key, promotion, user_id, team_id, claimed_at)
SELECT 'stripe-team:' || a.team_id, 'stripe', a.stripe_activation_user_id, a.team_id,
    COALESCE(a.stripe_activation_credit_granted_at, a.updated_at)
FROM team_billing_account a
WHERE (a.stripe_activation_credit_granted_at IS NOT NULL OR a.stripe_activation_credit_grant_id IS NOT NULL)
AND NOT EXISTS (SELECT 1 FROM user_promotion_entitlement e WHERE e.stripe_redemption_team_id = a.team_id);

CREATE FUNCTION reconcile_promotion_identity_history(p_history_key text, p_identity_keys text[], p_evidence_reference text,
    p_grant_outcome text DEFAULT 'granted')
RETURNS void LANGUAGE plpgsql AS $$
DECLARE h promotion_identity_history; v_key text;
BEGIN
    IF cardinality(p_identity_keys) IS NULL OR cardinality(p_identity_keys) = 0
       OR NULLIF(btrim(p_evidence_reference), '') IS NULL
       OR p_grant_outcome IS NULL OR p_grant_outcome NOT IN ('granted', 'released') THEN
        RAISE EXCEPTION 'historical identity evidence is required' USING ERRCODE = '22023';
    END IF;
    SELECT * INTO h FROM promotion_identity_history WHERE history_key = p_history_key FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'unknown promotion history' USING ERRCODE = '22023'; END IF;
    IF h.status = 'reconciled' THEN
        IF h.identity_keys IS DISTINCT FROM p_identity_keys OR h.grant_state <> p_grant_outcome THEN
            RAISE EXCEPTION 'historical identity reconciliation is immutable' USING ERRCODE = '22023';
        END IF;
        RETURN;
    END IF;
    IF EXISTS (SELECT 1 FROM user_promotion_entitlement
        WHERE (user_id = h.user_id OR stripe_redemption_reserved_team_id = h.team_id)
          AND stripe_redemption_reserved_team_id IS NOT NULL) THEN
        RAISE EXCEPTION 'settle pending Stripe grant before identity reconciliation' USING ERRCODE = '55000';
    END IF;
    IF p_grant_outcome = 'released' AND (h.promotion <> 'stripe' OR h.grant_state <> 'pending'
        OR EXISTS (SELECT 1 FROM user_promotion_entitlement WHERE user_id = h.user_id AND stripe_redemption_at IS NOT NULL)
        OR EXISTS (SELECT 1 FROM team_billing_account WHERE team_id = h.team_id
            AND (stripe_activation_credit_grant_id IS NOT NULL OR stripe_activation_credit_granted_at IS NOT NULL))) THEN
        RAISE EXCEPTION 'only a definitively ungranted historical reservation can be released' USING ERRCODE = '55000';
    END IF;
    FOR v_key IN SELECT DISTINCT k FROM unnest(p_identity_keys) k ORDER BY k LOOP
        IF v_key IS NULL OR v_key !~ '^(gmail:[0-9a-f]{64}|user:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$' THEN
            RAISE EXCEPTION 'invalid historical promotion identity' USING ERRCODE = '22023';
        END IF;
        PERFORM pg_advisory_xact_lock(hashtext('promotion-identity:' || v_key)::bigint);
        INSERT INTO promotion_identity(identity_key, signup_claimed_at, stripe_redemption_at)
        VALUES(v_key, CASE WHEN h.promotion = 'signup' THEN h.claimed_at END,
                     CASE WHEN h.promotion = 'stripe' AND p_grant_outcome = 'granted' THEN h.claimed_at END)
        ON CONFLICT (identity_key) DO UPDATE SET
            signup_claimed_at = COALESCE(promotion_identity.signup_claimed_at, EXCLUDED.signup_claimed_at),
            stripe_redemption_at = COALESCE(promotion_identity.stripe_redemption_at, EXCLUDED.stripe_redemption_at);
        IF h.user_id IS NOT NULL THEN
            INSERT INTO promotion_identity_binding(user_id, identity_key) VALUES(h.user_id, v_key)
            ON CONFLICT DO NOTHING;
        END IF;
    END LOOP;
    UPDATE promotion_identity_history SET status = 'reconciled', identity_keys = p_identity_keys,
        evidence_reference = p_evidence_reference, grant_state = p_grant_outcome, reconciled_at = now() WHERE history_key = p_history_key;
END $$;

DROP FUNCTION claim_team_signup_trial(uuid, uuid);
CREATE FUNCTION claim_team_signup_trial(p_team_id uuid, p_user_id uuid)
RETURNS TABLE(outcome text, reason text) LANGUAGE plpgsql AS $$
DECLARE p team_signup_trial_provenance; v_key text; v_claimed boolean; v_outcome text; v_reason text;
    v_enabled boolean; v_version uuid;
BEGIN
    IF p_user_id IS NULL THEN RAISE EXCEPTION 'signup trial requires a creator' USING ERRCODE = '22023'; END IF;
    v_enabled := canonical_promotion_identity_enabled();
    PERFORM 1 FROM team WHERE id = p_team_id FOR NO KEY UPDATE NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'signup team does not exist' USING ERRCODE = '22023'; END IF;
    IF EXISTS (SELECT 1 FROM team_signup_promotion_outcome o WHERE o.team_id = p_team_id AND o.user_id <> p_user_id) THEN
        RAISE EXCEPTION 'signup trial creator cannot change' USING ERRCODE = '22023';
    END IF;
    RETURN QUERY SELECT o.outcome, o.reason FROM team_signup_promotion_outcome o WHERE o.team_id = p_team_id;
    IF FOUND THEN RETURN; END IF;
    SELECT * INTO p FROM team_signup_trial_provenance WHERE team_id = p_team_id FOR UPDATE;
    IF NOT FOUND OR p.completed_at IS NOT NULL THEN
        RETURN QUERY SELECT 'promotion_ineligible'::text, 'not_initial_creation'::text;
        RETURN;
    END IF;
    IF p.creator_bound_at IS NOT NULL AND p.creator_user_id IS DISTINCT FROM p_user_id THEN
        RAISE EXCEPTION 'signup trial creator cannot change' USING ERRCODE = '22023';
    END IF;
    v_version := capture_promotion_identity_evidence(p_user_id);
    IF v_version IS NOT NULL THEN v_key := resolve_promotion_identity_evidence(p_user_id, v_version); END IF;
    v_claimed := false;
    IF v_enabled AND v_key IS NULL THEN
        v_outcome := 'promotion_ineligible'; v_reason := 'verified_identity_missing';
    ELSIF v_enabled AND EXISTS (SELECT 1 FROM promotion_identity i WHERE i.identity_key = v_key AND i.signup_claimed_at IS NOT NULL) THEN
        v_outcome := 'already_claimed'; v_reason := 'identity_already_claimed';
    ELSIF v_enabled AND promotion_identity_history_pending('signup') THEN
        v_outcome := 'promotion_ineligible'; v_reason := 'historical_identity_unresolved';
    ELSIF EXISTS (SELECT 1 FROM promotion_identity_history h
        WHERE h.promotion = 'signup' AND h.user_id = p_user_id AND h.grant_state = 'granted'
          AND h.team_id IS DISTINCT FROM p_team_id) THEN
        v_outcome := 'already_claimed'; v_reason := 'user_already_claimed';
    ELSE
        INSERT INTO user_signup_trial_claim(user_id, team_id) VALUES(p_user_id, p_team_id)
        ON CONFLICT (user_id) DO NOTHING RETURNING true INTO v_claimed;
        IF v_claimed OR EXISTS (SELECT 1 FROM user_signup_trial_claim WHERE user_id = p_user_id AND team_id = p_team_id) THEN
            INSERT INTO user_promotion_entitlement(user_id, signup_trial_claimed_at, signup_trial_team_id)
            VALUES(p_user_id, now(), p_team_id)
            ON CONFLICT (user_id) DO UPDATE SET
                signup_trial_claimed_at = COALESCE(user_promotion_entitlement.signup_trial_claimed_at, EXCLUDED.signup_trial_claimed_at),
                signup_trial_team_id = CASE WHEN user_promotion_entitlement.signup_trial_claimed_at IS NULL
                    THEN EXCLUDED.signup_trial_team_id ELSE user_promotion_entitlement.signup_trial_team_id END;
            PERFORM record_promotion_identity_grant('signup-grant:' || p_team_id::text,
                'signup', p_user_id, p_team_id, now(), CASE WHEN p.legacy_grant_id IS NULL THEN v_version END);
            IF p.legacy_grant_id IS NULL THEN
                INSERT INTO team_credit_grant(team_id, amount_usd, remaining_usd, reason, created_by)
                VALUES(p_team_id, 5, 5, 'signup trial credit', p_user_id);
            ELSE
                UPDATE team_credit_grant g SET created_by = p_user_id
                WHERE g.id = p.legacy_grant_id AND g.team_id = p_team_id AND g.reason = 'signup trial credit' AND g.created_by IS NULL;
            END IF;
            INSERT INTO team_trial_eligibility_cache(team_id, eligible) VALUES(p_team_id, true)
            ON CONFLICT (team_id) DO UPDATE SET eligible = true, updated_at = now();
            v_outcome := 'granted'; v_reason := CASE WHEN v_enabled THEN 'first_identity_claim' ELSE 'first_user_claim' END;
        ELSE
            v_outcome := 'already_claimed'; v_reason := 'user_already_claimed';
        END IF;
    END IF;
    IF v_outcome <> 'granted' AND p.legacy_grant_id IS NULL THEN
        INSERT INTO team_signup_trial_denial(team_id) VALUES(p_team_id) ON CONFLICT DO NOTHING;
    END IF;
    INSERT INTO team_signup_promotion_outcome(team_id, user_id, identity_key, outcome, reason)
    VALUES(p_team_id, p_user_id, v_key, v_outcome, v_reason);
    UPDATE team_signup_trial_provenance SET creator_user_id = p_user_id,
        creator_bound_at = COALESCE(creator_bound_at, now()), completed_at = now() WHERE team_id = p_team_id;
    RETURN QUERY SELECT v_outcome, v_reason;
END $$;

REVOKE ALL ON FUNCTION promotion_identity_key(uuid,text,boolean), resolve_promotion_identity(uuid),
    resolve_promotion_identity_evidence(uuid,uuid), canonical_promotion_identity_enabled(),
    capture_promotion_identity_evidence(uuid), enable_canonical_promotion_identity(text),
    upsert_profile_with_promotion_identity(uuid,text,boolean,timestamptz,timestamptz),
    record_promotion_identity_grant(text,text,uuid,uuid,timestamptz,uuid),
    protect_promotion_identity_evidence(), protect_canonical_promotion_identity_gate(),
    promotion_identity_history_pending(text), reconcile_promotion_identity_history(text,text[],text,text),
    claim_team_signup_trial(uuid,uuid) FROM PUBLIC;
REVOKE ALL ON promotion_identity_evidence,promotion_identity_current,promotion_identity_enforcement FROM PUBLIC;
DO $$ DECLARE r text; BEGIN
    FOREACH r IN ARRAY ARRAY['anon', 'authenticated'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
            EXECUTE format('REVOKE ALL ON promotion_identity,promotion_identity_binding,promotion_identity_history,team_signup_promotion_outcome FROM %I', r);
            EXECUTE format('REVOKE ALL ON promotion_identity_evidence,promotion_identity_current,promotion_identity_enforcement FROM %I', r);
            EXECUTE format('REVOKE ALL ON FUNCTION promotion_identity_key(uuid,text,boolean),resolve_promotion_identity(uuid),promotion_identity_history_pending(text),reconcile_promotion_identity_history(text,text[],text,text),claim_team_signup_trial(uuid,uuid) FROM %I', r);
            EXECUTE format('REVOKE ALL ON FUNCTION resolve_promotion_identity_evidence(uuid,uuid),canonical_promotion_identity_enabled(),capture_promotion_identity_evidence(uuid),enable_canonical_promotion_identity(text),upsert_profile_with_promotion_identity(uuid,text,boolean,timestamptz,timestamptz),record_promotion_identity_grant(text,text,uuid,uuid,timestamptz,uuid),protect_promotion_identity_evidence(),protect_canonical_promotion_identity_gate() FROM %I', r);
        END IF;
    END LOOP;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
        GRANT USAGE ON SCHEMA public TO service_role;
        REVOKE ALL ON FUNCTION reconcile_promotion_identity_history(text,text[],text,text) FROM service_role;
        REVOKE ALL ON FUNCTION enable_canonical_promotion_identity(text),protect_promotion_identity_evidence(),protect_canonical_promotion_identity_gate() FROM service_role;
        REVOKE ALL ON promotion_identity,promotion_identity_binding,promotion_identity_history,team_signup_promotion_outcome FROM service_role;
        REVOKE ALL ON promotion_identity_evidence,promotion_identity_current,promotion_identity_enforcement FROM service_role;
        GRANT EXECUTE ON FUNCTION promotion_identity_key(uuid,text,boolean),resolve_promotion_identity(uuid),
            resolve_promotion_identity_evidence(uuid,uuid),canonical_promotion_identity_enabled(),
            capture_promotion_identity_evidence(uuid),upsert_profile_with_promotion_identity(uuid,text,boolean,timestamptz,timestamptz),
            record_promotion_identity_grant(text,text,uuid,uuid,timestamptz,uuid),
            promotion_identity_history_pending(text),claim_team_signup_trial(uuid,uuid) TO service_role;
        GRANT SELECT, INSERT, UPDATE ON promotion_identity,promotion_identity_binding,team_signup_promotion_outcome TO service_role;
        GRANT SELECT ON promotion_identity_history,promotion_identity_evidence,promotion_identity_current,promotion_identity_enforcement TO service_role;
    END IF;
END $$;

COMMIT;
