-- Decisions outlive the mutable Checkout lease and deleted teams.
CREATE TABLE stripe_checkout_publication_decision (
    team_id uuid NOT NULL,
    checkout_generation timestamptz NOT NULL,
    user_id uuid NOT NULL,
    operation_id uuid NOT NULL UNIQUE,
    home_region text NOT NULL CHECK (home_region IN ('use', 'usw')),
    request_key text NOT NULL,
    decision text NOT NULL CHECK (decision IN ('standard', 'publication_failed')),
    PRIMARY KEY (team_id, checkout_generation)
);
CREATE TABLE stripe_checkout_publication_subscription (
    team_id uuid NOT NULL,
    subscription_id text NOT NULL,
    checkout_generation timestamptz NOT NULL,
    PRIMARY KEY (team_id, subscription_id),
    FOREIGN KEY (team_id, checkout_generation)
        REFERENCES stripe_checkout_publication_decision(team_id, checkout_generation)
);
ALTER TABLE stripe_checkout_publication_decision ENABLE ROW LEVEL SECURITY;
ALTER TABLE stripe_checkout_publication_subscription ENABLE ROW LEVEL SECURITY;
CREATE TRIGGER stripe_checkout_publication_decision_immutable BEFORE UPDATE OR DELETE OR TRUNCATE
    ON stripe_checkout_publication_decision FOR EACH STATEMENT EXECUTE FUNCTION protect_promotion_device_fact();
CREATE TRIGGER stripe_checkout_publication_subscription_immutable BEFORE UPDATE OR DELETE OR TRUNCATE
    ON stripe_checkout_publication_subscription FOR EACH STATEMENT EXECUTE FUNCTION protect_promotion_device_fact();

CREATE FUNCTION begin_stripe_checkout_with_publication_decision(
    p_team_id uuid, p_user_id uuid, p_operation_id uuid, p_home_region text,
    p_request_key text, p_decision text, p_attempt_id uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE a team_billing_account; d stripe_checkout_publication_decision; v_evidence uuid;
BEGIN
    SET LOCAL lock_timeout = '5s';
    IF p_team_id IS NULL OR p_user_id IS NULL OR p_operation_id IS NULL OR p_attempt_id IS NULL
       OR p_home_region IS NULL OR p_home_region NOT IN ('use','usw')
       OR p_decision IS NULL OR p_decision NOT IN ('standard','publication_failed')
       OR NULLIF(p_request_key,'') IS NULL THEN
        RAISE EXCEPTION 'invalid Checkout decision' USING ERRCODE='22023';
    END IF;
    -- Match the reservation user/account lock order, without requiring evidence
    -- or promotion policy authority for an explicitly paid-only generation.
    IF p_decision = 'standard' THEN
        PERFORM lock_stripe_checkout_identity(p_user_id);
    ELSE
        PERFORM pg_advisory_xact_lock(hashtext('stripe-promo-user:' || p_user_id::text)::bigint);
    END IF;
    SELECT * INTO a FROM team_billing_account WHERE team_id=p_team_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'Checkout account missing' USING ERRCODE='23505'; END IF;
    IF NULLIF(btrim(a.stripe_subscription_id),'') IS NOT NULL
       AND lower(btrim(a.stripe_subscription_status)) IN ('active','trialing','past_due','unpaid','paused') THEN
        RAISE EXCEPTION 'Checkout subscription already established' USING ERRCODE='23505';
    END IF;
    SELECT * INTO d FROM stripe_checkout_publication_decision WHERE operation_id=p_operation_id;
    IF FOUND THEN
        IF d.team_id IS DISTINCT FROM p_team_id OR d.user_id IS DISTINCT FROM p_user_id
           OR d.home_region IS DISTINCT FROM p_home_region OR d.request_key IS DISTINCT FROM p_request_key
           OR d.decision IS DISTINCT FROM p_decision
           OR a.checkout_initializing_at IS DISTINCT FROM d.checkout_generation
           OR a.stripe_checkout_actor_id IS DISTINCT FROM p_user_id
           OR a.checkout_request_key IS DISTINCT FROM p_request_key
           OR a.checkout_completed_at IS NOT NULL
           OR a.checkout_initializing_at <= now() - interval '23 hours' THEN
            RAISE EXCEPTION 'Checkout intent conflict or closed generation' USING ERRCODE='23505';
        END IF;
        UPDATE team_billing_account SET checkout_pending_attempt_ids =
            CASE WHEN p_attempt_id=ANY(checkout_pending_attempt_ids) THEN checkout_pending_attempt_ids
                 ELSE array_append(checkout_pending_attempt_ids,p_attempt_id) END,
            updated_at=now() WHERE team_id=p_team_id;
        RETURN;
    END IF;
    IF a.checkout_initializing_at IS NOT NULL OR a.checkout_completed_at IS NOT NULL
       OR a.stripe_activation_credit_reserved_at IS NOT NULL THEN
        RAISE EXCEPTION 'Checkout generation already in progress' USING ERRCODE='23505';
    END IF;
    IF p_decision='standard' THEN v_evidence := capture_promotion_identity_evidence(p_user_id); END IF;
    UPDATE team_billing_account SET
        checkout_initializing_at=clock_timestamp(), checkout_request_key=p_request_key,
        checkout_pending_attempt_ids=ARRAY[p_attempt_id], checkout_may_exist=false,
        checkout_subscription_id=NULL, checkout_completed_at=NULL, checkout_session_id=NULL,
        stripe_checkout_actor_id=p_user_id, stripe_checkout_actor_claimed_at=now(),
        stripe_checkout_identity_evidence_version=v_evidence,
        checkout_anchor_snapshot=COALESCE(checkout_anchor_snapshot,commercial_billing_anchor), updated_at=now()
    WHERE team_id=p_team_id RETURNING * INTO a;
    INSERT INTO stripe_checkout_publication_decision
        (team_id,checkout_generation,user_id,operation_id,home_region,request_key,decision)
    VALUES(p_team_id,a.checkout_initializing_at,p_user_id,p_operation_id,p_home_region,p_request_key,p_decision);
END $$;

CREATE FUNCTION stripe_checkout_publication_failed(p_team_id uuid, p_generation timestamptz, p_user_id uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT EXISTS(SELECT 1 FROM stripe_checkout_publication_decision
        WHERE team_id=p_team_id AND checkout_generation=p_generation AND user_id=p_user_id
          AND decision='publication_failed')
$$;

-- Subscription association is append-only, including when an old API writer
-- accepts the callback. A later callback need not repeat Stripe metadata.
CREATE FUNCTION retain_stripe_checkout_publication_subscription()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_subscription text;
BEGIN
    IF NEW.checkout_initializing_at IS NULL OR NOT EXISTS (
        SELECT 1 FROM stripe_checkout_publication_decision
        WHERE team_id=NEW.team_id AND checkout_generation=NEW.checkout_initializing_at) THEN RETURN NEW; END IF;
    v_subscription := NEW.checkout_subscription_id;
    -- Invoice projections can carry an older subscription ID. Only an accepted
    -- lifecycle projection or explicit Checkout association binds this decision.
    IF v_subscription IS NULL AND NEW.stripe_subscription_event_at IS NOT NULL
       AND (TG_OP='INSERT' OR NEW.stripe_subscription_event_at IS DISTINCT FROM OLD.stripe_subscription_event_at
            OR NEW.stripe_subscription_status IS DISTINCT FROM OLD.stripe_subscription_status) THEN
        v_subscription := NEW.stripe_subscription_id;
    END IF;
    IF v_subscription IS NOT NULL THEN
        INSERT INTO stripe_checkout_publication_subscription(team_id,subscription_id,checkout_generation)
        VALUES(NEW.team_id,v_subscription,NEW.checkout_initializing_at) ON CONFLICT DO NOTHING;
        IF NOT EXISTS (SELECT 1 FROM stripe_checkout_publication_subscription
            WHERE team_id=NEW.team_id AND subscription_id=v_subscription
              AND checkout_generation=NEW.checkout_initializing_at) THEN
            RAISE EXCEPTION 'Checkout subscription generation conflict' USING ERRCODE='23505';
        END IF;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER retain_stripe_checkout_publication_subscription AFTER INSERT OR UPDATE
    ON team_billing_account FOR EACH ROW EXECUTE FUNCTION retain_stripe_checkout_publication_subscription();

CREATE OR REPLACE FUNCTION reserve_stripe_promotion_with_device(p_team_id uuid, p_user_id uuid,
    p_event_id text, p_subscription_id text, p_checkout_generation timestamptz,
    p_has_checkout_generation boolean)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_decision text; v_result text; v_fingerprint text; v_publication_failed boolean; v_actor_conflict boolean;
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
    -- The immutable generation decision is checked under the reservation user
    -- lock and before any identity/device lookup. Existing financial obligations
    -- above retain their original reservation recovery semantics.
    SELECT bool_or(d.decision='publication_failed'), bool_or(d.user_id IS DISTINCT FROM p_user_id)
        INTO v_publication_failed, v_actor_conflict
        FROM stripe_checkout_publication_decision d
        WHERE d.team_id=p_team_id
          AND d.checkout_generation IN (
              SELECT p_checkout_generation WHERE p_has_checkout_generation
              UNION ALL
              SELECT s.checkout_generation FROM stripe_checkout_publication_subscription s
                  WHERE s.team_id=p_team_id AND s.subscription_id=p_subscription_id
              UNION ALL
              SELECT a.checkout_initializing_at FROM team_billing_account a
                  WHERE a.team_id=p_team_id AND NOT p_has_checkout_generation AND p_subscription_id IS NULL
              UNION ALL
              SELECT s.checkout_generation FROM team_billing_account a
                  JOIN stripe_checkout_publication_subscription s
                    ON s.team_id=a.team_id AND s.subscription_id=a.stripe_subscription_id
                  WHERE a.team_id=p_team_id AND NOT p_has_checkout_generation AND p_subscription_id IS NULL
          );
    IF v_publication_failed THEN
        IF EXISTS (SELECT 1 FROM team_billing_account
            WHERE team_id=p_team_id AND stripe_activation_credit_reserved_at IS NOT NULL) THEN
            RETURN 'blocked';
        END IF;
        -- Use the existing denial vocabulary so older webhook readers remain safe.
        RETURN 'authority_unavailable';
    END IF;
    IF v_actor_conflict THEN RETURN 'ineligible'; END IF;
    BEGIN
        -- A policy-row lock timeout is a promotion-only authority failure.
        -- Financial reservation contention must still propagate and retry.
        v_decision := promotion_device_decision(p_user_id, 'stripe');
    EXCEPTION WHEN SQLSTATE '55P03' THEN
        RETURN 'authority_unavailable';
    END;
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

REVOKE ALL ON stripe_checkout_publication_decision, stripe_checkout_publication_subscription FROM PUBLIC;
REVOKE ALL ON FUNCTION begin_stripe_checkout_with_publication_decision(uuid,uuid,uuid,text,text,text,uuid),
    stripe_checkout_publication_failed(uuid,timestamptz,uuid), retain_stripe_checkout_publication_subscription() FROM PUBLIC;
DO $$ DECLARE r text; BEGIN
    FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname=r) THEN
            EXECUTE format('REVOKE ALL ON stripe_checkout_publication_decision, stripe_checkout_publication_subscription FROM %I',r);
            EXECUTE format('REVOKE ALL ON FUNCTION begin_stripe_checkout_with_publication_decision(uuid,uuid,uuid,text,text,text,uuid), stripe_checkout_publication_failed(uuid,timestamptz,uuid), retain_stripe_checkout_publication_subscription() FROM %I',r);
        END IF;
    END LOOP;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN
        GRANT EXECUTE ON FUNCTION begin_stripe_checkout_with_publication_decision(uuid,uuid,uuid,text,text,text,uuid),
            stripe_checkout_publication_failed(uuid,timestamptz,uuid) TO service_role;
    END IF;
END $$;
