CREATE OR REPLACE FUNCTION activate_team_billing(p_team_id uuid, p_user_id uuid, p_stripe_grant_id text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE v_settled boolean; v_account team_billing_account;
BEGIN
    SELECT stripe_activation_credit_reserved_at IS NULL
        AND (NULLIF(stripe_activation_credit_grant_id, '') IS NOT NULL
             OR stripe_activation_credit_granted_at IS NOT NULL)
    INTO v_settled FROM team_billing_account WHERE team_id = p_team_id;
    IF NULLIF(BTRIM(p_stripe_grant_id), '') IS NOT NULL AND NOT COALESCE(v_settled, false) THEN
        PERFORM lock_stripe_promotion(p_team_id, p_user_id);
    END IF;
    SELECT * INTO v_account FROM team_billing_account WHERE team_id = p_team_id FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;
    -- A settled grant needs no promotion authority. Retry if a pending attempt appeared before the row lock.
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
