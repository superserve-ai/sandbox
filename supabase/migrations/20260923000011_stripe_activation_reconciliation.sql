-- Keep activation retries able to repair a local partial commit when Stripe
-- already owns the team-scoped grant reference.
CREATE OR REPLACE FUNCTION activate_team_billing(p_team_id uuid, p_stripe_grant_id text)
RETURNS void
LANGUAGE sql
AS $$
    WITH marked AS (
        UPDATE team_billing_account
        SET trial_ended_at = COALESCE(trial_ended_at, now()),
            stripe_activation_credit_granted_at = COALESCE(stripe_activation_credit_granted_at, now()),
            stripe_activation_credit_grant_id = COALESCE(stripe_activation_credit_grant_id, p_stripe_grant_id),
            updated_at = now()
        WHERE team_id = p_team_id
          AND lower(coalesce(stripe_subscription_status, '')) IN ('active', 'trialing', 'past_due')
          AND (trial_ended_at IS NULL
               OR stripe_activation_credit_granted_at IS NULL
               OR stripe_activation_credit_grant_id IS NULL)
        RETURNING team_id
    ), zeroed AS (
        UPDATE team_credit_grant g
        SET remaining_usd = 0,
            updated_at = now()
        FROM marked
        WHERE g.team_id = marked.team_id
          AND g.reason = 'signup trial credit'
        RETURNING g.team_id
    )
    SELECT 1 FROM marked;
$$;
