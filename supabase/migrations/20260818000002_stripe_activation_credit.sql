-- Stripe owns post-activation monetary credits. Keep only the auditable grant
-- reference in Superserve; never create a local spendable promotional balance.
ALTER TABLE team_billing_account
    ADD COLUMN IF NOT EXISTS stripe_activation_credit_grant_id text;

-- Remove balances created by the earlier local-only implementation. Stripe is
-- authoritative for the promotional credit after this migration.
UPDATE team_credit_grant
SET remaining_usd = 0,
    updated_at = now()
WHERE reason = 'stripe promotional credit'
  AND remaining_usd > 0;

DROP FUNCTION IF EXISTS activate_team_billing(uuid);

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
          AND stripe_activation_credit_grant_id IS NULL
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
