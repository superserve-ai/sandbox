-- Persist the transition away from the Superserve trial. Billing eligibility
-- is intentionally derived from normalized subscription state after this
-- transition; the trial balance must never make a former Stripe customer
-- eligible again.
ALTER TABLE team_billing_account
    ADD COLUMN trial_ended_at timestamptz,
    ADD COLUMN stripe_activation_credit_granted_at timestamptz,
    ADD COLUMN stripe_activation_credit_grant_id text;

CREATE TABLE team_trial_eligibility_cache (
    team_id uuid PRIMARY KEY REFERENCES team(id) ON DELETE CASCADE,
    eligible boolean NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_team_credit_grant_team_reason_expiry
    ON team_credit_grant (team_id, reason, expires_at);

ALTER TABLE team_trial_eligibility_cache ENABLE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION refresh_team_trial_eligibility(p_team_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    WITH account AS (
        SELECT trial_ended_at, stripe_subscription_status
        FROM team_billing_account
        WHERE team_id = p_team_id
    ), grant_balance AS (
        SELECT COALESCE(SUM(remaining_usd), 0)::numeric AS remaining_usd,
               COUNT(*)::int AS grant_count
        FROM team_credit_grant
        WHERE team_id = p_team_id
          AND reason = 'signup trial credit'
          AND (expires_at IS NULL OR expires_at > now())
    ), period AS (
        SELECT date_trunc('month', now()) AS period_start,
               date_trunc('month', now()) + interval '1 month' AS period_end
    ), compute AS (
        SELECT
            COALESCE(SUM(EXTRACT(EPOCH FROM (
                LEAST(COALESCE(i.ended_at, now()), period.period_end)
                - GREATEST(i.started_at, period.period_start)
            )) * i.vcpu_count), 0)::numeric AS vcpu_seconds,
            COALESCE(SUM(EXTRACT(EPOCH FROM (
                LEAST(COALESCE(i.ended_at, now()), period.period_end)
                - GREATEST(i.started_at, period.period_start)
            )) * i.memory_mib / 1024.0), 0)::numeric AS memory_gib_seconds
        FROM sandbox_compute_billing_interval i
        CROSS JOIN period
        WHERE i.team_id = p_team_id
          AND i.started_at < period.period_end
          AND COALESCE(i.ended_at, period.period_end) > period.period_start
    ), storage AS (
        SELECT COALESCE(SUM(EXTRACT(EPOCH FROM (
            LEAST(COALESCE(i.ended_at, now()), period.period_end)
            - GREATEST(i.started_at, period.period_start)
        )) * i.disk_mib / 1024.0), 0)::numeric AS storage_gib_seconds
        FROM sandbox_storage_interval i
        CROSS JOIN period
        WHERE i.team_id = p_team_id
          AND i.started_at < period.period_end
          AND COALESCE(i.ended_at, period.period_end) > period.period_start
    ), usage AS (
        SELECT compute.vcpu_seconds, compute.memory_gib_seconds, storage.storage_gib_seconds
        FROM compute, storage
    ), plan AS (
        SELECT COALESCE((
            SELECT tpp.plan_key
            FROM team_pricing_plan tpp
            JOIN pricing_plan pp ON pp.key = tpp.plan_key AND pp.active
            WHERE tpp.team_id = p_team_id
              AND tpp.effective_from <= now()
              AND (tpp.effective_to IS NULL OR tpp.effective_to > now())
            ORDER BY tpp.effective_from DESC
            LIMIT 1
        ), 'payg') AS plan_key
    ), ranked_rates AS (
        SELECT
            r.resource,
            r.unit,
            r.price_usd,
            row_number() OVER (
                PARTITION BY r.resource, r.unit
                ORDER BY r.effective_from DESC, r.created_at DESC, r.id DESC
            ) AS rate_rank
        FROM plan
        JOIN pricing_rate r ON r.plan_key = plan.plan_key
        WHERE r.unit = 'second'
          AND r.effective_from <= now()
          AND (r.effective_to IS NULL OR r.effective_to > now())
    ), rates AS (
        SELECT
            COALESCE(MAX(price_usd) FILTER (WHERE resource = 'vcpu'), 0)::numeric AS vcpu_rate,
            COALESCE(MAX(price_usd) FILTER (WHERE resource = 'memory_gib'), 0)::numeric AS memory_rate,
            COALESCE(MAX(price_usd) FILTER (WHERE resource = 'storage_gib'), 0)::numeric AS storage_rate
        FROM ranked_rates
        WHERE rate_rank = 1
    ), charges AS (
        SELECT usage.vcpu_seconds * rates.vcpu_rate
             + usage.memory_gib_seconds * rates.memory_rate
             + CASE WHEN feature_enabled('billing_storage_billing_enabled', p_team_id)
                    THEN usage.storage_gib_seconds * rates.storage_rate
                    ELSE 0
               END AS amount_usd
        FROM usage, rates
    )
    SELECT CASE
        WHEN COALESCE(account.trial_ended_at, NULL) IS NULL THEN
            grant_balance.grant_count = 0
            OR grant_balance.remaining_usd - charges.amount_usd > 0
        ELSE lower(coalesce(account.stripe_subscription_status, '')) IN ('active', 'trialing', 'past_due')
    END
    FROM (SELECT 1) one
    LEFT JOIN account ON true
    CROSS JOIN grant_balance
    CROSS JOIN charges;
$$;

CREATE OR REPLACE FUNCTION team_sandbox_billing_eligible(p_team_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    SELECT CASE
        WHEN account.trial_ended_at IS NULL THEN
            (grant_balance.grant_count = 0 AND account.stripe_subscription_id IS NULL)
            OR (account.stripe_subscription_id IS NOT NULL
                AND lower(coalesce(account.stripe_subscription_status, '')) IN ('active', 'trialing', 'past_due'))
            OR (grant_balance.remaining_usd > 0 AND COALESCE(cache.eligible, true))
        ELSE lower(coalesce(account.stripe_subscription_status, '')) IN ('active', 'trialing', 'past_due')
    END
    FROM (SELECT trial_ended_at, stripe_subscription_id, stripe_subscription_status
          FROM team_billing_account WHERE team_id = p_team_id) account
    FULL JOIN (SELECT COALESCE(SUM(remaining_usd), 0)::numeric AS remaining_usd,
                      COUNT(*)::int AS grant_count
               FROM team_credit_grant
               WHERE team_id = p_team_id
                 AND reason = 'signup trial credit'
                 AND (expires_at IS NULL OR expires_at > now())) grant_balance ON true
    LEFT JOIN team_trial_eligibility_cache cache ON cache.team_id = p_team_id;
$$;

CREATE OR REPLACE FUNCTION grant_signup_trial_credit()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO team_credit_grant (team_id, amount_usd, remaining_usd, reason)
    VALUES (NEW.id, 5.000000, 5.000000, 'signup trial credit');
    INSERT INTO team_trial_eligibility_cache (team_id, eligible)
    VALUES (NEW.id, true)
    ON CONFLICT (team_id) DO UPDATE SET eligible = true, updated_at = now();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS team_signup_trial_credit ON team;
CREATE TRIGGER team_signup_trial_credit
AFTER INSERT ON team
FOR EACH ROW
EXECUTE FUNCTION grant_signup_trial_credit();

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
          AND stripe_activation_credit_granted_at IS NULL
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
