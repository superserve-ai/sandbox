-- Apply the cumulative signup-credit eligibility calculation to databases
-- where the original trial-eligibility migration has already run.
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
        SELECT COALESCE(SUM(amount_usd), 0)::numeric AS grant_amount_usd,
               COUNT(*)::int AS grant_count,
               MIN(created_at) AS grant_started_at
        FROM team_credit_grant
        WHERE team_id = p_team_id
          AND reason = 'signup trial credit'
          AND (expires_at IS NULL OR expires_at > now())
    ), period AS (
        SELECT COALESCE(grant_balance.grant_started_at, now()) AS period_start,
               now() AS period_end
        FROM grant_balance
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
            OR grant_balance.grant_amount_usd - charges.amount_usd > 0
        ELSE lower(coalesce(account.stripe_subscription_status, '')) IN ('active', 'trialing', 'past_due')
    END
    FROM (SELECT 1) one
    LEFT JOIN account ON true
    CROSS JOIN grant_balance
    CROSS JOIN charges;
$$;
