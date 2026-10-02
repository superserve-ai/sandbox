-- Expose the authoritative, raw-interval trial balance to billing consumers.
-- Keeping this calculation in Postgres ensures enforcement and the API agree.
CREATE OR REPLACE FUNCTION get_team_trial_balance(p_team_id uuid)
RETURNS TABLE(grant_usd numeric, consumed_usd numeric, remaining_usd numeric, state text, eligible boolean)
LANGUAGE sql STABLE AS $$
WITH account AS (
  SELECT trial_ended_at, stripe_subscription_id, stripe_subscription_status FROM team_billing_account WHERE team_id = p_team_id
), historical_grants AS (
  SELECT COUNT(*)::int AS count
  FROM team_credit_grant
  WHERE team_id = p_team_id AND reason = 'signup trial credit'
), grants AS (
  SELECT COALESCE(SUM(amount_usd), 0)::numeric AS amount, COUNT(*)::int AS count,
         COUNT(*) FILTER (WHERE expires_at IS NULL OR expires_at > now())::int AS active_count,
         COALESCE(MIN(created_at), now()) AS started,
         MAX(expires_at) FILTER (WHERE expires_at IS NOT NULL) AS expires_end
  FROM team_credit_grant WHERE team_id = p_team_id AND reason = 'signup trial credit'
), bounds AS (
  SELECT COALESCE((SELECT trial_ended_at FROM account),
                  CASE WHEN grants.count > 0 AND grants.active_count = 0
                       THEN COALESCE(grants.expires_end, now()) ELSE now() END) AS period_end
  FROM grants
), compute_usage AS (
  SELECT COALESCE(SUM(EXTRACT(EPOCH FROM (LEAST(COALESCE(i.ended_at, bounds.period_end), bounds.period_end) - GREATEST(i.started_at, grants.started))) * i.vcpu_count), 0)::numeric AS cpu,
         COALESCE(SUM(EXTRACT(EPOCH FROM (LEAST(COALESCE(i.ended_at, bounds.period_end), bounds.period_end) - GREATEST(i.started_at, grants.started))) * i.memory_mib / 1024.0), 0)::numeric AS memory
  FROM sandbox_compute_billing_interval i, bounds, grants
  WHERE i.team_id = p_team_id AND i.started_at < bounds.period_end AND COALESCE(i.ended_at, bounds.period_end) > grants.started
), usage AS (
  SELECT compute_usage.cpu,
         compute_usage.memory,
         COALESCE((SELECT SUM(EXTRACT(EPOCH FROM (LEAST(COALESCE(i.ended_at, bounds.period_end), bounds.period_end) - GREATEST(i.started_at, grants.started))) * i.disk_mib / 1024.0) FROM sandbox_storage_interval i, bounds WHERE i.team_id = p_team_id AND i.started_at < bounds.period_end AND COALESCE(i.ended_at, bounds.period_end) > grants.started), 0)::numeric AS storage
  FROM compute_usage, grants
), ranked_rates AS (
  SELECT r.*, row_number() OVER (PARTITION BY r.resource, r.unit ORDER BY r.effective_from DESC, r.created_at DESC, r.id DESC) AS rate_rank
  FROM pricing_rate r JOIN pricing_plan pp ON pp.key = r.plan_key AND pp.active
  WHERE r.plan_key = COALESCE((SELECT plan_key FROM team_pricing_plan tpp JOIN pricing_plan tppp ON tppp.key = tpp.plan_key AND tppp.active WHERE tpp.team_id = p_team_id AND tpp.effective_from <= now() AND (tpp.effective_to IS NULL OR tpp.effective_to > now()) ORDER BY tpp.effective_from DESC LIMIT 1), 'payg')
    AND r.unit = 'second' AND r.effective_from <= now() AND (r.effective_to IS NULL OR r.effective_to > now())
), rates AS (
  SELECT COALESCE(MAX(price_usd) FILTER (WHERE resource = 'vcpu'), 0)::numeric cpu,
         COALESCE(MAX(price_usd) FILTER (WHERE resource = 'memory_gib'), 0)::numeric memory,
         COALESCE(MAX(price_usd) FILTER (WHERE resource = 'storage_gib'), 0)::numeric storage
  FROM ranked_rates WHERE rate_rank = 1
), calc AS (
  SELECT grants.amount, round((usage.cpu * rates.cpu + usage.memory * rates.memory + CASE WHEN feature_enabled('billing_storage_billing_enabled', p_team_id) THEN usage.storage * rates.storage ELSE 0 END)::numeric, 6) consumed,
         grants.count, grants.active_count, historical_grants.count AS historical_count,
         account.trial_ended_at, account.stripe_subscription_id, account.stripe_subscription_status
  FROM grants, historical_grants, usage, rates LEFT JOIN account ON true
)
SELECT amount, consumed,
  CASE WHEN trial_ended_at IS NOT NULL OR stripe_subscription_status IS NOT NULL AND lower(stripe_subscription_status) IN ('active','trialing','past_due') OR (historical_count > 0 AND active_count = 0)
       THEN 0::numeric ELSE round(GREATEST(amount - consumed, 0)::numeric, 6) END,
  CASE WHEN trial_ended_at IS NOT NULL OR stripe_subscription_status IS NOT NULL AND lower(stripe_subscription_status) IN ('active','trialing','past_due') THEN 'ended_by_billing_activation'
       WHEN historical_count = 0 THEN 'no_grant'
       WHEN active_count = 0 THEN 'expired'
       WHEN amount - consumed <= 0 THEN 'exhausted' ELSE 'active' END,
  CASE WHEN trial_ended_at IS NOT NULL OR stripe_subscription_status IS NOT NULL AND lower(stripe_subscription_status) IN ('active','trialing','past_due') THEN lower(COALESCE(stripe_subscription_status, '')) IN ('active','trialing','past_due')
       WHEN historical_count = 0 THEN stripe_subscription_id IS NULL
       WHEN active_count = 0 THEN false
       ELSE amount - consumed > 0 END
FROM calc;
$$;

CREATE OR REPLACE FUNCTION refresh_team_trial_eligibility(p_team_id uuid)
RETURNS boolean LANGUAGE sql STABLE AS $$ SELECT eligible FROM get_team_trial_balance(p_team_id); $$;

-- Keep the enforcement-side eligibility decision terminal for expired signup
-- grants while preserving the legacy no-grant path for teams with no grant.
CREATE OR REPLACE FUNCTION team_sandbox_billing_eligible(p_team_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    SELECT CASE
        WHEN account.trial_ended_at IS NULL THEN
            (grant_balance.historical_count = 0 AND account.stripe_subscription_id IS NULL)
            OR (account.stripe_subscription_id IS NOT NULL
                AND lower(coalesce(account.stripe_subscription_status, '')) IN ('active', 'trialing', 'past_due'))
            OR (grant_balance.remaining_usd > 0 AND COALESCE(cache.eligible, true))
        ELSE lower(coalesce(account.stripe_subscription_status, '')) IN ('active', 'trialing', 'past_due')
    END
    FROM (SELECT trial_ended_at, stripe_subscription_id, stripe_subscription_status
          FROM team_billing_account WHERE team_id = p_team_id) account
    FULL JOIN (SELECT COALESCE(SUM(remaining_usd) FILTER (WHERE expires_at IS NULL OR expires_at > now()), 0)::numeric AS remaining_usd,
                      COUNT(*)::int AS historical_count
               FROM team_credit_grant
               WHERE team_id = p_team_id
                 AND reason = 'signup trial credit') grant_balance ON true
    LEFT JOIN team_trial_eligibility_cache cache ON cache.team_id = p_team_id;
$$;
