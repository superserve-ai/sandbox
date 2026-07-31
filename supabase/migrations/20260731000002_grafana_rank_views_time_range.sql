-- Replaces weekly_team_spend / weekly_team_sandbox_count with row-level
-- views so the Grafana rank-chart panels can filter by the dashboard's
-- own time range ($__timeFilter) instead of a "this week" window baked
-- into the view. Aggregation (SUM/COUNT, GROUP BY team, ORDER BY, LIMIT)
-- now happens in the panel query, same pattern as daily_sandbox_starts.

DROP VIEW IF EXISTS analytics.weekly_team_spend;
DROP VIEW IF EXISTS analytics.weekly_team_sandbox_count;

-- One row per team per billing hour. Plan/rate resolution mirrors
-- db/queries/billing.sql (GetTeamActivePricingPlan + ranked_rates), same
-- reasoning as before: a team's usage prices against its own plan, and
-- rate selection is deterministic even with multiple effective_to IS NULL
-- rows for a resource.
CREATE OR REPLACE VIEW analytics.team_hourly_spend AS
WITH team_plan AS (
    SELECT t.id AS team_id,
           COALESCE((
               SELECT tpp.plan_key
               FROM team_pricing_plan tpp
               JOIN pricing_plan p ON p.key = tpp.plan_key
               WHERE tpp.team_id = t.id
                 AND p.active
                 AND tpp.effective_from <= now()
                 AND (tpp.effective_to IS NULL OR tpp.effective_to > now())
               ORDER BY tpp.effective_from DESC
               LIMIT 1
           ), 'payg') AS plan_key
    FROM team t
),
ranked_rates AS (
    SELECT r.plan_key, r.resource, r.price_usd,
           row_number() OVER (
               PARTITION BY r.plan_key, r.resource, r.unit
               ORDER BY r.effective_from DESC, r.created_at DESC, r.id DESC
           ) AS rate_rank
    FROM pricing_rate r
    JOIN pricing_plan p ON p.key = r.plan_key
    WHERE p.active
      AND r.effective_from <= now()
      AND (r.effective_to IS NULL OR r.effective_to > now())
),
current_rates AS (
    SELECT plan_key, resource, price_usd FROM ranked_rates WHERE rate_rank = 1
)
SELECT t.name AS team_name,
       u.hour_start,
       (u.vcpu_seconds * vcpu_rate.price_usd
        + u.memory_mib_seconds / 1024 * mem_rate.price_usd
        + u.storage_mib_seconds / 1024 * storage_rate.price_usd
       )::numeric(14,6) AS spend_usd
FROM team_billing_usage_hourly u
JOIN team t ON t.id = u.team_id
JOIN team_plan tp ON tp.team_id = u.team_id
LEFT JOIN current_rates vcpu_rate ON vcpu_rate.plan_key = tp.plan_key AND vcpu_rate.resource = 'vcpu'
LEFT JOIN current_rates mem_rate ON mem_rate.plan_key = tp.plan_key AND mem_rate.resource = 'memory_gib'
LEFT JOIN current_rates storage_rate ON storage_rate.plan_key = tp.plan_key AND storage_rate.resource = 'storage_gib';

-- One row per sandbox creation event.
CREATE OR REPLACE VIEW analytics.team_sandbox_events AS
SELECT t.name AS team_name,
       s.created_at
FROM sandbox s
JOIN team t ON t.id = s.team_id;
