-- Reporting views backing the Grafana "Overview" panels (live sandbox count,
-- daily start/resume trend, weekly team spend and sandbox rank). Same reason
-- as weekly_user_metrics (20260529000002): grafana_readonly only has grants
-- on the analytics schema, and every public table has RLS with no policy for
-- that role, so panels querying public.sandbox/activity/team directly fail
-- with "permission denied". These views live in analytics, are not
-- security_invoker, and so run with the view owner's privileges through RLS
-- — same trick, same schema, already covered by the existing blanket grant.

CREATE OR REPLACE VIEW analytics.active_sandbox_count AS
SELECT count(*) AS active_sandboxes
FROM sandbox
WHERE status = 'active';

CREATE OR REPLACE VIEW analytics.daily_sandbox_starts AS
SELECT date_trunc('day', created_at)::date AS day,
       count(*) AS starts
FROM activity
WHERE category = 'sandbox'
  AND action IN ('started', 'resumed')
  AND status = 'success'
GROUP BY 1;

-- "This week" is evaluated at query time, so these two stay a rolling
-- current-week window rather than a fixed historical rollup.

-- Mirrors the plan/rate resolution in db/queries/billing.sql
-- (GetTeamActivePricingPlan + the ranked_rates pattern) rather than
-- hardcoding payg: a team on a non-payg plan must price its usage against
-- its own plan's rates, and a resource can have more than one rate row
-- with effective_to IS NULL if a new version is inserted without closing
-- the old one, so the "current" rate has to be picked deterministically
-- (newest effective_from, tie-broken by created_at/id) rather than assumed
-- unique.
CREATE OR REPLACE VIEW analytics.weekly_team_spend AS
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
       (SUM(u.vcpu_seconds) * MAX(vcpu_rate.price_usd)
        + SUM(u.memory_mib_seconds) / 1024 * MAX(mem_rate.price_usd)
        + SUM(u.storage_mib_seconds) / 1024 * MAX(storage_rate.price_usd)
       )::numeric(14,6) AS spend_usd
FROM team_billing_usage_hourly u
JOIN team t ON t.id = u.team_id
JOIN team_plan tp ON tp.team_id = u.team_id
LEFT JOIN current_rates vcpu_rate ON vcpu_rate.plan_key = tp.plan_key AND vcpu_rate.resource = 'vcpu'
LEFT JOIN current_rates mem_rate ON mem_rate.plan_key = tp.plan_key AND mem_rate.resource = 'memory_gib'
LEFT JOIN current_rates storage_rate ON storage_rate.plan_key = tp.plan_key AND storage_rate.resource = 'storage_gib'
WHERE u.hour_start >= date_trunc('week', now())
GROUP BY t.name;

CREATE OR REPLACE VIEW analytics.weekly_team_sandbox_count AS
SELECT t.name AS team_name,
       count(*) AS sandbox_count
FROM sandbox s
JOIN team t ON t.id = s.team_id
WHERE s.created_at >= date_trunc('week', now())
GROUP BY t.name;
