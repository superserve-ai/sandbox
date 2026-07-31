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

CREATE OR REPLACE VIEW analytics.weekly_team_spend AS
WITH rates AS (
    SELECT resource, price_usd
    FROM pricing_rate
    WHERE plan_key = 'payg' AND effective_to IS NULL
)
SELECT t.name AS team_name,
       (SUM(u.vcpu_seconds) * (SELECT price_usd FROM rates WHERE resource = 'vcpu')
       + SUM(u.memory_mib_seconds) / 1024 * (SELECT price_usd FROM rates WHERE resource = 'memory_gib')
       + SUM(u.storage_mib_seconds) / 1024 * (SELECT price_usd FROM rates WHERE resource = 'storage_gib'))::numeric(14,6)
       AS spend_usd
FROM team_billing_usage_hourly u
JOIN team t ON t.id = u.team_id
WHERE u.hour_start >= date_trunc('week', now())
GROUP BY t.name;

CREATE OR REPLACE VIEW analytics.weekly_team_sandbox_count AS
SELECT t.name AS team_name,
       count(*) AS sandbox_count
FROM sandbox s
JOIN team t ON t.id = s.team_id
WHERE s.created_at >= date_trunc('week', now())
GROUP BY t.name;
