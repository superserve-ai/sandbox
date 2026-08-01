-- Exposes team.home_region on the per-team analytics views so a cell's
-- Grafana panels can filter to teams actually homed there.
--
-- When a team migrates between cells, its team_id and historical usage
-- rows can still be present in the source cell's database even though
-- team.home_region now points at the destination cell (rows are copied at
-- cutover, and only the destination cell accrues new usage afterward).
-- Without a region filter, a migrated team's pre-cutover usage still gets
-- ranked on both cells' dashboards for the overlapping window.
DROP VIEW IF EXISTS analytics.team_hourly_spend;
DROP VIEW IF EXISTS analytics.team_sandbox_events;

CREATE OR REPLACE VIEW analytics.team_hourly_spend AS
SELECT t.name AS team_name,
       t.home_region,
       u.hour_start,
       (CASE WHEN u.hour_start < pl.at THEN 0
             WHEN vcpu_rate.price_usd IS NOT NULL THEN u.vcpu_seconds * vcpu_rate.price_usd
             ELSE NULL END
        + CASE WHEN u.hour_start < pl.at THEN 0
             WHEN mem_rate.price_usd IS NOT NULL THEN u.memory_mib_seconds / 1024 * mem_rate.price_usd
             ELSE NULL END
        + CASE WHEN u.hour_start < pl.at THEN 0
             WHEN storage_rate.price_usd IS NOT NULL THEN u.storage_mib_seconds / 1024 * storage_rate.price_usd
             ELSE NULL END
       )::numeric(14,6) AS spend_usd
FROM team_billing_usage_hourly u
JOIN team t ON t.id = u.team_id
CROSS JOIN (SELECT '2026-06-17 00:00:00+00'::timestamptz AS at) pl
CROSS JOIN LATERAL (
    SELECT COALESCE((
        SELECT tpp.plan_key
        FROM team_pricing_plan tpp
        JOIN pricing_plan p ON p.key = tpp.plan_key
        WHERE tpp.team_id = u.team_id
          AND tpp.effective_from <= u.hour_start
          AND (tpp.effective_to IS NULL OR tpp.effective_to > u.hour_start)
        ORDER BY tpp.effective_from DESC
        LIMIT 1
    ), 'payg') AS plan_key
) tp
LEFT JOIN LATERAL (
    SELECT r.price_usd FROM pricing_rate r
    WHERE r.plan_key = tp.plan_key AND r.resource = 'vcpu'
      AND r.effective_from <= u.hour_start
      AND (r.effective_to IS NULL OR r.effective_to > u.hour_start)
    ORDER BY r.effective_from DESC, r.created_at DESC, r.id DESC LIMIT 1
) vcpu_rate ON true
LEFT JOIN LATERAL (
    SELECT r.price_usd FROM pricing_rate r
    WHERE r.plan_key = tp.plan_key AND r.resource = 'memory_gib'
      AND r.effective_from <= u.hour_start
      AND (r.effective_to IS NULL OR r.effective_to > u.hour_start)
    ORDER BY r.effective_from DESC, r.created_at DESC, r.id DESC LIMIT 1
) mem_rate ON true
LEFT JOIN LATERAL (
    SELECT r.price_usd FROM pricing_rate r
    WHERE r.plan_key = tp.plan_key AND r.resource = 'storage_gib'
      AND r.effective_from <= u.hour_start
      AND (r.effective_to IS NULL OR r.effective_to > u.hour_start)
    ORDER BY r.effective_from DESC, r.created_at DESC, r.id DESC LIMIT 1
) storage_rate ON true;

CREATE OR REPLACE VIEW analytics.team_sandbox_events AS
SELECT t.name AS team_name,
       t.home_region,
       s.created_at
FROM sandbox s
JOIN team t ON t.id = s.team_id;
