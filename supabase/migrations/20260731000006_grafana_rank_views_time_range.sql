-- Replaces weekly_team_spend / weekly_team_sandbox_count with row-level
-- views so the Grafana rank-chart panels can filter by the dashboard's
-- own time range ($__timeFilter) instead of a "this week" window baked
-- into the view. Aggregation (SUM/COUNT, GROUP BY team, ORDER BY, LIMIT)
-- now happens in the panel query, same pattern as daily_sandbox_starts.

DROP VIEW IF EXISTS analytics.weekly_team_spend;
DROP VIEW IF EXISTS analytics.weekly_team_sandbox_count;

-- One row per team per billing hour, priced as of that hour rather than
-- now(): this view is queried over arbitrary historical ranges, so
-- resolving against the current wall clock would retroactively reprice
-- all history on every plan/rate change. Mirrors the point-in-time
-- pattern in db/queries/billing.sql (ListPricingRatesForPlanAt), not the
-- current-state pattern (GetTeamActivePricingPlan): no p.active filter,
-- since a plan being deactivated today doesn't undo what was effective
-- during its actual assignment window. LATERAL correlates the resolution
-- to each row's own hour_start.
--
-- Usage before the platform's single, actual pricing-launch instant
-- prices at 0: that usage was genuinely unpriced pre-launch, a
-- historical fact independent of team or plan. The instant is the
-- effective_from of the initial payg rates
-- (20260617000003_billing_pricing_credits.sql), pinned as a literal
-- rather than computed as MIN(effective_from) over pricing_rate: a later
-- rate inserted with an earlier effective_from must not move the
-- boundary and flip already-zero-priced hours to NULL. The boundary
-- check comes before the rate match in each CASE for the same reason: a
-- backdated rate must not start charging pre-launch hours either.
-- Past that instant, a resource with no matching rate
-- resolves to NULL instead of 0, whether that's a one-off gap between two
-- rate periods or a custom plan that never defined the resource at all,
-- the same "can't price this" signal handlers_platform_billing.go's
-- pricing_unavailable surfaces, deliberately not silently zeroed. A
-- single fixed launch instant (not a per-resource "first rate ever seen")
-- matters here: the latter would zero an eternally incomplete plan's
-- missing resource forever, not just during launch.
--
-- A plain SUM(spend_usd) ignores NULL rows, so a range mixing priced and
-- unpriceable hours would still return a plausible-looking partial total
-- instead of surfacing the gap — the same silent-understatement failure
-- mode this view exists to avoid. Aggregating queries (the Grafana panel
-- included) must poison the whole total instead:
--   SELECT team_name,
--          CASE WHEN bool_and(spend_usd IS NOT NULL) THEN SUM(spend_usd) ELSE NULL END
--   FROM analytics.team_hourly_spend
--   GROUP BY team_name
-- See TestAnalyticsTeamHourlySpend_MixedRangePoisonsAggregate.
CREATE OR REPLACE VIEW analytics.team_hourly_spend AS
SELECT t.name AS team_name,
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

-- One row per sandbox creation event.
CREATE OR REPLACE VIEW analytics.team_sandbox_events AS
SELECT t.name AS team_name,
       s.created_at
FROM sandbox s
JOIN team t ON t.id = s.team_id;
