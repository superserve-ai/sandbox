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
-- current-state pattern (GetTeamActivePricingPlan) — no p.active filter,
-- since a plan being deactivated today doesn't undo what was effective
-- during its actual assignment window. LATERAL correlates the resolution
-- to each row's own hour_start.
--
-- Usage recorded before a resource ever had ANY effective rate (real gap:
-- usage starts 2026-04-14, payg rates start 2026-06-17, the platform's
-- actual pricing launch date) prices at 0 — deliberately, that usage was
-- genuinely unpriced pre-launch. But per Codex review on this PR, that must
-- stay narrow: if a rate exists for the resource/plan at some point but not
-- for this specific hour (an incomplete custom plan, or an unintended gap
-- between two rate periods), spend_usd resolves to NULL instead, the same
-- "can't price this" signal handlers_platform_billing.go's pricing_unavailable
-- surfaces — not silently zeroed, which would understate a real charge.
-- SUM() in the panel query drops NULL rows same as it would drop a
-- genuinely-zero row, so a pricing gap still needs separate investigation
-- if the total looks off; this view doesn't error on it.
CREATE OR REPLACE VIEW analytics.team_hourly_spend AS
SELECT t.name AS team_name,
       u.hour_start,
       (CASE
            WHEN vcpu_rate.price_usd IS NOT NULL THEN u.vcpu_seconds * vcpu_rate.price_usd
            WHEN vcpu_rate.first_effective_from IS NULL OR u.hour_start < vcpu_rate.first_effective_from THEN 0
            ELSE NULL
        END
        + CASE
            WHEN mem_rate.price_usd IS NOT NULL THEN u.memory_mib_seconds / 1024 * mem_rate.price_usd
            WHEN mem_rate.first_effective_from IS NULL OR u.hour_start < mem_rate.first_effective_from THEN 0
            ELSE NULL
        END
        + CASE
            WHEN storage_rate.price_usd IS NOT NULL THEN u.storage_mib_seconds / 1024 * storage_rate.price_usd
            WHEN storage_rate.first_effective_from IS NULL OR u.hour_start < storage_rate.first_effective_from THEN 0
            ELSE NULL
        END
       )::numeric(14,6) AS spend_usd
FROM team_billing_usage_hourly u
JOIN team t ON t.id = u.team_id
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
    SELECT
        (SELECT r.price_usd FROM pricing_rate r
         WHERE r.plan_key = tp.plan_key AND r.resource = 'vcpu'
           AND r.effective_from <= u.hour_start
           AND (r.effective_to IS NULL OR r.effective_to > u.hour_start)
         ORDER BY r.effective_from DESC, r.created_at DESC, r.id DESC LIMIT 1) AS price_usd,
        (SELECT MIN(r.effective_from) FROM pricing_rate r
         WHERE r.plan_key = tp.plan_key AND r.resource = 'vcpu') AS first_effective_from
) vcpu_rate ON true
LEFT JOIN LATERAL (
    SELECT
        (SELECT r.price_usd FROM pricing_rate r
         WHERE r.plan_key = tp.plan_key AND r.resource = 'memory_gib'
           AND r.effective_from <= u.hour_start
           AND (r.effective_to IS NULL OR r.effective_to > u.hour_start)
         ORDER BY r.effective_from DESC, r.created_at DESC, r.id DESC LIMIT 1) AS price_usd,
        (SELECT MIN(r.effective_from) FROM pricing_rate r
         WHERE r.plan_key = tp.plan_key AND r.resource = 'memory_gib') AS first_effective_from
) mem_rate ON true
LEFT JOIN LATERAL (
    SELECT
        (SELECT r.price_usd FROM pricing_rate r
         WHERE r.plan_key = tp.plan_key AND r.resource = 'storage_gib'
           AND r.effective_from <= u.hour_start
           AND (r.effective_to IS NULL OR r.effective_to > u.hour_start)
         ORDER BY r.effective_from DESC, r.created_at DESC, r.id DESC LIMIT 1) AS price_usd,
        (SELECT MIN(r.effective_from) FROM pricing_rate r
         WHERE r.plan_key = tp.plan_key AND r.resource = 'storage_gib') AS first_effective_from
) storage_rate ON true;

-- One row per sandbox creation event.
CREATE OR REPLACE VIEW analytics.team_sandbox_events AS
SELECT t.name AS team_name,
       s.created_at
FROM sandbox s
JOIN team t ON t.id = s.team_id;
