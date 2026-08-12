-- Reporting views backing two new Grafana panels: live concurrent sandbox
-- count by region (5m rollup) and failed sandboxes by region over time.
-- Same reason as 20260731000001_grafana_overview_views.sql: grafana_readonly
-- only has grants on the analytics schema (via the blanket ALTER DEFAULT
-- PRIVILEGES in 20260730000002), so panels querying public tables directly
-- fail with "permission denied".

-- Minimal projection of sandbox_active_interval (just the two columns the
-- panel needs) so the live-count panel can reconstruct concurrency at any
-- point in time via generate_series bucketing, without exposing team_id/
-- actor_id through the read-only Grafana connection.
CREATE OR REPLACE VIEW analytics.sandbox_active_interval AS
SELECT started_at, ended_at
FROM sandbox_active_interval;

-- Count of sandboxes that ended up in status='failed', bucketed by day.
--
-- Caveat: there is no dedicated "failed_at" timestamp in the schema.
-- activity never logs failures for sandbox start/resume (only
-- status='success' rows exist there), and reconciler_log.mark_failed only
-- covers the fraction of failures caught by drift detection. updated_at is
-- the best available signal, but it isn't purely a failure timestamp: a
-- historical backfill swept ~1.7k stale rows on 2026-07-15, which shows up
-- as an artificial spike on that date rather than real failures.
CREATE OR REPLACE VIEW analytics.daily_sandbox_failures AS
SELECT date_trunc('day', updated_at)::date AS day,
       count(*) AS failures
FROM sandbox
WHERE status = 'failed'
GROUP BY 1;
