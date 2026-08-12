-- Reporting views backing two new Grafana panels: live concurrent sandbox
-- count by region (5m rollup) and failed sandboxes by region over time.
-- Same reason as 20260731000001_grafana_overview_views.sql: grafana_readonly
-- only has grants on the analytics schema (via the blanket ALTER DEFAULT
-- PRIVILEGES in 20260730000002), so panels querying public tables directly
-- fail with "permission denied".

-- Durable failure timestamp: set once, when a sandbox is actually marked
-- failed (see MarkSandboxFailed / MarkSandboxFailedInTeam below), and never
-- overwritten afterward — including by DestroySandbox, which only touches
-- status/destroyed_at/updated_at on cleanup. Nullable and never backfilled:
-- sandboxes that failed before this column existed simply have no
-- failed_at, which is correct since their real failure time isn't known.
ALTER TABLE sandbox ADD COLUMN IF NOT EXISTS failed_at timestamptz;

-- Minimal projection of sandbox_active_interval (just the two columns the
-- panel needs) so the live-count panel can reconstruct concurrency at any
-- point in time via generate_series bucketing, without exposing team_id/
-- actor_id through the read-only Grafana connection.
CREATE OR REPLACE VIEW analytics.sandbox_active_interval AS
SELECT started_at, ended_at
FROM sandbox_active_interval;

-- sandbox.status alone can't drive a failures-over-time trend: DestroySandbox
-- rewrites 'failed' to 'deleted' on cleanup (and bumps updated_at), so a
-- day's count would silently shrink as failed sandboxes get reaped later.
-- failed_at is set once, at the moment a sandbox is actually marked failed
-- (see MarkSandboxFailed / MarkSandboxFailedInTeam), and is never touched by
-- the delete path, so it stays a durable per-sandbox failure event even
-- after the row moves on to 'deleted'. Rows failed before this column
-- existed have failed_at NULL and are excluded rather than misdated.
CREATE OR REPLACE VIEW analytics.daily_sandbox_failures AS
SELECT date_trunc('day', failed_at)::date AS day,
       count(*) AS failures
FROM sandbox
WHERE failed_at IS NOT NULL
GROUP BY 1;
