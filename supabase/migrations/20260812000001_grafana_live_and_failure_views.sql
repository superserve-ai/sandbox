-- Reporting views backing two new Grafana panels: live concurrent sandbox
-- count by region (5m rollup) and failed sandboxes by region over time.
-- Same reason as 20260731000001_grafana_overview_views.sql: grafana_readonly
-- only has grants on the analytics schema (via the blanket ALTER DEFAULT
-- PRIVILEGES in 20260730000002), so panels querying public tables directly
-- fail with "permission denied".

-- Durable failure timestamp. Nullable and never backfilled: sandboxes that
-- failed before this column existed simply have no failed_at, which is
-- correct since their real failure time isn't known.
ALTER TABLE sandbox ADD COLUMN IF NOT EXISTS failed_at timestamptz;

-- Set at the DB layer rather than in each Go call site: a migration-first
-- deploy leaves the old API revision serving (with the old binary that has
-- never heard of failed_at) for the whole window between this migration
-- landing and the new image rolling out, so any app-level "set failed_at
-- when writing 'failed'" convention would silently lose every failure that
-- lands during that window, permanently — nothing revisits the row later
-- to backfill it. A trigger applies the moment this migration runs,
-- independent of which binary revision is writing, and also covers any
-- future write path that forgets the convention. Never overwrites an
-- existing failed_at (a later UPDATE that leaves status='failed' unchanged,
-- e.g. a metadata patch, must not move the timestamp), and DestroySandbox
-- doesn't touch failed_at at all, so it survives the row moving on to
-- 'deleted'.
CREATE OR REPLACE FUNCTION sandbox_failed_at_on_transition()
    RETURNS trigger
    LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status = 'failed' AND NEW.failed_at IS NULL THEN
        NEW.failed_at := now();
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_sandbox_failed_at_on_transition
    BEFORE INSERT OR UPDATE OF status ON sandbox
    FOR EACH ROW
    EXECUTE FUNCTION sandbox_failed_at_on_transition();

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
-- failed_at (set by the trigger above) is a durable per-sandbox failure
-- event that survives the row moving on to 'deleted'. Rows failed before
-- this column existed have failed_at NULL and are excluded rather than
-- misdated.
CREATE OR REPLACE VIEW analytics.daily_sandbox_failures AS
SELECT date_trunc('day', failed_at)::date AS day,
       count(*) AS failures
FROM sandbox
WHERE failed_at IS NOT NULL
GROUP BY 1;
