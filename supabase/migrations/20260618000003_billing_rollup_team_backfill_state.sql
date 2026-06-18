-- Tenant-aware hourly billing backfill cursor.
--
-- The original backfill cursor was global. That could skip historical hours
-- for teams whose billing_hourly_rollups flag was disabled while the global
-- cursor passed over their intervals. Per-team cursors let newly enabled teams
-- catch up from the configured backfill start without rewinding other tenants.

CREATE TABLE billing_rollup_team_backfill_state (
    team_id          uuid PRIMARY KEY REFERENCES team(id) ON DELETE CASCADE,
    next_hour_start  timestamptz NOT NULL,
    updated_at       timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_billing_rollup_team_backfill_next_hour
    ON billing_rollup_team_backfill_state(next_hour_start, team_id);

-- This is internal scheduler state. RLS is enabled and no policies are created
-- intentionally: anon/authenticated roles get no direct access, while the
-- control plane scheduler uses the service role to read and advance cursors.
ALTER TABLE public.billing_rollup_team_backfill_state ENABLE ROW LEVEL SECURITY;


-- Bootstrap tenants known to have been covered by the old global cursor so
-- deploying this migration does not rewind them to the full backfill lookback.
-- Teams with explicit team-level billing_hourly_rollups overrides are left
-- unseeded because team_feature_flag only stores current state: a currently
-- enabled override may have been disabled while the old global cursor advanced.
-- Those teams initialize from the configured backfill start when the scheduler
-- next sees them enabled, preserving catch-up for skipped hours.
WITH global_cursor AS (
    SELECT next_hour_start
    FROM billing_rollup_backfill_state
    WHERE name = 'hourly'
),
candidate_teams AS (
    SELECT DISTINCT team_id
    FROM (
        SELECT team_id FROM sandbox_compute_billing_interval
        UNION
        SELECT team_id FROM sandbox_storage_interval
    ) billing_teams
    WHERE feature_enabled('billing_hourly_rollups', billing_teams.team_id)
      AND NOT EXISTS (
          SELECT 1
          FROM team_feature_flag tff
          WHERE tff.team_id = billing_teams.team_id
            AND tff.key = 'billing_hourly_rollups'
      )
)
INSERT INTO billing_rollup_team_backfill_state (team_id, next_hour_start)
SELECT candidate_teams.team_id, global_cursor.next_hour_start
FROM candidate_teams
CROSS JOIN global_cursor
ON CONFLICT (team_id) DO NOTHING;
