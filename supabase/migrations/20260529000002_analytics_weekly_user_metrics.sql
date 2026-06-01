-- analytics schema holds derived / rollup objects used for product reporting.
-- Operational tables stay in public; analytics is read-only from the app's
-- perspective and can be dropped & rebuilt without touching prod data.

CREATE SCHEMA IF NOT EXISTS analytics;

-- Grants to service_role are Supabase-specific; vanilla Postgres (used by
-- CI / integration tests) doesn't have that role. Guard with a role-exists
-- check so the migration runs unchanged in both environments.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
    GRANT USAGE ON SCHEMA analytics TO service_role;
    ALTER DEFAULT PRIVILEGES IN SCHEMA analytics GRANT SELECT ON TABLES TO service_role;
  END IF;
END $$;

-- weekly_user_metrics: one row per ISO week (Mon–Sun, UTC) from the first
-- signup through the current week.
--
--   signups          rows in profile with created_at in the week
--   wau              distinct actor_id with an active interval overlapping the week
--   returning_users  subset of wau whose first ever active interval was in a prior week
--   *_wow            absolute change from prior week
--   *_wow_pct        pct change from prior week; NULL when prior week was 0
--
-- Filter at read time, e.g.:
--   SELECT * FROM analytics.weekly_user_metrics
--   WHERE week_start >= now() - interval '12 weeks' ORDER BY week_start;

CREATE OR REPLACE VIEW analytics.weekly_user_metrics AS

-- 1. Enumerate every ISO week from the earliest signup through this week.
WITH weeks AS (
    SELECT generate_series(
        (SELECT date_trunc('week', MIN(created_at) AT TIME ZONE 'utc') FROM profile),
        date_trunc('week', now() AT TIME ZONE 'utc'),
        interval '1 week'
    )::date AS week_start
),

-- 2. Signups per week.
signups AS (
    SELECT date_trunc('week', created_at AT TIME ZONE 'utc')::date AS week_start,
           COUNT(*) AS n
    FROM profile
    GROUP BY 1
),

-- 3. Each (week, actor) pair where the actor had an active interval overlapping
--    the week. Overlap: started before week end AND not yet ended by week start.
--    Both sides of the comparison are converted to naive UTC timestamps so the
--    boundary is timezone-independent of the session running this query.
active_in_week AS (
    SELECT w.week_start, i.actor_id
    FROM weeks w
    JOIN sandbox_active_interval i
      ON  i.actor_id IS NOT NULL
      AND (i.started_at AT TIME ZONE 'utc') <  w.week_start + interval '1 week'
      AND (i.ended_at IS NULL OR (i.ended_at AT TIME ZONE 'utc') >= w.week_start)
    GROUP BY 1, 2
),

-- 4. The ISO week of each actor's very first active interval.
first_active_week AS (
    SELECT actor_id,
           date_trunc('week', MIN(started_at) AT TIME ZONE 'utc')::date AS week_start
    FROM sandbox_active_interval
    WHERE actor_id IS NOT NULL
    GROUP BY actor_id
),

-- 5. WAU = distinct actors active in the week.
wau AS (
    SELECT week_start, COUNT(*) AS n
    FROM active_in_week
    GROUP BY 1
),

-- 6. Returning = actors active this week whose first active week was earlier.
returning_per_week AS (
    SELECT a.week_start, COUNT(*) AS n
    FROM active_in_week a
    JOIN first_active_week f USING (actor_id)
    WHERE f.week_start < a.week_start
    GROUP BY 1
),

-- 7. Stitch the three metrics onto every week (zero-fill missing weeks).
weekly AS (
    SELECT w.week_start,
           COALESCE(s.n, 0) AS signups,
           COALESCE(u.n, 0) AS wau,
           COALESCE(r.n, 0) AS returning_users
    FROM weeks w
    LEFT JOIN signups            s USING (week_start)
    LEFT JOIN wau                u USING (week_start)
    LEFT JOIN returning_per_week r USING (week_start)
),

-- 8. Attach the prior week's value for each metric so the final SELECT is flat.
with_prev AS (
    SELECT week_start,
           signups,         LAG(signups)         OVER w AS prev_signups,
           wau,             LAG(wau)             OVER w AS prev_wau,
           returning_users, LAG(returning_users) OVER w AS prev_returning
    FROM weekly
    WINDOW w AS (ORDER BY week_start)
)

-- WoW deltas. pct is NULL when prior week was 0 (avoids div-by-zero / inf).
SELECT week_start,
       signups,
       signups - prev_signups AS signups_wow,
       CASE WHEN prev_signups > 0
            THEN ROUND(100.0 * (signups - prev_signups) / prev_signups, 1)
       END AS signups_wow_pct,
       wau,
       wau - prev_wau AS wau_wow,
       CASE WHEN prev_wau > 0
            THEN ROUND(100.0 * (wau - prev_wau) / prev_wau, 1)
       END AS wau_wow_pct,
       returning_users,
       returning_users - prev_returning AS returning_wow,
       CASE WHEN prev_returning > 0
            THEN ROUND(100.0 * (returning_users - prev_returning) / prev_returning, 1)
       END AS returning_wow_pct
FROM with_prev
ORDER BY week_start;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
    GRANT SELECT ON analytics.weekly_user_metrics TO service_role;
  END IF;
END $$;
