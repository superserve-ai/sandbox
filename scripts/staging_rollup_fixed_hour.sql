-- Read-only, one fixed fully closed UTC hour; source-equivalent to deployed7bfa.
-- Replace __FIXED_HOUR_START_UTC__ once with an exact UTC hour timestamp.
-- Reuse the SAME timestamp before/after. Maximum50candidate teams.
-- If candidate_limit_exceeded=true or valid_closed_hour=false, do not interpret totals.
WITH fixed_window AS MATERIALIZED (
 SELECT timestamptz '__FIXED_HOUR_START_UTC__' AS hour_start,
        timestamptz '__FIXED_HOUR_START_UTC__' + interval '1 hour' AS hour_end
), valid_window AS MATERIALIZED (
 SELECT * FROM fixed_window WHERE hour_start=(date_trunc('hour',hour_start AT TIME ZONE 'UTC') AT TIME ZONE 'UTC')
 AND hour_end<=now()
), candidate_ids AS MATERIALIZED (
 SELECT i.team_id FROM sandbox_compute_billing_interval i CROSS JOIN valid_window w
 WHERE i.started_at<w.hour_end AND COALESCE(i.ended_at,w.hour_end)>w.hour_start
 UNION
 SELECT i.team_id FROM sandbox_storage_interval i CROSS JOIN valid_window w
 WHERE i.started_at<w.hour_end AND COALESCE(i.ended_at,w.hour_end)>w.hour_start
 UNION
 SELECT h.team_id FROM team_billing_usage_hourly h CROSS JOIN valid_window w WHERE h.hour_start=w.hour_start
 UNION
 SELECT j.team_id FROM billing_rollup_job j CROSS JOIN valid_window w WHERE j.hour_start=w.hour_start
), candidate_count AS MATERIALIZED (SELECT count(*) AS n FROM candidate_ids), bounded AS MATERIALIZED (
 SELECT c.team_id,w.* FROM candidate_ids c CROSS JOIN valid_window w CROSS JOIN candidate_count n WHERE n.n<=50
), evidence AS MATERIALIZED (
 SELECT b.*, feature_enabled('billing_hourly_rollups',b.team_id) AS enabled,
 storage_reports_complete_through(b.team_id,b.hour_end) AS reports_complete,
 h.team_id IS NOT NULL AS hourly_present, h.hour_end AS stored_hour_end,h.updated_at AS hourly_updated_at,
 h.vcpu_seconds AS hourly_cpu,h.memory_mib_seconds AS hourly_memory,h.storage_mib_seconds AS hourly_storage,
 raw.team_id IS NOT NULL AS raw_ready,raw.vcpu_seconds AS raw_cpu,
 raw.memory_mib_seconds AS raw_memory,raw.storage_mib_seconds AS raw_storage,
 j.status AS job_status,j.attempt_count,j.locked_until,j.completed_at AS job_completed_at
 FROM bounded b
 LEFT JOIN team_billing_usage_hourly h ON h.team_id=b.team_id AND h.hour_start=b.hour_start
 LEFT JOIN billing_rollup_job j ON j.team_id=b.team_id AND j.hour_start=b.hour_start
 LEFT JOIN LATERAL (
WITH compute AS (
    SELECT
        COALESCE(SUM(
            EXTRACT(EPOCH FROM (
                LEAST(COALESCE(i.ended_at, billing_request_now()), b.hour_end)
                - GREATEST(i.started_at, b.hour_start)
            )) * i.vcpu_count
        ), 0)::numeric AS vcpu_seconds,
        COALESCE(SUM(
            EXTRACT(EPOCH FROM (
                LEAST(COALESCE(i.ended_at, billing_request_now()), b.hour_end)
                - GREATEST(i.started_at, b.hour_start)
            )) * i.memory_mib
        ), 0)::numeric AS memory_mib_seconds
    FROM sandbox_compute_billing_interval i
    WHERE i.team_id = b.team_id
      AND i.started_at < b.hour_end
      AND b.hour_start < LEAST(billing_request_now(), b.hour_end)
      AND COALESCE(i.ended_at, LEAST(billing_request_now(), b.hour_end)) > b.hour_start
),
artifact_bounds AS (
    SELECT
        s.id,
        s.team_id,
        s.snapshot_id,
        s.template_id,
        s.base_path,
        s.delta_path,
        s.destroyed_at,
        first_interval.started_at AS billing_started_at
    FROM sandbox s
    LEFT JOIN LATERAL (
        SELECT MIN(i.started_at) AS started_at
        FROM sandbox_storage_interval i
        WHERE i.sandbox_id = s.id
          AND i.team_id = s.team_id
    ) first_interval ON true
    WHERE s.team_id = b.team_id
      AND first_interval.started_at IS NOT NULL
      AND first_interval.started_at < LEAST(billing_request_now(), b.hour_end)
      AND s.created_at < LEAST(billing_request_now(), b.hour_end)
      AND COALESCE(s.destroyed_at, LEAST(billing_request_now(), b.hour_end)) > b.hour_start
),
artifact_storage AS (
    SELECT FLOOR(COALESCE(SUM(ar.artifact_mib * EXTRACT(EPOCH FROM (upper(r) - lower(r)))), 0))::numeric AS mib_seconds
    FROM (
        SELECT p.path,
               MAX(COALESCE(NULLIF(am.allocated_bytes, 0), 0))::numeric / 1048576.0 AS artifact_mib,
               range_agg(tstzrange(GREATEST(s.billing_started_at, b.hour_start), LEAST(COALESCE(s.destroyed_at, billing_request_now()), b.hour_end), '[)')) AS retained_ranges
        FROM artifact_bounds s
        LEFT JOIN template t ON t.id = s.template_id
        CROSS JOIN LATERAL unnest(ARRAY[s.base_path, s.delta_path, CASE WHEN s.base_path IS NULL AND s.delta_path IS NULL THEN t.rootfs_path END]) AS p(path)
        LEFT JOIN artifact_manifest am ON (am.snapshot_id = s.snapshot_id OR am.template_id = t.id)
          AND am.path = p.path
        WHERE p.path IS NOT NULL
        GROUP BY p.path
    ) ar
    CROSS JOIN LATERAL unnest(ar.retained_ranges) AS ranges(r)
),
storage AS (
    SELECT COALESCE(SUM(
        EXTRACT(EPOCH FROM (
            LEAST(COALESCE(i.ended_at, billing_request_now()), b.hour_end)
            - GREATEST(i.started_at, b.hour_start)
        )) * i.disk_mib
    ), 0)::numeric + COALESCE(MAX(artifact_storage.mib_seconds), 0) AS storage_mib_seconds
    FROM artifact_storage
    LEFT JOIN sandbox_storage_interval i ON
      i.team_id = b.team_id
      AND i.started_at < b.hour_end
      AND b.hour_start < LEAST(billing_request_now(), b.hour_end)
      AND COALESCE(i.ended_at, LEAST(billing_request_now(), b.hour_end)) > b.hour_start
),
usage AS (
    SELECT
        b.team_id::uuid AS team_id,
        b.hour_start::timestamptz AS hour_start,
        b.hour_end::timestamptz AS hour_end,
        compute.vcpu_seconds,
        compute.memory_mib_seconds,
        storage.storage_mib_seconds
    FROM compute, storage
    WHERE feature_enabled('billing_hourly_rollups', b.team_id::uuid)
      AND storage_reports_complete_through(b.team_id::uuid, b.hour_end::timestamptz)
)
SELECT * FROM usage
 ) raw ON true
)
SELECT (SELECT hour_start FROM fixed_window) AS fixed_hour_start,
 (SELECT hour_end FROM fixed_window) AS fixed_hour_end,
 EXISTS(SELECT 1 FROM valid_window) AS valid_closed_hour,
 (SELECT n FROM candidate_count) AS candidate_teams,
 (SELECT n>50 FROM candidate_count) AS candidate_limit_exceeded,
 count(*) FILTER(WHERE enabled) AS enabled_teams,
 count(*) FILTER(WHERE enabled AND NOT reports_complete) AS awaiting_source_completeness,
 count(*) FILTER(WHERE raw_ready AND NOT hourly_present) AS missing_hourly_rows,
 count(*) FILTER(WHERE raw_ready AND hourly_present AND stored_hour_end<>hour_end) AS wrong_hour_end,
 count(*) FILTER(WHERE raw_ready AND hourly_present AND
 ROW(raw_cpu,raw_memory,raw_storage) IS DISTINCT FROM ROW(hourly_cpu,hourly_memory,hourly_storage)) AS unequal_team_rows,
 count(*) FILTER(WHERE raw_ready AND hourly_present AND
 ROW(raw_cpu,raw_memory,raw_storage) IS NOT DISTINCT FROM ROW(hourly_cpu,hourly_memory,hourly_storage) AND stored_hour_end=hour_end) AS equal_team_rows,
 count(*) FILTER(WHERE raw_ready AND (raw_cpu<>0 OR raw_memory<>0 OR raw_storage<>0)) AS nonzero_raw_teams,
 sum(raw_cpu) AS raw_cpu_seconds,sum(hourly_cpu) FILTER(WHERE raw_ready) AS hourly_cpu_seconds,
 sum(abs(raw_cpu-hourly_cpu)) FILTER(WHERE raw_ready AND hourly_present) AS absolute_cpu_difference,
 sum(abs(raw_memory-hourly_memory)) FILTER(WHERE raw_ready AND hourly_present) AS absolute_memory_difference,
 sum(abs(raw_storage-hourly_storage)) FILTER(WHERE raw_ready AND hourly_present) AS absolute_storage_difference,
 min(hourly_updated_at) FILTER(WHERE enabled) AS oldest_hourly_update,
 max(job_completed_at + interval '1 hour') FILTER(WHERE job_status='completed') AS latest_completed_refresh_eligible_after,
 count(*) FILTER(WHERE job_status='completed' AND job_completed_at<now()-interval '1 hour') AS completed_refresh_eligible_now,
 count(*) FILTER(WHERE job_status='pending') AS pending_jobs,
 count(*) FILTER(WHERE job_status='running') AS running_jobs,
 count(*) FILTER(WHERE job_status='failed') AS failed_jobs,
 count(*) FILTER(WHERE job_status IN('pending','failed') AND attempt_count>=5) AS exhausted_jobs
FROM evidence;
