package billing

// ExportRemeasurementSQL uses the same raw interval and artifact semantics as
// the authoritative close snapshot. It is only used at boundaries or by operators.
const ExportRemeasurementSQL = `WITH compute AS (
    SELECT
        COALESCE(SUM(
            EXTRACT(EPOCH FROM (
                LEAST(COALESCE(i.ended_at, now()), $3)
                - GREATEST(i.started_at, $2)
            )) * i.vcpu_count
        ), 0)::numeric AS vcpu_seconds,
        COALESCE(SUM(
            EXTRACT(EPOCH FROM (
                LEAST(COALESCE(i.ended_at, now()), $3)
                - GREATEST(i.started_at, $2)
            )) * i.memory_mib
        ), 0)::numeric AS memory_mib_seconds
    FROM sandbox_compute_billing_interval i
    WHERE i.team_id = $1
      AND $2 < LEAST(now(), $3)
      AND i.started_at < LEAST(now(), $3)
      AND COALESCE(i.ended_at, LEAST(now(), $3)) > $2
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
    WHERE s.team_id = $1
      AND first_interval.started_at IS NOT NULL
      AND first_interval.started_at < LEAST(now(), $3)
      AND s.created_at < LEAST(now(), $3)
      AND COALESCE(s.destroyed_at, LEAST(now(), $3)) > $2
),
artifact_storage AS (
    SELECT FLOOR(COALESCE(SUM(ar.artifact_mib * EXTRACT(EPOCH FROM (upper(r) - lower(r)))), 0))::numeric AS mib_seconds
    FROM (
        SELECT p.path,
               MAX(COALESCE(NULLIF(am.allocated_bytes, 0), 0))::numeric / 1048576.0 AS artifact_mib,
               range_agg(tstzrange(GREATEST(s.billing_started_at, $2), LEAST(COALESCE(s.destroyed_at, now()), $3), '[)')) AS retained_ranges
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
            LEAST(COALESCE(i.ended_at, now()), $3)
            - GREATEST(i.started_at, $2)
        )) * i.disk_mib
    ), 0)::numeric + COALESCE(MAX(artifact_storage.mib_seconds), 0) AS storage_mib_seconds
    FROM artifact_storage
    LEFT JOIN sandbox_storage_interval i ON
      i.team_id = $1
      AND $2 < LEAST(now(), $3)
      AND i.started_at < LEAST(now(), $3)
      AND COALESCE(i.ended_at, LEAST(now(), $3)) > $2
)
SELECT compute.vcpu_seconds,compute.memory_mib_seconds,storage.storage_mib_seconds FROM compute,storage`
