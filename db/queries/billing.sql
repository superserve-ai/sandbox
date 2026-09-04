-- name: UpdateHostSandboxStorageMeasurements :execrows
-- Apply trusted host-side overlay allocations without rewriting history.
-- statement_timestamp() is stable for the whole statement, so closing and
-- opening an interval use the exact same measurement boundary.
WITH measurements AS MATERIALIZED (
    SELECT unnest(sqlc.arg(sandbox_ids)::uuid[]) AS sandbox_id,
           unnest(sqlc.arg(disk_mib)::int[]) AS disk_mib
), eligible AS MATERIALIZED (
    SELECT s.id, s.team_id, m.disk_mib
    FROM measurements m
    JOIN sandbox s ON s.id = m.sandbox_id
    WHERE s.host_id = sqlc.arg(host_id)
      AND s.destroyed_at IS NULL
      AND feature_enabled('billing_metrics_write', s.team_id)
), closed AS (
    UPDATE sandbox_storage_interval i
    SET ended_at = statement_timestamp(), end_reason = 'measurement'
    FROM eligible e
    WHERE i.sandbox_id = e.id
      AND i.team_id = e.team_id
      AND i.ended_at IS NULL
      AND i.disk_mib IS DISTINCT FROM e.disk_mib
    RETURNING i.sandbox_id, i.team_id
)
INSERT INTO sandbox_storage_interval (sandbox_id, team_id, disk_mib, started_at)
SELECT e.id, e.team_id, e.disk_mib, statement_timestamp()
FROM eligible e
LEFT JOIN closed c ON c.sandbox_id = e.id AND c.team_id = e.team_id
ON CONFLICT (sandbox_id) WHERE ended_at IS NULL DO NOTHING;

-- name: GetTeamBillingUsage :one
-- Allocated usage for one team clipped to [period_start, period_end).
WITH compute AS (
    SELECT
        COALESCE(SUM(
            EXTRACT(EPOCH FROM (
                LEAST(COALESCE(i.ended_at, now()), sqlc.arg(period_end))
                - GREATEST(i.started_at, sqlc.arg(period_start))
            )) * i.vcpu_count
        ), 0)::numeric AS vcpu_seconds,
        COALESCE(SUM(
            EXTRACT(EPOCH FROM (
                LEAST(COALESCE(i.ended_at, now()), sqlc.arg(period_end))
                - GREATEST(i.started_at, sqlc.arg(period_start))
            )) * i.memory_mib
        ), 0)::numeric AS memory_mib_seconds
    FROM sandbox_compute_billing_interval i
    WHERE i.team_id = sqlc.arg(team_id)
      AND sqlc.arg(period_start) < LEAST(now(), sqlc.arg(period_end))
      AND i.started_at < LEAST(now(), sqlc.arg(period_end))
      AND COALESCE(i.ended_at, LEAST(now(), sqlc.arg(period_end))) > sqlc.arg(period_start)
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
    WHERE s.team_id = sqlc.arg(team_id)
      AND first_interval.started_at IS NOT NULL
      AND first_interval.started_at < LEAST(now(), sqlc.arg(period_end))
      AND s.created_at < LEAST(now(), sqlc.arg(period_end))
      AND COALESCE(s.destroyed_at, LEAST(now(), sqlc.arg(period_end))) > sqlc.arg(period_start)
),
artifact_ranges AS (
    SELECT p.path,
           MAX(COALESCE(NULLIF(am.allocated_bytes, 0), 0))::numeric / 1048576.0 AS artifact_mib,
           range_agg(tstzrange(
               GREATEST(s.billing_started_at, sqlc.arg(period_start)),
               LEAST(COALESCE(s.destroyed_at, now()), sqlc.arg(period_end)), '[)'
           )) AS retained_ranges
    FROM artifact_bounds s
    LEFT JOIN template t ON t.id = s.template_id
    CROSS JOIN LATERAL unnest(ARRAY[
        s.base_path,
        s.delta_path,
        CASE WHEN s.base_path IS NULL AND s.delta_path IS NULL THEN t.rootfs_path END
    ]) AS p(path)
    LEFT JOIN artifact_manifest am ON (am.snapshot_id = s.snapshot_id OR am.template_id = t.id)
      AND am.path = p.path
    WHERE p.path IS NOT NULL
    GROUP BY p.path
),
artifact_storage AS (
    SELECT FLOOR(COALESCE(SUM(artifact_mib * EXTRACT(EPOCH FROM (upper(r) - lower(r)))), 0))::numeric AS mib_seconds
    FROM artifact_ranges ar
    CROSS JOIN LATERAL unnest(ar.retained_ranges) AS ranges(r)
),
storage AS (
    -- Overlay intervals are per sandbox; template artifacts are a separate
    -- distinct-path set so shared bases and deltas are never multiplied by
    -- the number of sandboxes that pin them.
    SELECT COALESCE(SUM(
        EXTRACT(EPOCH FROM (
            LEAST(COALESCE(i.ended_at, now()), sqlc.arg(period_end))
            - GREATEST(i.started_at, sqlc.arg(period_start))
        )) * i.disk_mib
    ), 0)::numeric + COALESCE(MAX(artifact_storage.mib_seconds), 0) AS storage_mib_seconds
    FROM artifact_storage
    LEFT JOIN sandbox_storage_interval i ON
      i.team_id = sqlc.arg(team_id)
      AND sqlc.arg(period_start) < LEAST(now(), sqlc.arg(period_end))
      AND i.started_at < LEAST(now(), sqlc.arg(period_end))
      AND COALESCE(i.ended_at, LEAST(now(), sqlc.arg(period_end))) > sqlc.arg(period_start)
)
SELECT
    sqlc.arg(team_id)::uuid AS team_id,
    sqlc.arg(period_start)::timestamptz AS period_start,
    sqlc.arg(period_end)::timestamptz AS period_end,
    compute.vcpu_seconds,
    (compute.memory_mib_seconds / 1024.0)::numeric AS memory_gib_seconds,
    (storage.storage_mib_seconds / 1024.0)::numeric AS storage_gib_seconds
FROM compute, storage;

-- name: GetActiveTeamBillingPeriod :one
SELECT *
FROM team_billing_period
WHERE team_id = sqlc.arg(team_id)
  AND finalized_at IS NULL
ORDER BY period_start DESC
LIMIT 1;

-- name: UpsertTeamBillingUsage :one
-- Recomputes a team's period rollup from raw intervals. Exported/finalized
-- rows are immutable so a billing export cannot be silently rewritten.
WITH compute AS (
    SELECT
        COALESCE(SUM(
            EXTRACT(EPOCH FROM (
                LEAST(COALESCE(i.ended_at, now()), sqlc.arg(period_end))
                - GREATEST(i.started_at, sqlc.arg(period_start))
            )) * i.vcpu_count
        ), 0)::numeric AS vcpu_seconds,
        COALESCE(SUM(
            EXTRACT(EPOCH FROM (
                LEAST(COALESCE(i.ended_at, now()), sqlc.arg(period_end))
                - GREATEST(i.started_at, sqlc.arg(period_start))
            )) * i.memory_mib
        ), 0)::numeric AS memory_mib_seconds
    FROM sandbox_compute_billing_interval i
    WHERE i.team_id = sqlc.arg(team_id)
      AND sqlc.arg(period_start) < LEAST(now(), sqlc.arg(period_end))
      AND i.started_at < LEAST(now(), sqlc.arg(period_end))
      AND COALESCE(i.ended_at, LEAST(now(), sqlc.arg(period_end))) > sqlc.arg(period_start)
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
    WHERE s.team_id = sqlc.arg(team_id)
      AND first_interval.started_at IS NOT NULL
      AND first_interval.started_at < LEAST(now(), sqlc.arg(period_end))
      AND s.created_at < LEAST(now(), sqlc.arg(period_end))
      AND COALESCE(s.destroyed_at, LEAST(now(), sqlc.arg(period_end))) > sqlc.arg(period_start)
),
artifact_storage AS (
    SELECT FLOOR(COALESCE(SUM(ar.artifact_mib * EXTRACT(EPOCH FROM (upper(r) - lower(r)))), 0))::numeric AS mib_seconds
    FROM (
        SELECT p.path,
               MAX(COALESCE(NULLIF(am.allocated_bytes, 0), 0))::numeric / 1048576.0 AS artifact_mib,
               range_agg(tstzrange(GREATEST(s.billing_started_at, sqlc.arg(period_start)), LEAST(COALESCE(s.destroyed_at, now()), sqlc.arg(period_end)), '[)')) AS retained_ranges
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
            LEAST(COALESCE(i.ended_at, now()), sqlc.arg(period_end))
            - GREATEST(i.started_at, sqlc.arg(period_start))
        )) * i.disk_mib
    ), 0)::numeric + COALESCE(MAX(artifact_storage.mib_seconds), 0) AS storage_mib_seconds
    FROM artifact_storage
    LEFT JOIN sandbox_storage_interval i ON
      i.team_id = sqlc.arg(team_id)
      AND sqlc.arg(period_start) < LEAST(now(), sqlc.arg(period_end))
      AND i.started_at < LEAST(now(), sqlc.arg(period_end))
      AND COALESCE(i.ended_at, LEAST(now(), sqlc.arg(period_end))) > sqlc.arg(period_start)
),
usage AS (
    SELECT
        sqlc.arg(team_id)::uuid AS team_id,
        sqlc.arg(period_start)::timestamptz AS period_start,
        sqlc.arg(period_end)::timestamptz AS period_end,
        compute.vcpu_seconds,
        compute.memory_mib_seconds,
        storage.storage_mib_seconds
    FROM compute, storage
),
upserted AS (
    INSERT INTO team_billing_usage (
        team_id, period_start, period_end,
        vcpu_seconds, memory_mib_seconds, storage_mib_seconds
    )
    SELECT
        usage.team_id,
        usage.period_start,
        usage.period_end,
        usage.vcpu_seconds,
        usage.memory_mib_seconds,
        usage.storage_mib_seconds
    FROM usage
    WHERE NOT EXISTS (
        SELECT 1
        FROM team_billing_period p
        WHERE p.team_id = usage.team_id
          AND p.period_start = usage.period_start
          AND p.period_end = usage.period_end
          AND (
              p.status IN ('exported', 'finalized')
              OR p.exported_at IS NOT NULL
              OR p.finalized_at IS NOT NULL
          )
    )
    ON CONFLICT (team_id, period_start, period_end) DO UPDATE
    SET vcpu_seconds = EXCLUDED.vcpu_seconds,
        memory_mib_seconds = EXCLUDED.memory_mib_seconds,
        storage_mib_seconds = EXCLUDED.storage_mib_seconds,
        updated_at = now()
    WHERE team_billing_usage.finalized_at IS NULL
      AND team_billing_usage.exported_at IS NULL
    RETURNING
        team_id, period_start, period_end,
        vcpu_seconds, memory_mib_seconds, storage_mib_seconds,
        finalized_at, exported_at, updated_at
),
immutable_existing AS (
    SELECT
        existing.team_id,
        existing.period_start,
        existing.period_end,
        existing.vcpu_seconds,
        existing.memory_mib_seconds,
        existing.storage_mib_seconds,
        existing.finalized_at,
        existing.exported_at,
        existing.updated_at
    FROM team_billing_usage existing
    JOIN usage
      ON usage.team_id = existing.team_id
     AND usage.period_start = existing.period_start
     AND usage.period_end = existing.period_end
    WHERE NOT EXISTS (SELECT 1 FROM upserted)
      AND (
          existing.exported_at IS NOT NULL
          OR existing.finalized_at IS NOT NULL
      )
)
SELECT * FROM upserted
UNION ALL
SELECT * FROM immutable_existing
LIMIT 1;

-- name: UpsertTeamBillingUsageHour :one
WITH compute AS (
    SELECT
        COALESCE(SUM(
            EXTRACT(EPOCH FROM (
                LEAST(COALESCE(i.ended_at, billing_request_now()), sqlc.arg(hour_end))
                - GREATEST(i.started_at, sqlc.arg(hour_start))
            )) * i.vcpu_count
        ), 0)::numeric AS vcpu_seconds,
        COALESCE(SUM(
            EXTRACT(EPOCH FROM (
                LEAST(COALESCE(i.ended_at, billing_request_now()), sqlc.arg(hour_end))
                - GREATEST(i.started_at, sqlc.arg(hour_start))
            )) * i.memory_mib
        ), 0)::numeric AS memory_mib_seconds
    FROM sandbox_compute_billing_interval i
    WHERE i.team_id = sqlc.arg(team_id)
      AND i.started_at < sqlc.arg(hour_end)
      AND sqlc.arg(hour_start) < LEAST(billing_request_now(), sqlc.arg(hour_end))
      AND COALESCE(i.ended_at, LEAST(billing_request_now(), sqlc.arg(hour_end))) > sqlc.arg(hour_start)
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
    WHERE s.team_id = sqlc.arg(team_id)
      AND first_interval.started_at IS NOT NULL
      AND first_interval.started_at < LEAST(billing_request_now(), sqlc.arg(hour_end))
      AND s.created_at < LEAST(billing_request_now(), sqlc.arg(hour_end))
      AND COALESCE(s.destroyed_at, LEAST(billing_request_now(), sqlc.arg(hour_end))) > sqlc.arg(hour_start)
),
artifact_storage AS (
    SELECT FLOOR(COALESCE(SUM(ar.artifact_mib * EXTRACT(EPOCH FROM (upper(r) - lower(r)))), 0))::numeric AS mib_seconds
    FROM (
        SELECT p.path,
               MAX(COALESCE(NULLIF(am.allocated_bytes, 0), 0))::numeric / 1048576.0 AS artifact_mib,
               range_agg(tstzrange(GREATEST(s.billing_started_at, sqlc.arg(hour_start)), LEAST(COALESCE(s.destroyed_at, billing_request_now()), sqlc.arg(hour_end)), '[)')) AS retained_ranges
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
            LEAST(COALESCE(i.ended_at, billing_request_now()), sqlc.arg(hour_end))
            - GREATEST(i.started_at, sqlc.arg(hour_start))
        )) * i.disk_mib
    ), 0)::numeric + COALESCE(MAX(artifact_storage.mib_seconds), 0) AS storage_mib_seconds
    FROM artifact_storage
    LEFT JOIN sandbox_storage_interval i ON
      i.team_id = sqlc.arg(team_id)
      AND i.started_at < sqlc.arg(hour_end)
      AND sqlc.arg(hour_start) < LEAST(billing_request_now(), sqlc.arg(hour_end))
      AND COALESCE(i.ended_at, LEAST(billing_request_now(), sqlc.arg(hour_end))) > sqlc.arg(hour_start)
),
usage AS (
    SELECT
        sqlc.arg(team_id)::uuid AS team_id,
        sqlc.arg(hour_start)::timestamptz AS hour_start,
        sqlc.arg(hour_end)::timestamptz AS hour_end,
        compute.vcpu_seconds,
        compute.memory_mib_seconds,
        storage.storage_mib_seconds
    FROM compute, storage
    WHERE feature_enabled('billing_hourly_rollups', sqlc.arg(team_id)::uuid)
)
INSERT INTO team_billing_usage_hourly (
    team_id, hour_start, hour_end,
    vcpu_seconds, memory_mib_seconds, storage_mib_seconds
)
SELECT
    usage.team_id,
    usage.hour_start,
    usage.hour_end,
    usage.vcpu_seconds,
    usage.memory_mib_seconds,
    usage.storage_mib_seconds
FROM usage
ON CONFLICT (team_id, hour_start) DO UPDATE
SET hour_end = EXCLUDED.hour_end,
    vcpu_seconds = EXCLUDED.vcpu_seconds,
    memory_mib_seconds = EXCLUDED.memory_mib_seconds,
    storage_mib_seconds = EXCLUDED.storage_mib_seconds,
    updated_at = now()
RETURNING *;

-- name: ListTeamBillingUsageHourly :many
SELECT *
FROM team_billing_usage_hourly
WHERE team_id = sqlc.arg(team_id)
  AND feature_enabled('tenant_usage_dashboard', team_id)
  AND hour_start >= sqlc.arg(period_start)
  AND hour_start < sqlc.arg(period_end)
ORDER BY hour_start ASC;

-- name: GetTeamBillingUsageRollup :one
SELECT *
FROM team_billing_usage
WHERE team_id = sqlc.arg(team_id)
  AND period_start = sqlc.arg(period_start)
  AND period_end = sqlc.arg(period_end);

-- name: ListTeamBillingPeriods :many
SELECT *
FROM team_billing_period
WHERE team_id = sqlc.arg(team_id)
ORDER BY period_start DESC
LIMIT sqlc.arg(limit_count);

-- name: GetTeamBillingPeriod :one
SELECT *
FROM team_billing_period
WHERE team_id = sqlc.arg(team_id)
  AND period_start = sqlc.arg(period_start)
  AND period_end = sqlc.arg(period_end);

-- name: GetTeamBillingPeriodForUpdate :one
SELECT *
FROM team_billing_period
WHERE team_id = sqlc.arg(team_id)
  AND period_start = sqlc.arg(period_start)
  AND period_end = sqlc.arg(period_end)
FOR UPDATE;

-- name: UpsertTeamBillingPeriod :one
INSERT INTO team_billing_period (team_id, period_start, period_end, status)
SELECT
    sqlc.arg(team_id),
    sqlc.arg(period_start),
    sqlc.arg(period_end),
    sqlc.arg(status)
WHERE NOT EXISTS (
    SELECT 1
    FROM team_billing_period billed
    WHERE billed.team_id = sqlc.arg(team_id)
      AND (billed.period_start, billed.period_end) <>
          (sqlc.arg(period_start), sqlc.arg(period_end))
      AND (
          billed.status = 'exported'
          OR billed.exported_at IS NOT NULL
          OR (
              billed.finalized_at IS NOT NULL
              AND (billed.blocked_reason IS NULL OR billed.blocked_reason NOT IN (
                  'reporting_only_calendar_period', 'discarded_before_billing_cutover'
              ))
          )
      )
      AND tstzrange(billed.period_start, billed.period_end, '[)') &&
          tstzrange(sqlc.arg(period_start), sqlc.arg(period_end), '[)')
)
ON CONFLICT (team_id, period_start, period_end) DO UPDATE
SET status = CASE
        WHEN team_billing_period.status IN ('blocked', 'approved', 'exporting', 'exported')
            THEN team_billing_period.status
        ELSE EXCLUDED.status
    END,
    updated_at = now()
WHERE team_billing_period.finalized_at IS NULL
RETURNING *;

-- name: BlockTeamBillingPeriod :one
UPDATE team_billing_period
SET status = 'blocked',
    blocked_reason = sqlc.arg(blocked_reason),
    blocked_at = now(),
    updated_at = now()
WHERE team_billing_period.team_id = sqlc.arg(team_id)
  AND team_billing_period.period_start = sqlc.arg(period_start)
  AND team_billing_period.period_end = sqlc.arg(period_end)
  AND team_billing_period.status IN ('open', 'validating', 'blocked')
  AND team_billing_period.finalized_at IS NULL
RETURNING *;

-- name: ApproveTeamBillingPeriod :one
UPDATE team_billing_period
SET status = 'approved',
    approved_by = sqlc.arg(approved_by),
    approved_at = now(),
    blocked_reason = NULL,
    blocked_at = NULL,
    updated_at = now()
WHERE team_billing_period.team_id = sqlc.arg(team_id)
  AND team_billing_period.period_start = sqlc.arg(period_start)
  AND team_billing_period.period_end = sqlc.arg(period_end)
  AND team_billing_period.status IN ('validating', 'blocked')
  AND team_billing_period.finalized_at IS NULL
  AND NOT EXISTS (
      SELECT 1
      FROM billing_period_anomaly a
      WHERE a.team_id = team_billing_period.team_id
        AND a.period_start = team_billing_period.period_start
        AND a.period_end = team_billing_period.period_end
        AND a.resolved_at IS NULL
        AND a.severity IN ('error', 'critical')
  )
RETURNING *;

-- name: MarkTeamBillingPeriodExported :one
WITH exported_period AS (
    UPDATE team_billing_period
    SET status = 'exported',
        exported_at = now(),
        updated_at = now()
    WHERE team_billing_period.team_id = sqlc.arg(team_id)
      AND team_billing_period.period_start = sqlc.arg(period_start)
      AND team_billing_period.period_end = sqlc.arg(period_end)
      AND team_billing_period.status IN ('approved', 'exporting')
      AND team_billing_period.finalized_at IS NULL
      AND EXISTS (
          SELECT 1
          FROM team_billing_usage u
          WHERE u.team_id = team_billing_period.team_id
            AND u.period_start = team_billing_period.period_start
            AND u.period_end = team_billing_period.period_end
            AND u.finalized_at IS NULL
      )
      AND feature_enabled('billing_export_enabled', team_billing_period.team_id)
    RETURNING *
),
exported_usage AS (
    UPDATE team_billing_usage u
    SET exported_at = exported_period.exported_at,
        updated_at = now()
    FROM exported_period
    WHERE u.team_id = exported_period.team_id
      AND u.period_start = exported_period.period_start
      AND u.period_end = exported_period.period_end
      AND u.exported_at IS NULL
      AND u.finalized_at IS NULL
    RETURNING u.team_id
)
SELECT *
FROM exported_period;

-- name: MarkTeamBillingPeriodExporting :one
WITH exporting_period AS (
    UPDATE team_billing_period
    SET status = 'exporting',
        updated_at = now()
    WHERE team_billing_period.team_id = sqlc.arg(team_id)
      AND team_billing_period.period_start = sqlc.arg(period_start)
      AND team_billing_period.period_end = sqlc.arg(period_end)
      AND team_billing_period.status IN ('approved', 'exporting', 'exported')
      AND team_billing_period.finalized_at IS NULL
      AND feature_enabled('billing_export_enabled', team_billing_period.team_id)
    RETURNING *
),
exporting_usage AS (
    UPDATE team_billing_usage u
    SET exported_at = COALESCE(u.exported_at, now()),
        updated_at = now()
    FROM exporting_period
    WHERE u.team_id = exporting_period.team_id
      AND u.period_start = exporting_period.period_start
      AND u.period_end = exporting_period.period_end
      AND u.finalized_at IS NULL
    RETURNING u.team_id
)
SELECT *
FROM exporting_period;

-- name: CreateBillingPeriodAnomaly :one
INSERT INTO billing_period_anomaly (
    team_id, period_start, period_end, severity, kind, sandbox_id, details
)
VALUES (
    sqlc.arg(team_id),
    sqlc.arg(period_start),
    sqlc.arg(period_end),
    sqlc.arg(severity),
    sqlc.arg(kind),
    sqlc.narg(sandbox_id),
    sqlc.arg(details)
)
RETURNING *;

-- name: ListUnresolvedBillingPeriodAnomalies :many
SELECT *
FROM billing_period_anomaly
WHERE team_id = sqlc.arg(team_id)
  AND period_start = sqlc.arg(period_start)
  AND period_end = sqlc.arg(period_end)
  AND resolved_at IS NULL
ORDER BY
  CASE severity
    WHEN 'critical' THEN 0
    WHEN 'error' THEN 1
    ELSE 2
  END,
  detected_at ASC;

-- name: ResolveBillingPeriodAnomaly :one
UPDATE billing_period_anomaly
SET resolved_at = now(),
    resolved_by = sqlc.arg(resolved_by)
WHERE billing_period_anomaly.id = sqlc.arg(id)
  AND billing_period_anomaly.resolved_at IS NULL
RETURNING *;

-- name: GetTeamBillingAccount :one
SELECT team_id, stripe_customer_id, stripe_subscription_id, stripe_subscription_status, stripe_invoice_status, stripe_subscription_event_at, current_period_start, current_period_end, commercial_billing_anchor, cancel_at_period_end, created_at, updated_at, trial_ended_at, stripe_activation_credit_granted_at, stripe_activation_credit_grant_id, checkout_initializing_at, checkout_session_id
FROM team_billing_account
WHERE team_id = sqlc.arg(team_id);

-- name: GetTeamBillingAccountByStripeCustomerID :one
SELECT team_id, stripe_customer_id, stripe_subscription_id, stripe_subscription_status, stripe_invoice_status, stripe_subscription_event_at, current_period_start, current_period_end, commercial_billing_anchor, cancel_at_period_end, created_at, updated_at, trial_ended_at, stripe_activation_credit_granted_at, stripe_activation_credit_grant_id, checkout_initializing_at, checkout_session_id
FROM team_billing_account
WHERE stripe_customer_id = sqlc.arg(stripe_customer_id);

-- name: UpsertTeamBillingAccountCustomer :one
INSERT INTO team_billing_account (team_id, stripe_customer_id)
VALUES (sqlc.arg(team_id), sqlc.arg(stripe_customer_id))
ON CONFLICT (team_id) DO UPDATE
SET stripe_customer_id = EXCLUDED.stripe_customer_id,
    updated_at = now()
RETURNING *;

-- name: ClaimTeamCommercialBillingAnchor :one
SELECT claim_team_commercial_billing_anchor(sqlc.arg(team_id), sqlc.arg(anchor))::timestamptz AS commercial_billing_anchor;

-- name: BeginTeamBillingCheckout :one
UPDATE team_billing_account
SET checkout_initializing_at = now(),
    checkout_anchor_snapshot = commercial_billing_anchor,
    checkout_session_id = NULL,
    updated_at = now()
WHERE team_id = sqlc.arg(team_id)
  AND (checkout_initializing_at IS NULL OR checkout_initializing_at < now() - interval '32 minutes')
RETURNING *;

-- name: FinishTeamBillingCheckout :exec
UPDATE team_billing_account
SET checkout_initializing_at = NULL,
    checkout_anchor_snapshot = NULL,
    checkout_session_id = NULL,
    updated_at = now()
WHERE team_id = sqlc.arg(team_id);

-- name: FinishTeamBillingCheckoutIfStartedBefore :exec
UPDATE team_billing_account
SET checkout_initializing_at = NULL,
    checkout_anchor_snapshot = NULL,
    updated_at = now()
WHERE team_id = sqlc.arg(team_id)
  AND checkout_initializing_at <= sqlc.arg(event_at)
  AND checkout_session_id = sqlc.arg(session_id);

-- name: SetTeamBillingCheckoutSession :exec
UPDATE team_billing_account
SET checkout_session_id = sqlc.arg(session_id), updated_at = now()
WHERE team_id = sqlc.arg(team_id)
  AND checkout_initializing_at IS NOT NULL;

-- name: FinishTeamBillingCheckoutForSubscription :exec
UPDATE team_billing_account
SET checkout_initializing_at = NULL,
    checkout_anchor_snapshot = NULL,
    checkout_session_id = NULL,
    updated_at = now()
WHERE team_id = sqlc.arg(team_id)
  AND stripe_subscription_id = sqlc.arg(subscription_id)
  AND checkout_initializing_at IS NOT NULL;

-- name: EstablishBillingCutover :one
SELECT establish_billing_cutover(sqlc.arg(cutover), sqlc.arg(preserved_team_ids)::uuid[])::int AS team_count;

-- name: UpsertTeamBillingAccountSubscription :one
INSERT INTO team_billing_account (
    team_id,
    stripe_customer_id,
    stripe_subscription_id,
    stripe_subscription_status,
    stripe_invoice_status,
    stripe_subscription_event_at,
    current_period_start,
    current_period_end,
    commercial_billing_anchor,
    cancel_at_period_end
)
VALUES (
    sqlc.arg(team_id),
    sqlc.narg(stripe_customer_id),
    sqlc.narg(stripe_subscription_id),
    sqlc.narg(stripe_subscription_status),
    sqlc.narg(stripe_invoice_status),
    sqlc.narg(stripe_subscription_event_at),
    sqlc.narg(current_period_start),
    sqlc.narg(current_period_end),
    COALESCE(sqlc.narg(commercial_billing_anchor)::timestamptz, sqlc.narg(current_period_start)::timestamptz),
    COALESCE(sqlc.narg(cancel_at_period_end), false)
)
ON CONFLICT (team_id) DO UPDATE
SET stripe_customer_id = COALESCE(EXCLUDED.stripe_customer_id, team_billing_account.stripe_customer_id),
    stripe_subscription_id = COALESCE(EXCLUDED.stripe_subscription_id, team_billing_account.stripe_subscription_id),
    stripe_subscription_status = COALESCE(EXCLUDED.stripe_subscription_status, team_billing_account.stripe_subscription_status),
    stripe_invoice_status = COALESCE(EXCLUDED.stripe_invoice_status, team_billing_account.stripe_invoice_status),
    stripe_subscription_event_at = COALESCE(EXCLUDED.stripe_subscription_event_at, team_billing_account.stripe_subscription_event_at),
    current_period_start = COALESCE(EXCLUDED.current_period_start, team_billing_account.current_period_start),
    current_period_end = COALESCE(EXCLUDED.current_period_end, team_billing_account.current_period_end),
    commercial_billing_anchor = COALESCE(team_billing_account.commercial_billing_anchor, EXCLUDED.commercial_billing_anchor),
    cancel_at_period_end = COALESCE(sqlc.narg(cancel_at_period_end), team_billing_account.cancel_at_period_end),
    updated_at = now()
RETURNING *;

-- name: CreateBillingUsageExport :one
INSERT INTO billing_usage_export (
    team_id,
    period_start,
    period_end,
    resource_type,
    stripe_customer_id,
    stripe_meter_event_identifier,
    stripe_idempotency_key,
    stripe_event_name,
    value,
    status,
    error,
    sent_at
)
VALUES (
    sqlc.arg(team_id),
    sqlc.arg(period_start),
    sqlc.arg(period_end),
    sqlc.arg(resource_type),
    sqlc.narg(stripe_customer_id),
    sqlc.arg(stripe_meter_event_identifier),
    sqlc.narg(stripe_idempotency_key),
    sqlc.arg(stripe_event_name),
    sqlc.arg(value),
    sqlc.arg(status),
    sqlc.narg(error),
    sqlc.narg(sent_at)
)
RETURNING *;

-- name: UpdateBillingUsageExportStatus :one
UPDATE billing_usage_export
SET status = sqlc.arg(status),
    error = sqlc.narg(error),
    sent_at = COALESCE(sqlc.narg(sent_at), billing_usage_export.sent_at),
    updated_at = now()
WHERE id = sqlc.arg(id)
RETURNING *;

-- name: MarkBillingUsageExportSent :one
UPDATE billing_usage_export
SET status = 'sent',
    sent_at = sqlc.arg(sent_at),
    updated_at = now()
WHERE id = sqlc.arg(id)
  AND status = 'pending'
RETURNING *;

-- name: SetBillingUsageExportIdempotencyKey :one
UPDATE billing_usage_export
SET stripe_idempotency_key = sqlc.arg(stripe_idempotency_key),
    updated_at = now()
WHERE id = sqlc.arg(id)
  AND (stripe_idempotency_key IS NULL OR stripe_idempotency_key = stripe_meter_event_identifier)
RETURNING *;

-- name: ListBillingUsageExportsForPeriod :many
SELECT *
FROM billing_usage_export
WHERE team_id = sqlc.arg(team_id)
  AND period_start = sqlc.arg(period_start)
  AND period_end = sqlc.arg(period_end)
ORDER BY created_at ASC, id ASC;

-- name: GetBillingUsageExportByIdempotencyKey :one
SELECT *
FROM billing_usage_export
WHERE stripe_idempotency_key = sqlc.arg(stripe_idempotency_key)
ORDER BY created_at DESC, id DESC
LIMIT 1;

-- name: GetBillingUsageExportByIdentifier :one
SELECT *
FROM billing_usage_export
WHERE stripe_meter_event_identifier = sqlc.arg(stripe_meter_event_identifier)
ORDER BY created_at DESC, id DESC
LIMIT 1;

-- name: CreateStripeWebhookEvent :one
INSERT INTO stripe_webhook_event (event_id, event_type, payload)
VALUES (sqlc.arg(event_id), sqlc.arg(event_type), sqlc.arg(payload))
ON CONFLICT (event_id) DO NOTHING
RETURNING *;

-- name: GetStripeWebhookEvent :one
SELECT *
FROM stripe_webhook_event
WHERE event_id = sqlc.arg(event_id);

-- name: GetStripeWebhookEventForUpdate :one
SELECT *
FROM stripe_webhook_event
WHERE event_id = sqlc.arg(event_id)
FOR UPDATE;

-- name: MarkStripeWebhookEventProcessed :one
UPDATE stripe_webhook_event
SET processed_at = now(),
    last_error = NULL,
    updated_at = now()
WHERE event_id = sqlc.arg(event_id)
RETURNING *;

-- name: MarkStripeWebhookEventFailed :one
UPDATE stripe_webhook_event
SET last_error = sqlc.arg(last_error),
    updated_at = now()
WHERE event_id = sqlc.arg(event_id)
RETURNING *;

-- name: IsFeatureEnabledForTeam :one
SELECT feature_enabled(sqlc.arg(key), sqlc.narg(team_id))::boolean AS enabled;

-- name: SetFeatureFlag :one
INSERT INTO feature_flag (key, enabled, description)
VALUES (sqlc.arg(key), sqlc.arg(enabled), sqlc.narg(description))
ON CONFLICT (key) DO UPDATE
SET enabled = EXCLUDED.enabled,
    description = COALESCE(EXCLUDED.description, feature_flag.description),
    updated_at = now()
RETURNING *;

-- name: SetTeamFeatureFlag :one
INSERT INTO team_feature_flag (team_id, key, enabled)
VALUES (sqlc.arg(team_id), sqlc.arg(key), sqlc.arg(enabled))
ON CONFLICT (team_id, key) DO UPDATE
SET enabled = EXCLUDED.enabled,
    updated_at = now()
RETURNING *;

-- name: ListActivePricingRates :many
WITH ranked_rates AS (
    SELECT
        r.plan_key,
        p.name AS plan_name,
        p.currency,
        r.resource,
        r.unit,
        r.price_usd,
        r.effective_from,
        row_number() OVER (
            PARTITION BY r.resource, r.unit
            ORDER BY r.effective_from DESC, r.created_at DESC, r.id DESC
        ) AS rate_rank
    FROM pricing_rate r
    JOIN pricing_plan p ON p.key = r.plan_key
    WHERE r.plan_key = sqlc.arg(plan_key)
      AND p.active
      AND r.effective_from <= now()
      AND (r.effective_to IS NULL OR r.effective_to > now())
)
SELECT
    plan_key,
    plan_name,
    currency,
    resource,
    unit,
    price_usd,
    effective_from
FROM ranked_rates
WHERE rate_rank = 1
ORDER BY resource, unit;

-- name: ListPricingRatesForPlanAt :many
WITH ranked_rates AS (
    SELECT
        r.plan_key,
        p.name AS plan_name,
        p.currency,
        r.resource,
        r.unit,
        r.price_usd,
        r.effective_from,
        row_number() OVER (
            PARTITION BY r.resource, r.unit
            ORDER BY r.effective_from DESC, r.created_at DESC, r.id DESC
        ) AS rate_rank
    FROM pricing_rate r
    JOIN pricing_plan p ON p.key = r.plan_key
    WHERE r.plan_key = sqlc.arg(plan_key)
      AND r.effective_from <= sqlc.arg(effective_at)::timestamptz
      AND (r.effective_to IS NULL OR r.effective_to > sqlc.arg(effective_at)::timestamptz)
)
SELECT
    plan_key,
    plan_name,
    currency,
    resource,
    unit,
    price_usd,
    effective_from
FROM ranked_rates
WHERE rate_rank = 1
ORDER BY resource, unit;

-- name: GetTeamActivePricingPlan :one
SELECT COALESCE((
    SELECT tpp.plan_key
    FROM team_pricing_plan tpp
    JOIN pricing_plan p ON p.key = tpp.plan_key
    WHERE tpp.team_id = sqlc.arg(team_id)
      AND p.active
      AND tpp.effective_from <= now()
      AND (tpp.effective_to IS NULL OR tpp.effective_to > now())
    ORDER BY tpp.effective_from DESC
    LIMIT 1
), 'payg')::text AS plan_key;

-- name: ListActivePricingRatesForTeam :many
WITH selected_plan AS (
    SELECT COALESCE((
        SELECT tpp.plan_key
        FROM team_pricing_plan tpp
        JOIN pricing_plan p ON p.key = tpp.plan_key
        WHERE tpp.team_id = sqlc.arg(team_id)
          AND p.active
          AND tpp.effective_from <= sqlc.arg(effective_at)::timestamptz
          AND (tpp.effective_to IS NULL OR tpp.effective_to > sqlc.arg(effective_at)::timestamptz)
        ORDER BY tpp.effective_from DESC
        LIMIT 1
    ), 'payg')::text AS plan_key
),
ranked_rates AS (
    SELECT
        r.plan_key,
        p.name AS plan_name,
        p.currency,
        r.resource,
        r.unit,
        r.price_usd,
        r.effective_from,
        row_number() OVER (
            PARTITION BY r.resource, r.unit
            ORDER BY r.effective_from DESC, r.created_at DESC, r.id DESC
        ) AS rate_rank
    FROM selected_plan sp
    JOIN pricing_rate r ON r.plan_key = sp.plan_key
    JOIN pricing_plan p ON p.key = r.plan_key
    WHERE p.active
      AND r.effective_from <= sqlc.arg(effective_at)::timestamptz
      AND (r.effective_to IS NULL OR r.effective_to > sqlc.arg(effective_at)::timestamptz)
)
SELECT
    plan_key,
    plan_name,
    currency,
    resource,
    unit,
    price_usd,
    effective_from
FROM ranked_rates
WHERE rate_rank = 1
ORDER BY resource, unit;

-- name: AssignTeamPricingPlan :one
INSERT INTO team_pricing_plan (team_id, plan_key, effective_from, effective_to, assigned_by)
VALUES (
    sqlc.arg(team_id),
    sqlc.arg(plan_key),
    sqlc.arg(effective_from),
    sqlc.narg(effective_to),
    sqlc.narg(assigned_by)
)
RETURNING *;

-- name: ListExportedTeamBillingPeriods :many
WITH ranked AS (
    SELECT
        team_billing_period.*,
        ROW_NUMBER() OVER (
            PARTITION BY team_id
            ORDER BY period_end ASC, period_start ASC
        ) AS team_rank
    FROM team_billing_period
    WHERE finalized_at IS NULL
)
SELECT *
FROM ranked
WHERE team_rank = 1
  AND status = 'exported'
ORDER BY period_end ASC, period_start ASC, team_id ASC
LIMIT sqlc.arg(batch_size);

-- name: GrantTeamCredit :one
INSERT INTO team_credit_grant (
    team_id, amount_usd, remaining_usd, reason, expires_at, created_by
)
VALUES (
    sqlc.arg(team_id),
    sqlc.arg(amount_usd),
    sqlc.arg(amount_usd),
    sqlc.narg(reason),
    sqlc.narg(expires_at),
    sqlc.narg(created_by)
)
RETURNING *;

-- name: GetTeamCreditBalance :one
SELECT COALESCE(SUM(remaining_usd), 0)::numeric AS balance_usd
FROM team_credit_grant
WHERE team_id = sqlc.arg(team_id)
  AND remaining_usd > 0
  AND (expires_at IS NULL OR expires_at > now());

-- name: IsTeamSandboxBillingEligible :one
SELECT team_sandbox_billing_eligible(sqlc.arg(team_id)) AS eligible;

-- name: RefreshTeamTrialEligibility :exec
INSERT INTO team_trial_eligibility_cache (team_id, eligible, updated_at)
SELECT sqlc.arg(team_id), refresh_team_trial_eligibility(sqlc.arg(team_id)), now()
ON CONFLICT (team_id) DO UPDATE
SET eligible = EXCLUDED.eligible,
    updated_at = EXCLUDED.updated_at;

-- name: ListTeamsWithActiveTrialSandboxes :many
SELECT DISTINCT s.team_id
FROM sandbox s
JOIN team_credit_grant g
  ON g.team_id = s.team_id
  AND g.reason = 'signup trial credit'
LEFT JOIN team_billing_account a ON a.team_id = s.team_id
WHERE s.destroyed_at IS NULL
  AND s.status = 'active'
  AND a.trial_ended_at IS NULL
  AND s.team_id > COALESCE(sqlc.narg(after_team_id)::uuid, '00000000-0000-0000-0000-000000000000'::uuid)
ORDER BY s.team_id
LIMIT sqlc.arg(batch_limit);

-- name: ListTeamsWithActiveIneligibleSandboxes :many
-- MATERIALIZED fence, same reason as the rollup's interval_team_set: dedupe
-- the active-team set first so team_sandbox_billing_eligible() runs once per
-- team. Inlined in the WHERE clause the planner may evaluate it per active
-- sandbox row — the function does three reads, and this sweep runs on a
-- timer against every control-plane instance.
WITH active_teams AS MATERIALIZED (
    SELECT DISTINCT s.team_id
    FROM sandbox s
    WHERE s.destroyed_at IS NULL
      AND s.status = 'active'
      AND s.team_id > COALESCE(sqlc.narg(after_team_id)::uuid, '00000000-0000-0000-0000-000000000000'::uuid)
)
SELECT team_id
FROM active_teams
WHERE NOT team_sandbox_billing_eligible(team_id)
ORDER BY team_id
LIMIT sqlc.arg(batch_limit);

-- name: ActivateTeamBilling :exec
SELECT activate_team_billing(sqlc.arg(team_id), sqlc.arg(stripe_grant_id));

-- name: ListTeamCreditGrants :many
SELECT *
FROM team_credit_grant
WHERE team_id = sqlc.arg(team_id)
ORDER BY created_at DESC;

-- name: ApplyTeamCreditGrant :one
UPDATE team_credit_grant
SET remaining_usd = remaining_usd - sqlc.arg(amount_usd),
    updated_at = now()
WHERE id = sqlc.arg(grant_id)
  AND team_id = sqlc.arg(team_id)
  AND sqlc.arg(amount_usd) > 0
  AND remaining_usd >= sqlc.arg(amount_usd)
  AND (expires_at IS NULL OR expires_at > now())
RETURNING *;

-- name: RecordTeamCreditLedgerEntry :one
INSERT INTO team_credit_ledger (
    team_id,
    grant_id,
    billing_period_start,
    billing_period_end,
    amount_usd,
    reason,
    created_by
)
VALUES (
    sqlc.arg(team_id),
    sqlc.narg(grant_id),
    sqlc.narg(billing_period_start),
    sqlc.narg(billing_period_end),
    sqlc.arg(amount_usd),
    sqlc.arg(reason),
    sqlc.narg(created_by)
)
RETURNING *;

-- name: GetTeamBillingUsageSeries :many
-- Allocated usage for each requested bucket, clipped exactly to bucket bounds.
WITH buckets AS (
 SELECT starts.bucket_start, ends.bucket_end
 FROM unnest(sqlc.arg(period_starts)::timestamptz[]) WITH ORDINALITY starts(bucket_start,n)
 JOIN unnest(sqlc.arg(period_ends)::timestamptz[]) WITH ORDINALITY ends(bucket_end,n) USING (n)
), compute AS (
 SELECT b.bucket_start,b.bucket_end,
   COALESCE(SUM(EXTRACT(EPOCH FROM (LEAST(COALESCE(i.ended_at,now()),b.bucket_end)-GREATEST(i.started_at,b.bucket_start)))*i.vcpu_count),0)::numeric vcpu_seconds,
   COALESCE(SUM(EXTRACT(EPOCH FROM (LEAST(COALESCE(i.ended_at,now()),b.bucket_end)-GREATEST(i.started_at,b.bucket_start)))*i.memory_mib),0)::numeric memory_mib_seconds
 FROM buckets b LEFT JOIN sandbox_compute_billing_interval i ON i.team_id=sqlc.arg(team_id)
  AND i.started_at < LEAST(now(),b.bucket_end) AND COALESCE(i.ended_at,LEAST(now(),b.bucket_end)) > b.bucket_start
 GROUP BY b.bucket_start,b.bucket_end
), artifact_ranges AS (
 SELECT b.bucket_start,b.bucket_end,p.path,
   MAX(COALESCE(NULLIF(am.allocated_bytes,0),0))::numeric/1048576.0 AS artifact_mib,
   range_agg(tstzrange(GREATEST(s.started_at,b.bucket_start),LEAST(COALESCE(sb.destroyed_at,now()),b.bucket_end),'[)')) AS retained_ranges
 FROM buckets b
 JOIN sandbox_storage_interval s ON s.team_id=sqlc.arg(team_id)
 JOIN sandbox sb ON sb.id=s.sandbox_id
 LEFT JOIN template t ON t.id=sb.template_id
 CROSS JOIN LATERAL unnest(ARRAY[sb.base_path,sb.delta_path,CASE WHEN sb.base_path IS NULL AND sb.delta_path IS NULL THEN t.rootfs_path END]) AS p(path)
 LEFT JOIN artifact_manifest am ON (am.snapshot_id=sb.snapshot_id OR am.template_id=t.id) AND am.path=p.path
 WHERE p.path IS NOT NULL AND s.started_at < LEAST(now(),b.bucket_end) AND COALESCE(sb.destroyed_at,LEAST(now(),b.bucket_end)) > b.bucket_start
 GROUP BY b.bucket_start,b.bucket_end,p.path
), artifact_storage AS (
 SELECT bucket_start,bucket_end,FLOOR(COALESCE(SUM(artifact_mib*EXTRACT(EPOCH FROM (upper(r)-lower(r)))),0))::numeric AS mib_seconds
 FROM artifact_ranges CROSS JOIN LATERAL unnest(retained_ranges) AS ranges(r) GROUP BY bucket_start,bucket_end
), storage AS (
 SELECT b.bucket_start,b.bucket_end,
   COALESCE(SUM(EXTRACT(EPOCH FROM (LEAST(COALESCE(i.ended_at,now()),b.bucket_end)-GREATEST(i.started_at,b.bucket_start)))*i.disk_mib),0)::numeric + COALESCE(MAX(a.mib_seconds),0) AS storage_mib_seconds
 FROM buckets b LEFT JOIN sandbox_storage_interval i ON i.team_id=sqlc.arg(team_id)
  AND i.started_at < LEAST(now(),b.bucket_end) AND COALESCE(i.ended_at,LEAST(now(),b.bucket_end)) > b.bucket_start
 LEFT JOIN artifact_storage a ON a.bucket_start=b.bucket_start AND a.bucket_end=b.bucket_end GROUP BY b.bucket_start,b.bucket_end
)
SELECT sqlc.arg(team_id)::uuid team_id,c.bucket_start period_start,c.bucket_end period_end,c.vcpu_seconds,(c.memory_mib_seconds/1024.0)::numeric memory_gib_seconds,(s.storage_mib_seconds/1024.0)::numeric storage_gib_seconds
FROM compute c JOIN storage s USING(bucket_start,bucket_end) ORDER BY c.bucket_start;
