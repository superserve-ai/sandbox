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
storage AS (
    SELECT COALESCE(SUM(
        EXTRACT(EPOCH FROM (
            LEAST(COALESCE(i.ended_at, now()), sqlc.arg(period_end))
            - GREATEST(i.started_at, sqlc.arg(period_start))
        )) * i.disk_mib
    ), 0)::numeric AS storage_mib_seconds
    FROM sandbox_storage_interval i
    WHERE i.team_id = sqlc.arg(team_id)
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
storage AS (
    SELECT COALESCE(SUM(
        EXTRACT(EPOCH FROM (
            LEAST(COALESCE(i.ended_at, now()), sqlc.arg(period_end))
            - GREATEST(i.started_at, sqlc.arg(period_start))
        )) * i.disk_mib
    ), 0)::numeric AS storage_mib_seconds
    FROM sandbox_storage_interval i
    WHERE i.team_id = sqlc.arg(team_id)
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
                LEAST(COALESCE(i.ended_at, now()), sqlc.arg(hour_end))
                - GREATEST(i.started_at, sqlc.arg(hour_start))
            )) * i.vcpu_count
        ), 0)::numeric AS vcpu_seconds,
        COALESCE(SUM(
            EXTRACT(EPOCH FROM (
                LEAST(COALESCE(i.ended_at, now()), sqlc.arg(hour_end))
                - GREATEST(i.started_at, sqlc.arg(hour_start))
            )) * i.memory_mib
        ), 0)::numeric AS memory_mib_seconds
    FROM sandbox_compute_billing_interval i
    WHERE i.team_id = sqlc.arg(team_id)
      AND i.started_at < sqlc.arg(hour_end)
      AND sqlc.arg(hour_start) < LEAST(now(), sqlc.arg(hour_end))
      AND COALESCE(i.ended_at, LEAST(now(), sqlc.arg(hour_end))) > sqlc.arg(hour_start)
),
storage AS (
    SELECT COALESCE(SUM(
        EXTRACT(EPOCH FROM (
            LEAST(COALESCE(i.ended_at, now()), sqlc.arg(hour_end))
            - GREATEST(i.started_at, sqlc.arg(hour_start))
        )) * i.disk_mib
    ), 0)::numeric AS storage_mib_seconds
    FROM sandbox_storage_interval i
    WHERE i.team_id = sqlc.arg(team_id)
      AND i.started_at < sqlc.arg(hour_end)
      AND sqlc.arg(hour_start) < LEAST(now(), sqlc.arg(hour_end))
      AND COALESCE(i.ended_at, LEAST(now(), sqlc.arg(hour_end))) > sqlc.arg(hour_start)
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

-- name: UpsertTeamBillingPeriod :one
INSERT INTO team_billing_period (team_id, period_start, period_end, status)
VALUES (
    sqlc.arg(team_id),
    sqlc.arg(period_start),
    sqlc.arg(period_end),
    sqlc.arg(status)
)
ON CONFLICT (team_id, period_start, period_end) DO UPDATE
SET status = CASE
        WHEN team_billing_period.status IN ('blocked', 'approved', 'exported')
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
      AND team_billing_period.status = 'approved'
      AND team_billing_period.finalized_at IS NULL
      AND EXISTS (
          SELECT 1
          FROM team_billing_usage u
          WHERE u.team_id = team_billing_period.team_id
            AND u.period_start = team_billing_period.period_start
            AND u.period_end = team_billing_period.period_end
            AND u.exported_at IS NULL
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
