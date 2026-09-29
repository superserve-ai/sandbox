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
storage AS (
    SELECT billable_storage_mib_seconds($1,$2,$3) AS storage_mib_seconds
)
SELECT compute.vcpu_seconds,compute.memory_mib_seconds,storage.storage_mib_seconds FROM compute,storage`
