-- The first valid retained measurement starts the prospective quantity
-- interval.  A resolved activation obligation therefore records the
-- measurement fence for settlement, but must not turn the pre-receipt gap
-- into an unknown value or a retroactive charge.
CREATE OR REPLACE FUNCTION storage_mib_seconds(
  p_team uuid,
  p_start timestamptz,
  p_end timestamptz,
  p_floor_legacy_artifacts boolean DEFAULT true
) RETURNS numeric LANGUAGE sql STABLE AS $$
  SELECT CASE WHEN EXISTS (
    SELECT 1
    FROM retained_storage_measurement_obligation o
    WHERE o.team_id = p_team
      AND o.effective_at < LEAST(p_end, billing_request_now())
      AND o.resolved_at IS NULL
      AND o.ended_at IS NULL
      AND billing_request_now() > p_start
  ) THEN NULL::numeric
  ELSE storage_mib_seconds_segmented(p_team, p_start, p_end, p_floor_legacy_artifacts)
  END
$$;

-- Once a first compatible receipt resolves an obligation, any earlier gap is
-- explicitly unbilled. Only an unresolved obligation remains a settlement
-- fence; a receipt that arrives after an older period must not make that
-- already-unmeasured gap permanently unknown.
CREATE OR REPLACE FUNCTION storage_reports_complete_through(
  p_team_id uuid, p_boundary timestamptz
) RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT NOT EXISTS (
    SELECT 1
    FROM retained_storage_measurement_obligation o
    WHERE o.team_id = p_team_id
      AND o.effective_at < p_boundary
      AND o.resolved_at IS NULL
      AND o.ended_at IS NULL
  ) AND NOT EXISTS (
    SELECT 1
    FROM host_storage_report r
    WHERE r.received_at < p_boundary
      AND (
        r.state IN ('pending','processing','retry_exhausted')
        OR (
          r.state = 'processed' AND r.payload IS NOT NULL AND
          (
            jsonb_typeof(r.payload) <> 'array'
            OR r.next_measurement_index <> CASE
              WHEN jsonb_typeof(r.payload) = 'array' THEN jsonb_array_length(r.payload)
              ELSE -1
            END
          )
        )
      )
      AND EXISTS (
        SELECT 1 FROM sandbox s
        WHERE s.team_id = p_team_id
          AND s.host_id = r.host_id
          AND s.created_at <= r.received_at
          AND (s.destroyed_at IS NULL OR s.destroyed_at > r.received_at)
        UNION ALL
        SELECT 1 FROM sandbox_snapshot s
        WHERE s.team_id = p_team_id
          AND s.host_id = r.host_id
          AND s.created_at <= r.received_at
          AND (s.status IN ('ready','creating','deleting') OR s.retention_ended_at > r.received_at)
          AND (LEAST(s.deleted_at,s.retention_ended_at) IS NULL OR LEAST(s.deleted_at,s.retention_ended_at) > r.received_at)
      )
    UNION ALL
    SELECT 1
    FROM legacy_host_storage_report legacy
    WHERE legacy.received_at < p_boundary
      AND EXISTS (
        SELECT 1 FROM sandbox s
        WHERE s.team_id = p_team_id
          AND s.host_id = legacy.host_id
          AND s.created_at <= legacy.received_at
          AND (s.destroyed_at IS NULL OR s.destroyed_at > legacy.received_at)
        UNION ALL
        SELECT 1 FROM sandbox_snapshot s
        WHERE s.team_id = p_team_id
          AND s.host_id = legacy.host_id
          AND s.created_at <= legacy.received_at
          AND (s.status IN ('ready','creating','deleting') OR s.retention_ended_at > legacy.received_at)
          AND (LEAST(s.deleted_at,s.retention_ended_at) IS NULL OR LEAST(s.deleted_at,s.retention_ended_at) > legacy.received_at)
      )
  )
$$;
