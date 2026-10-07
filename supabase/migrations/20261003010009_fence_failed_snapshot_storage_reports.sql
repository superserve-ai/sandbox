-- Keep receipt-time snapshot ownership until pending storage reports are applied.
CREATE OR REPLACE FUNCTION storage_reports_complete_through(
    p_team_id uuid,
    p_boundary timestamptz
) RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    SELECT NOT EXISTS (
        SELECT 1
        FROM host_storage_report r
        WHERE r.received_at < p_boundary
          AND (
              r.state IN ('pending', 'processing', 'retry_exhausted')
              OR (
                  r.state = 'processed'
                  AND r.payload IS NOT NULL
                  AND (
                      jsonb_typeof(r.payload) <> 'array'
                      OR r.next_measurement_index <> CASE
                          WHEN jsonb_typeof(r.payload) = 'array' THEN jsonb_array_length(r.payload)
                          ELSE -1
                      END
                  )
              )
          )
          AND EXISTS (
              SELECT 1
              FROM sandbox s
              WHERE s.team_id = p_team_id
                AND s.host_id = r.host_id
                AND s.created_at <= r.received_at
                AND (s.destroyed_at IS NULL OR s.destroyed_at > r.received_at)
              UNION ALL SELECT 1 FROM sandbox_snapshot s
              WHERE s.team_id=p_team_id AND s.host_id=r.host_id
                AND (s.status IN ('ready','creating','deleting') OR s.retention_ended_at>r.received_at)
                AND s.created_at<=r.received_at
                AND (LEAST(s.deleted_at,s.retention_ended_at) IS NULL
                     OR LEAST(s.deleted_at,s.retention_ended_at)>r.received_at)
          )
        UNION ALL
        SELECT 1
        FROM legacy_host_storage_report legacy
        WHERE legacy.received_at < p_boundary
          AND EXISTS (
              SELECT 1
              FROM sandbox s
              WHERE s.team_id = p_team_id
                AND s.host_id = legacy.host_id
                AND s.created_at <= legacy.received_at
                AND (s.destroyed_at IS NULL OR s.destroyed_at > legacy.received_at)
              UNION ALL SELECT 1 FROM sandbox_snapshot s
              WHERE s.team_id=p_team_id AND s.host_id=legacy.host_id
                AND (s.status IN ('ready','creating','deleting') OR s.retention_ended_at>legacy.received_at)
                AND s.created_at<=legacy.received_at
                AND (LEAST(s.deleted_at,s.retention_ended_at) IS NULL
                     OR LEAST(s.deleted_at,s.retention_ended_at)>legacy.received_at)
          )
    )
$$;
