-- Billing must not settle a window while an accepted storage report for one of
-- its hosts is still pending, partially applied, or terminally failed.
-- The report rows are the durable watermark: processed reports advance the
-- persisted state/progress, and every consumer applies the same conservative
-- predicate before treating a window as complete.
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
          AND EXISTS (
              SELECT 1
              FROM sandbox s
              WHERE s.team_id = p_team_id
                AND s.host_id = r.host_id
          )
          AND (
              r.state <> 'processed'
              OR jsonb_typeof(r.payload) <> 'array'
              OR r.next_measurement_index <> CASE
                  WHEN jsonb_typeof(r.payload) = 'array' THEN jsonb_array_length(r.payload)
                  ELSE -1
              END
          )
    )
$$;

CREATE INDEX host_storage_report_completeness_idx
    ON host_storage_report (host_id, received_at)
    WHERE state <> 'processed';
