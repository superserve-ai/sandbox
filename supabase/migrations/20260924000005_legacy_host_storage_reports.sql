-- Temporary durable compatibility handoff for storage sent by legacy
-- heartbeats before the host has an incarnation bound.
CREATE TABLE legacy_host_storage_report (
    host_id text NOT NULL REFERENCES host(id) ON DELETE CASCADE,
    requested_incarnation_id uuid,
    report_id uuid NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    payload jsonb NOT NULL,
    attempts int NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    last_error text,
    PRIMARY KEY (host_id, report_id),
    CONSTRAINT legacy_host_storage_report_attempts_nonnegative CHECK (attempts >= 0)
);

CREATE INDEX legacy_host_storage_report_pending_idx
    ON legacy_host_storage_report (next_attempt_at, received_at);

ALTER TABLE public.legacy_host_storage_report ENABLE ROW LEVEL SECURITY;

-- Include reports waiting in the compatibility handoff in the same
-- conservative billing-settlement gate as bound reports.
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
        UNION ALL
        SELECT 1
        FROM legacy_host_storage_report legacy
        WHERE legacy.received_at < p_boundary
          AND EXISTS (
              SELECT 1
              FROM sandbox s
              WHERE s.team_id = p_team_id
                AND s.host_id = legacy.host_id
          )
    )
$$;
