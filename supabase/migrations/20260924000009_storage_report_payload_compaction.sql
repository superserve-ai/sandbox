-- Completed reports only need their identity, sequence, timestamp, and a
-- payload digest for idempotent retries. The measurement payload is no longer
-- needed once processing has completed (or the report is terminal), so clear
-- it in the worker's state transition instead of retaining fleet-sized JSON.
ALTER TABLE public.host_storage_report
    ADD COLUMN payload_hash text;

UPDATE public.host_storage_report
SET payload_hash = encode(digest(payload::text, 'sha256'), 'hex')
WHERE payload_hash IS NULL;

ALTER TABLE public.host_storage_report
    ALTER COLUMN payload DROP NOT NULL;

UPDATE public.host_storage_report
SET payload = NULL
WHERE state = 'terminal'
   OR (state = 'processed'
       AND jsonb_typeof(payload) = 'array'
       AND next_measurement_index = CASE
           WHEN jsonb_typeof(payload) = 'array' THEN jsonb_array_length(payload)
           ELSE -1
       END);

ALTER TABLE public.host_storage_report
    ALTER COLUMN payload_hash SET NOT NULL;

CREATE OR REPLACE FUNCTION set_host_storage_report_payload_hash()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    -- Keep the digest when compaction clears payload. Recompute it whenever a
    -- row is inserted or a payload is explicitly replaced.
    IF NEW.payload IS NOT NULL THEN
        IF TG_OP = 'INSERT' OR NEW.payload_hash IS NULL THEN
            NEW.payload_hash := encode(digest(NEW.payload::text, 'sha256'), 'hex');
        ELSIF TG_OP = 'UPDATE' AND NEW.payload IS DISTINCT FROM OLD.payload THEN
            NEW.payload_hash := encode(digest(NEW.payload::text, 'sha256'), 'hex');
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER host_storage_report_payload_hash_trg
    BEFORE INSERT OR UPDATE OF payload ON public.host_storage_report
    FOR EACH ROW
    EXECUTE FUNCTION set_host_storage_report_payload_hash();

-- A compacted processed report is complete because its durable cursor already
-- equals the number of measurements it applied. A non-null payload still gets
-- the shape/length check for rows that have not yet been compacted.
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
          )
    )
$$;
