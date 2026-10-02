-- An unresolved retained measurement is a blocking outcome, not a numeric
-- cache value.  Keep export writes fail-closed so NULL never reaches the
-- not-null ledger columns and the pending measurement can be retried.
CREATE OR REPLACE FUNCTION clip_storage_export_cache() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    frozen boolean;
    measured numeric;
BEGIN
    SELECT EXISTS (
        SELECT 1 FROM team_billing_period p
        WHERE p.team_id = NEW.team_id
          AND p.period_start = NEW.period_start
          AND p.period_end = NEW.period_end
          AND (p.finalized_at IS NOT NULL OR p.exported_at IS NOT NULL
               OR p.status IN ('exporting','exported','finalized'))
    ) INTO frozen;
    IF frozen THEN
        RETURN NEW;
    END IF;
    IF TG_TABLE_NAME = 'billing_export_measurement' THEN
        SELECT billable_storage_mib_seconds(
            NEW.team_id,
            GREATEST(NEW.hour_start, NEW.period_start),
            LEAST(NEW.hour_start + interval '1 hour', NEW.period_end)
        ) INTO measured;
        IF measured IS NULL THEN
            RAISE EXCEPTION 'storage measurement unavailable for export cache'
                USING ERRCODE = '55000';
        END IF;
        NEW.storage_mib_seconds := measured;
    ELSE
        -- Only consumed hour contributions belong in the accumulator.
        SELECT COALESCE(SUM(m.storage_mib_seconds), 0)
        INTO NEW.storage_mib_seconds
        FROM billing_export_measurement m
        WHERE m.team_id = NEW.team_id
          AND m.period_start = NEW.period_start
          AND m.period_end = NEW.period_end;
    END IF;
    RETURN NEW;
END;
$$;
