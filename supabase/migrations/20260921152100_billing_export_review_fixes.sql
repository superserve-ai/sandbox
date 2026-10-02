ALTER TABLE billing_export_usage ADD COLUMN last_export_attempt_at timestamptz;
ALTER TABLE billing_incremental_period ADD COLUMN last_reconcile_attempt_at timestamptz;
CREATE INDEX billing_export_usage_attempt_order ON billing_export_usage
    (team_id,last_export_attempt_at NULLS FIRST,period_start);
CREATE INDEX billing_incremental_period_attempt_order ON billing_incremental_period
    (team_id,last_reconcile_attempt_at NULLS FIRST,period_start);

CREATE SEQUENCE billing_accounting_sequence;
ALTER TABLE billing_export_event ADD COLUMN accounting_sequence bigint;
ALTER TABLE billing_export_correction ADD COLUMN accounting_sequence bigint;
WITH ordered AS (
    SELECT id,row_number() OVER (ORDER BY created_at,id) AS n FROM billing_export_event
)
UPDATE billing_export_event e SET accounting_sequence=o.n FROM ordered o WHERE e.id=o.id;
-- Backfill ordering metadata without changing immutable correction evidence.
ALTER TABLE billing_export_correction DISABLE TRIGGER billing_export_correction_immutable;
WITH ordered AS (
    SELECT id,row_number() OVER (ORDER BY created_at,id) AS n FROM billing_export_correction
)
UPDATE billing_export_correction c SET accounting_sequence=o.n FROM ordered o WHERE c.id=o.id;
ALTER TABLE billing_export_correction ENABLE TRIGGER billing_export_correction_immutable;
SELECT setval('billing_accounting_sequence',greatest(
    COALESCE((SELECT max(accounting_sequence) FROM billing_export_event),0),
    COALESCE((SELECT max(accounting_sequence) FROM billing_export_correction),0),1));
ALTER TABLE billing_export_event ALTER COLUMN accounting_sequence SET NOT NULL;
ALTER TABLE billing_export_correction ALTER COLUMN accounting_sequence SET NOT NULL;

-- A sequence alone is not commit ordered. Serialize assignment with the same
-- period row lock used by allocation and recovery, held until transaction end.
CREATE FUNCTION assign_billing_accounting_sequence() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    owner_team uuid;
    owner_start timestamptz;
    owner_end timestamptz;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.accounting_sequence IS DISTINCT FROM OLD.accounting_sequence THEN
            RAISE EXCEPTION 'accounting sequence is immutable';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_TABLE_NAME = 'billing_export_event' THEN
        SELECT team_id,period_start,period_end INTO STRICT owner_team,owner_start,owner_end
        FROM billing_export_allocation WHERE id=NEW.allocation_id;
    ELSE
        owner_team := NEW.team_id;
        owner_start := NEW.period_start;
        owner_end := NEW.period_end;
    END IF;
    PERFORM 1 FROM team_billing_period WHERE team_id=owner_team
        AND period_start=owner_start AND period_end=owner_end FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'accounting period missing'; END IF;
    NEW.accounting_sequence := nextval('billing_accounting_sequence');
    RETURN NEW;
END;
$$;
CREATE TRIGGER billing_export_event_sequence BEFORE INSERT OR UPDATE ON billing_export_event
    FOR EACH ROW EXECUTE FUNCTION assign_billing_accounting_sequence();
CREATE TRIGGER billing_export_correction_sequence BEFORE INSERT OR UPDATE ON billing_export_correction
    FOR EACH ROW EXECUTE FUNCTION assign_billing_accounting_sequence();
DROP INDEX billing_export_event_allocation_cursor;
CREATE INDEX billing_export_event_allocation_cursor ON billing_export_event (allocation_id,accounting_sequence);
DROP INDEX billing_export_correction_period_cursor;
CREATE INDEX billing_export_correction_period_cursor ON billing_export_correction
    (team_id,period_start,period_end,accounting_sequence);
