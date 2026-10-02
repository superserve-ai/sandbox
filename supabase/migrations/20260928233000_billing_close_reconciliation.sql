-- Observational history never becomes reservation coverage or event acceptance.
CREATE TABLE billing_meter_reconciliation (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id uuid NOT NULL,
    period_start timestamptz NOT NULL,
    period_end timestamptz NOT NULL,
    resource_type text NOT NULL CHECK (resource_type IN ('cpu','memory','storage')),
    event_name text NOT NULL,
    customer_id text NOT NULL,
    meter_id text NOT NULL CHECK (btrim(meter_id) <> ''),
    local_quantity numeric NOT NULL,
    reserved_quantity numeric NOT NULL,
    submitted_quantity numeric NOT NULL,
    provider_quantity numeric NOT NULL,
    difference numeric NOT NULL,
    query_start timestamptz NOT NULL,
    query_end timestamptz NOT NULL,
    observed_at timestamptz NOT NULL,
    collected_at timestamptz NOT NULL,
    policy text NOT NULL,
    accounting_snapshot jsonb NOT NULL,
    bucket_passes jsonb NOT NULL,
    FOREIGN KEY (team_id,period_start,period_end)
        REFERENCES billing_incremental_period(team_id,period_start,period_end),
    CHECK (difference = provider_quantity-reserved_quantity)
);
CREATE INDEX billing_meter_reconciliation_observation ON billing_meter_reconciliation
    (team_id,period_start,period_end,resource_type,observed_at DESC);
ALTER TABLE billing_meter_reconciliation ENABLE ROW LEVEL SECURITY;

CREATE FUNCTION protect_billing_meter_reconciliation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'meter reconciliation history is immutable';
END;
$$;
CREATE TRIGGER billing_meter_reconciliation_immutable BEFORE UPDATE OR DELETE ON billing_meter_reconciliation
    FOR EACH ROW EXECUTE FUNCTION protect_billing_meter_reconciliation();

-- At most 4096 historical events, including replaced events. NULL means the
-- bounded read is incomplete. Exact JSON equality avoids digest collisions.
CREATE FUNCTION billing_meter_accounting_snapshot(t uuid, ps timestamptz, pe timestamptz, r text)
RETURNS jsonb LANGUAGE sql STABLE AS $$
    WITH inventory AS MATERIALIZED (
        SELECT jsonb_build_array(a.id,a.coverage_start,a.coverage_end,a.measured_through,a.correction_id,
            e.id,e.accounting_sequence,e.active,e.status,e.event_name,e.customer_id,e.quantity_payload,
            e.event_timestamp,e.updated_at,e.recovery_outcome,e.recovery_evidence) AS item,
            a.coverage_end,e.id
        FROM billing_export_allocation a LEFT JOIN billing_export_event e ON e.allocation_id=a.id
        WHERE a.team_id=t AND a.period_start=ps AND a.period_end=pe AND a.resource_type=r
        ORDER BY a.coverage_end DESC,e.id LIMIT 4097
    )
    SELECT CASE WHEN count(*) > 4096 THEN NULL ELSE jsonb_build_object(
        'events',COALESCE(jsonb_agg(item ORDER BY coverage_end,id),'[]'::jsonb),
        'correction_version',(SELECT correction_version FROM billing_incremental_period
            WHERE team_id=t AND period_start=ps AND period_end=pe),
        'measurement',(SELECT jsonb_build_array(vcpu_seconds,memory_mib_seconds,storage_mib_seconds)
            FROM team_billing_usage WHERE team_id=t AND period_start=ps AND period_end=pe),
        'customer',(SELECT stripe_customer_id FROM team_billing_account WHERE team_id=t)) END
    FROM inventory;
$$;

-- Exact one-binary64-spacing policy, mirrored by meterPrecisionBound in Go.
-- Multiplication by 0.5 is exact numeric arithmetic even in the smallest binade.
CREATE FUNCTION billing_meter_precision_bound(q numeric) RETURNS numeric LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE binade numeric := 1;
        allowance numeric := 0.0000000000000002220446049250313080847263336181640625;
BEGIN
    IF q < 0.000000000001 OR q > 1000000000 OR q IS NULL THEN RETURN NULL; END IF;
    WHILE binade > q LOOP binade := binade*0.5; allowance := allowance*0.5; END LOOP;
    WHILE binade*2 <= q LOOP binade := binade*2; allowance := allowance*2; END LOOP;
    RETURN allowance;
END;
$$;

CREATE FUNCTION billing_meter_close_evidence_matches(o billing_export_observation)
RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE evidence billing_meter_reconciliation;
        snapshot jsonb;
        mapping jsonb;
        mapping_checked_at timestamptz;
        allowance numeric;
        pass jsonb;
        bucket jsonb;
        cursor_time timestamptz;
        next_time timestamptz;
        quantity numeric;
        expected numeric;
        pass_total numeric;
BEGIN
    SELECT * INTO evidence FROM billing_meter_reconciliation e
    WHERE e.team_id=o.team_id AND e.period_start=o.period_start AND e.period_end=o.period_end
      AND e.resource_type=o.resource_type AND e.observed_at=o.observed_at
    ORDER BY e.id LIMIT 1;
    IF NOT FOUND THEN RETURN false; END IF;
    -- This transaction must supply a fresh independent active-mapping lookup.
    -- Binding by evidence ID also rejects observations replaced during the read.
    mapping := NULLIF(current_setting('billing.close_meter_mapping',true),'')::jsonb;
    mapping_checked_at := (mapping->>'checked_at')::timestamptz;
    IF mapping_checked_at IS NULL OR mapping_checked_at < clock_timestamp()-interval '30 seconds'
       OR mapping_checked_at > clock_timestamp()
       OR mapping->'meters'->>evidence.id::text IS DISTINCT FROM evidence.meter_id THEN RETURN false; END IF;
    allowance := billing_meter_precision_bound(o.reserved_quantity);
    IF allowance IS NULL OR evidence.policy <> 'exact-daily-one-ulp-v1'
       OR evidence.collected_at < statement_timestamp()-interval '2 hours'
       OR evidence.collected_at > evidence.observed_at OR evidence.observed_at > statement_timestamp()
       OR evidence.query_start <> o.query_start OR evidence.query_end <> o.query_end
       OR evidence.query_start <> date_trunc('minute',o.period_start)+
           (CASE WHEN date_trunc('minute',o.period_start)<o.period_start THEN interval '1 minute' ELSE interval '0' END)
       OR evidence.query_end <> date_trunc('minute',o.period_end)
       OR evidence.query_end <= evidence.query_start OR evidence.query_end-evidence.query_start>interval '32 days'
       OR o.meter_id IS NULL OR evidence.meter_id <> o.meter_id
       OR evidence.local_quantity <> o.local_quantity OR evidence.reserved_quantity <> o.reserved_quantity
       OR evidence.submitted_quantity <> o.submitted_quantity OR evidence.provider_quantity <> o.counted_quantity
       OR evidence.local_quantity <> evidence.reserved_quantity OR evidence.submitted_quantity <> evidence.reserved_quantity
       OR evidence.difference <= 0 OR evidence.difference > allowance
       OR evidence.difference <> evidence.provider_quantity-evidence.reserved_quantity THEN RETURN false; END IF;

    -- The caller already owns the period lock. Freeze customer scope through
    -- the close transaction; provider reads never hold this lock.
    PERFORM 1 FROM team_billing_account WHERE team_id=o.team_id AND stripe_customer_id=evidence.customer_id FOR SHARE;
    IF NOT FOUND THEN RETURN false; END IF;
    snapshot := billing_meter_accounting_snapshot(o.team_id,o.period_start,o.period_end,o.resource_type);
    IF snapshot IS NULL OR snapshot <> evidence.accounting_snapshot THEN RETURN false; END IF;
    IF EXISTS(SELECT 1 FROM billing_export_allocation a LEFT JOIN billing_export_event e ON e.allocation_id=a.id AND e.active
        WHERE a.team_id=o.team_id AND a.period_start=o.period_start AND a.period_end=o.period_end AND a.resource_type=o.resource_type
        AND (e.id IS NULL OR e.status NOT IN ('submitted','adopted') OR e.customer_id<>evidence.customer_id
          OR e.event_name<>evidence.event_name OR e.event_timestamp<extract(epoch FROM o.query_start)
          OR e.event_timestamp>=extract(epoch FROM o.query_end))) THEN RETURN false; END IF;
    IF jsonb_typeof(evidence.bucket_passes) IS DISTINCT FROM 'array' THEN RETURN false; END IF;
    IF jsonb_array_length(evidence.bucket_passes)<>2 THEN RETURN false; END IF;
    FOR pass IN SELECT value FROM jsonb_array_elements(evidence.bucket_passes) LOOP
        IF jsonb_typeof(pass) IS DISTINCT FROM 'array' THEN RETURN false; END IF;
        IF jsonb_array_length(pass) NOT BETWEEN 1 AND 33 THEN RETURN false; END IF;
        cursor_time := o.query_start;
        pass_total := 0;
        FOR bucket IN SELECT value FROM jsonb_array_elements(pass) LOOP
            next_time := least((date_trunc('day',cursor_time AT TIME ZONE 'UTC')+interval '1 day') AT TIME ZONE 'UTC',o.query_end);
            IF cursor_time>=o.query_end OR (bucket->>'start')::numeric IS DISTINCT FROM extract(epoch FROM cursor_time)
               OR (bucket->>'end')::numeric IS DISTINCT FROM extract(epoch FROM next_time)
               OR (bucket->>'quantity') IS NULL OR length(bucket->>'quantity')>128
               OR (bucket->>'quantity') !~ '^[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]{1,3})?$' THEN RETURN false; END IF;
            quantity := (bucket->>'quantity')::numeric;
            SELECT COALESCE(sum(e.quantity),0) INTO expected FROM billing_export_allocation a
            JOIN billing_export_event e ON e.allocation_id=a.id AND e.active AND e.status IN ('submitted','adopted')
            WHERE a.team_id=o.team_id AND a.period_start=o.period_start AND a.period_end=o.period_end AND a.resource_type=o.resource_type
              AND e.event_timestamp>=extract(epoch FROM cursor_time) AND e.event_timestamp<extract(epoch FROM next_time);
            IF quantity<>expected THEN RETURN false; END IF;
            pass_total := pass_total+quantity;
            cursor_time := next_time;
        END LOOP;
        IF cursor_time<>o.query_end OR pass_total<>o.submitted_quantity THEN RETURN false; END IF;
    END LOOP;
    RETURN true;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range OR datetime_field_overflow THEN
    RETURN false;
END;
$$;

CREATE OR REPLACE FUNCTION gate_incremental_billing_close() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS(SELECT 1 FROM billing_incremental_period p
        WHERE p.team_id=NEW.team_id AND p.period_start=NEW.period_start AND p.period_end=NEW.period_end) THEN
        RETURN NEW;
    END IF;
    IF NEW.status IN ('exporting','exported','finalized') AND NEW.period_end > now() THEN
        RAISE EXCEPTION 'open incremental period cannot be frozen or finalized';
    END IF;
    IF NEW.status IN ('exported','finalized') AND OLD.finalized_at IS NULL THEN
        IF EXISTS(SELECT 1 FROM billing_export_allocation a
            WHERE a.team_id=NEW.team_id AND a.period_start=NEW.period_start AND a.period_end=NEW.period_end
              AND NOT EXISTS(SELECT 1 FROM billing_export_observation o WHERE o.team_id=a.team_id
                AND o.period_start=a.period_start AND o.period_end=a.period_end AND o.resource_type=a.resource_type)) THEN
            RAISE EXCEPTION 'incremental export resource lacks provider evidence';
        END IF;
        IF EXISTS(SELECT 1 FROM billing_export_allocation a LEFT JOIN billing_export_event e ON e.allocation_id=a.id AND e.active
            WHERE a.team_id=NEW.team_id AND a.period_start=NEW.period_start AND a.period_end=NEW.period_end
              AND (e.id IS NULL OR e.status NOT IN ('submitted','adopted'))) THEN
            RAISE EXCEPTION 'incremental export has unresolved events';
        END IF;
        IF NOT EXISTS(SELECT 1 FROM billing_export_observation o
            WHERE o.team_id=NEW.team_id AND o.period_start=NEW.period_start AND o.period_end=NEW.period_end) OR EXISTS(
            SELECT 1 FROM billing_export_observation o
            WHERE o.team_id=NEW.team_id AND o.period_start=NEW.period_start AND o.period_end=NEW.period_end
              AND (o.last_error IS NOT NULL OR o.counted_quantity IS NULL OR o.query_end<>date_trunc('minute',NEW.period_end)
                OR (o.counted_quantity<>o.local_quantity AND NOT billing_meter_close_evidence_matches(o))
                OR o.reserved_quantity<>o.local_quantity
                OR o.submitted_quantity<>o.local_quantity OR o.observed_at<now()-interval '2 hours'
                OR o.reserved_quantity<>COALESCE((SELECT max(a.coverage_end) FROM billing_export_allocation a
                    WHERE a.team_id=o.team_id AND a.period_start=o.period_start AND a.period_end=o.period_end AND a.resource_type=o.resource_type),0)
                OR o.submitted_quantity<>COALESCE((SELECT sum(e.quantity) FROM billing_export_allocation a
                    JOIN billing_export_event e ON e.allocation_id=a.id AND e.active AND e.status IN ('submitted','adopted')
                    WHERE a.team_id=o.team_id AND a.period_start=o.period_start AND a.period_end=o.period_end AND a.resource_type=o.resource_type),0)
                OR EXISTS(SELECT 1 FROM billing_export_allocation a JOIN billing_export_event e ON e.allocation_id=a.id
                    WHERE a.team_id=o.team_id AND a.period_start=o.period_start AND a.period_end=o.period_end
                    AND a.resource_type=o.resource_type AND e.updated_at>o.observed_at))) THEN
            RAISE EXCEPTION 'incremental export requires fresh matching Stripe reconciliation';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
