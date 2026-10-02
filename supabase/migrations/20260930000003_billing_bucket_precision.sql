-- Decimal accounting stays exact. Compare only supported provider representations.
CREATE FUNCTION billing_meter_precision_equivalent(provider numeric, local numeric)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE allowance numeric;
BEGIN
    IF provider IS NULL OR local IS NULL OR provider::text IN ('NaN','Infinity','-Infinity')
       OR local::text IN ('NaN','Infinity','-Infinity') OR provider<0 OR local<0 THEN RETURN false; END IF;
    IF provider=local THEN RETURN true; END IF;
    allowance := billing_meter_precision_bound(local);
    IF allowance IS NULL OR local<=0 OR provider<=0 OR abs(provider-local)>allowance THEN RETURN false; END IF;
    -- PostgreSQL converts numeric directly to correctly rounded binary64.
    RETURN provider::double precision=local::double precision;
END;
$$;

-- Preserve v1 evidence under its original rules during mixed-version rollout.
CREATE OR REPLACE FUNCTION billing_meter_close_evidence_matches(o billing_export_observation)
RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE evidence billing_meter_reconciliation;
        snapshot jsonb;
        mapping jsonb;
        mapping_checked_at timestamptz;
        allowance numeric;
        pass jsonb;
        first_pass jsonb;
        pass_number integer := 0;
        bucket_number integer;
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
    IF allowance IS NULL OR evidence.policy NOT IN ('exact-daily-one-ulp-v1','binary64-equivalent-v2')
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
       OR (evidence.policy='exact-daily-one-ulp-v1' AND (evidence.difference<=0 OR evidence.difference>allowance))
       OR (evidence.policy='binary64-equivalent-v2' AND (evidence.difference=0
           OR NOT billing_meter_precision_equivalent(evidence.provider_quantity,evidence.reserved_quantity)))
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
        pass_number := pass_number+1;
        bucket_number := 0;
        IF pass_number=1 THEN first_pass := pass;
        ELSIF jsonb_array_length(pass)<>jsonb_array_length(first_pass) THEN RETURN false; END IF;
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
            IF evidence.policy='exact-daily-one-ulp-v1' THEN
                IF quantity<>expected THEN RETURN false; END IF;
            ELSE
                IF NOT billing_meter_precision_equivalent(quantity,expected) THEN RETURN false; END IF;
                IF pass_number=2 AND quantity IS DISTINCT FROM (first_pass->bucket_number->>'quantity')::numeric THEN RETURN false; END IF;
            END IF;
            -- Coverage remains exact local accounting; provider decimals can
            -- round independently and need not sum to the exact period total.
            pass_total := pass_total+expected;
            bucket_number := bucket_number+1;
            cursor_time := next_time;
        END LOOP;
        IF cursor_time<>o.query_end OR pass_total<>o.submitted_quantity THEN RETURN false; END IF;
    END LOOP;
    RETURN true;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range OR datetime_field_overflow THEN
    RETURN false;
END;
$$;

