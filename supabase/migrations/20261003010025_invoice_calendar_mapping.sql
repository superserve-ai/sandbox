-- Commercial usage periods and provider collection periods are independent.
-- Keep export identities and coverage immutable while pinning a one-to-one
-- settlement calendar before any new usage can enter the provider cycle.
CREATE TABLE billing_invoice_calendar (
    team_id uuid NOT NULL,
    period_start timestamptz NOT NULL,
    period_end timestamptz NOT NULL,
    customer_id text NOT NULL,
    subscription_id text NOT NULL,
    invoice_start timestamptz NOT NULL,
    invoice_end timestamptz NOT NULL,
    billing_cycle_anchor bigint NOT NULL CHECK (billing_cycle_anchor > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(team_id,period_start,period_end),
    UNIQUE(team_id,subscription_id,invoice_start,invoice_end),
    FOREIGN KEY(team_id,period_start,period_end) REFERENCES team_billing_period(team_id,period_start,period_end),
    CHECK(invoice_start < period_end AND invoice_end >= period_end AND invoice_end > invoice_start)
);
ALTER TABLE billing_invoice_calendar ENABLE ROW LEVEL SECURITY;

CREATE FUNCTION guard_billing_invoice_calendar() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN RAISE EXCEPTION 'invoice calendar is immutable'; END IF;
    PERFORM 1 FROM billing_invoice_account WHERE team_id=NEW.team_id
        AND customer_id=NEW.customer_id AND subscription_id=NEW.subscription_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'invoice calendar association differs'; END IF;
    IF EXISTS(SELECT 1 FROM billing_invoice_calendar c WHERE c.team_id=NEW.team_id
        AND c.subscription_id=NEW.subscription_id AND c.invoice_start<NEW.invoice_end AND c.invoice_end>NEW.invoice_start
        AND (c.period_start,c.period_end)<>(NEW.period_start,NEW.period_end)) THEN
        RAISE EXCEPTION 'invoice cycle is already assigned to another commercial period';
    END IF;
    -- Reject incompatible history; never retimestamp, replace, or reassign it.
    IF EXISTS(SELECT 1 FROM billing_export_allocation a JOIN billing_export_event e ON e.allocation_id=a.id AND e.active
        WHERE a.team_id=NEW.team_id AND (
            ((a.period_start,a.period_end)=(NEW.period_start,NEW.period_end)
                AND (e.customer_id<>NEW.customer_id OR to_timestamp(e.event_timestamp)<(date_trunc('minute',NEW.invoice_start) + CASE WHEN NEW.invoice_start=date_trunc('minute',NEW.invoice_start) THEN interval '0' ELSE interval '1 minute' END) OR to_timestamp(e.event_timestamp)>=date_trunc('minute',NEW.invoice_end)))
            OR ((a.period_start,a.period_end)<>(NEW.period_start,NEW.period_end)
                AND e.customer_id=NEW.customer_id AND to_timestamp(e.event_timestamp)>=NEW.invoice_start AND to_timestamp(e.event_timestamp)<NEW.invoice_end)
        )) THEN RAISE EXCEPTION 'existing events cross invoice calendar boundaries; explicit recovery required'; END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER billing_invoice_calendar_guard BEFORE INSERT OR UPDATE OR DELETE ON billing_invoice_calendar
    FOR EACH ROW EXECUTE FUNCTION guard_billing_invoice_calendar();

CREATE FUNCTION guard_billing_invoice_event_calendar() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE a billing_export_allocation; c billing_invoice_calendar;
BEGIN
    SELECT * INTO STRICT a FROM billing_export_allocation WHERE id=NEW.allocation_id;
    -- The same account lock serializes mapping creation and legacy writers.
    PERFORM 1 FROM billing_invoice_account WHERE team_id=a.team_id FOR SHARE;
    SELECT * INTO c FROM billing_invoice_calendar WHERE team_id=a.team_id AND period_start=a.period_start AND period_end=a.period_end;
    IF FOUND AND (NEW.customer_id<>c.customer_id OR to_timestamp(NEW.event_timestamp)<(date_trunc('minute',c.invoice_start) + CASE WHEN c.invoice_start=date_trunc('minute',c.invoice_start) THEN interval '0' ELSE interval '1 minute' END) OR to_timestamp(NEW.event_timestamp)>=date_trunc('minute',c.invoice_end)) THEN
        RAISE EXCEPTION 'event is outside its mapped invoice cycle';
    END IF;
    IF EXISTS(SELECT 1 FROM billing_invoice_calendar other WHERE other.team_id=a.team_id
        AND other.customer_id=NEW.customer_id AND (other.period_start,other.period_end)<>(a.period_start,a.period_end)
        AND to_timestamp(NEW.event_timestamp)>=other.invoice_start AND to_timestamp(NEW.event_timestamp)<other.invoice_end) THEN
        RAISE EXCEPTION 'event would enter another commercial periods invoice';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER billing_invoice_event_calendar BEFORE INSERT OR UPDATE OF active ON billing_export_event
    FOR EACH ROW WHEN (NEW.active) EXECUTE FUNCTION guard_billing_invoice_event_calendar();

CREATE OR REPLACE FUNCTION billing_invoice_close_matches(t uuid, s timestamptz, e timestamptz)
RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE j billing_invoice_close; a billing_invoice_account; r jsonb; c billing_invoice_calendar;
BEGIN
    SELECT * INTO j FROM billing_invoice_close WHERE team_id=t AND period_start=s AND period_end=e;
    IF NOT FOUND OR j.state NOT IN ('verified','released') OR j.verified_at IS NULL OR e>now() THEN RETURN false; END IF;
    SELECT * INTO a FROM billing_invoice_account WHERE team_id=t;
    IF NOT FOUND OR a.enrolled_at>=e THEN RETURN false; END IF;
    -- The saved enrollment remains authoritative for frozen historical periods
    -- while a replacement waits for their settlement before taking ownership.
    IF NOT EXISTS(SELECT 1 FROM team_billing_account b
        WHERE b.team_id=t AND b.stripe_customer_id=a.customer_id AND b.stripe_subscription_id=a.subscription_id)
       AND NOT EXISTS(SELECT 1 FROM team_billing_period p JOIN billing_incremental_period i USING(team_id,period_start,period_end)
         JOIN billing_invoice_enrollment w USING(team_id) JOIN team_billing_account b USING(team_id) WHERE p.team_id=t AND p.period_start=s AND p.period_end=e
           AND (p.status IN ('exporting','exported') OR p.finalized_at IS NOT NULL)
           AND e<=w.requested_at AND w.completed_at IS NULL
           AND w.customer_id=b.stripe_customer_id AND w.subscription_id=b.stripe_subscription_id
           AND b.stripe_subscription_status='active') THEN RETURN false; END IF;
    IF jsonb_typeof(j.plan->'resources') IS DISTINCT FROM 'array' OR jsonb_array_length(j.plan->'resources') NOT BETWEEN 1 AND 3 THEN RETURN false; END IF;
    IF j.plan->>'customer' IS DISTINCT FROM a.customer_id OR j.plan->>'subscription' IS DISTINCT FROM a.subscription_id
       OR (j.plan->>'expected_cents')::numeric < 0
       OR (j.plan->>'expected_cents')::numeric IS DISTINCT FROM (SELECT sum((value->>'expected_cents')::numeric) FROM jsonb_array_elements(j.plan->'resources'))
       OR (SELECT count(DISTINCT value->>'resource') FROM jsonb_array_elements(j.plan->'resources')) <> jsonb_array_length(j.plan->'resources')
       OR (j.finalized_evidence->>'credit_applied_cents')::numeric IS DISTINCT FROM LEAST((j.plan->>'expected_cents')::numeric,(j.plan->>'credit_before_cents')::numeric)
       OR (j.finalized_evidence->>'credit_remaining_cents')::numeric IS DISTINCT FROM (j.plan->>'credit_before_cents')::numeric-(j.finalized_evidence->>'credit_applied_cents')::numeric
       OR (j.finalized_evidence->>'net_cents')::numeric IS DISTINCT FROM (j.plan->>'expected_cents')::numeric-(j.finalized_evidence->>'credit_applied_cents')::numeric THEN RETURN false; END IF;
    FOR r IN SELECT value FROM jsonb_array_elements(j.plan->'resources') LOOP
        IF r->>'resource' NOT IN ('cpu','memory','storage') OR r->'snapshot' IS NULL OR r->'snapshot'='null'::jsonb OR r->'snapshot' IS DISTINCT FROM billing_meter_accounting_snapshot(t,s,e,r->>'resource') THEN RETURN false; END IF;
    END LOOP;
    IF EXISTS(SELECT 1 FROM billing_export_allocation x LEFT JOIN billing_export_event v ON v.allocation_id=x.id AND v.active
        WHERE x.team_id=t AND x.period_start=s AND x.period_end=e
        AND (v.id IS NULL OR v.status NOT IN ('submitted','adopted') OR NOT EXISTS(
          SELECT 1 FROM jsonb_array_elements(j.plan->'resources') resource WHERE resource->>'resource'=x.resource_type))) THEN RETURN false; END IF;
    IF j.plan ? 'invoice_start' OR j.plan ? 'invoice_end' THEN
        SELECT * INTO c FROM billing_invoice_calendar WHERE team_id=t AND period_start=s AND period_end=e;
        IF NOT FOUND OR c.customer_id IS DISTINCT FROM j.plan->>'customer' OR c.subscription_id IS DISTINCT FROM j.plan->>'subscription'
            OR extract(epoch from c.invoice_start)::bigint IS DISTINCT FROM (j.plan->>'invoice_start')::bigint
            OR extract(epoch from c.invoice_end)::bigint IS DISTINCT FROM (j.plan->>'invoice_end')::bigint
            OR (j.finalized_evidence->'invoice'->>'period_start')::bigint IS DISTINCT FROM (j.plan->>'invoice_start')::bigint
            OR (j.finalized_evidence->'invoice'->>'period_end')::bigint IS DISTINCT FROM (j.plan->>'invoice_end')::bigint THEN RETURN false; END IF;
    ELSIF EXISTS(SELECT 1 FROM billing_invoice_calendar WHERE team_id=t AND period_start=s AND period_end=e AND (invoice_start,invoice_end)<>(s,e)) THEN
        RETURN false;
    END IF;
    RETURN true;
END;
$$;

