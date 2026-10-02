-- Enrollment is persisted only after the provider subscription is held and
-- include its metered one-cent adjustment price before any tolerance changes.
CREATE TABLE billing_invoice_account (
    team_id uuid PRIMARY KEY REFERENCES team(id) ON DELETE CASCADE,
    customer_id text NOT NULL UNIQUE,
    subscription_id text NOT NULL UNIQUE,
    adjustment_price_id text NOT NULL,
    adjustment_event_name text NOT NULL,
    adjustment_meter_id text NOT NULL,
    enrolled_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    last_attempt_at timestamptz,
    last_error text
);
ALTER TABLE billing_invoice_account ENABLE ROW LEVEL SECURITY;

CREATE TABLE billing_invoice_close (
    team_id uuid NOT NULL,
    period_start timestamptz NOT NULL,
    period_end timestamptz NOT NULL,
    invoice_id text NOT NULL UNIQUE,
    plan jsonb NOT NULL,
    state text NOT NULL DEFAULT 'prepared' CHECK (state IN ('prepared','adjusted','finalizing','verified','released')),
    first_adjustment_at timestamptz,
    first_finalize_at timestamptz,
    verified_at timestamptz,
    finalized_evidence jsonb,
    last_error text,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(team_id,period_start,period_end),
    FOREIGN KEY(team_id,period_start,period_end) REFERENCES team_billing_period(team_id,period_start,period_end),
    CHECK (period_end>period_start)
);
ALTER TABLE billing_invoice_close ENABLE ROW LEVEL SECURITY;
CREATE INDEX billing_invoice_close_pending ON billing_invoice_close(updated_at) WHERE state <> 'released';

CREATE FUNCTION billing_invoice_close_matches(t uuid, s timestamptz, e timestamptz)
RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE j billing_invoice_close; a billing_invoice_account; r jsonb;
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
    RETURN true;
END;
$$;

CREATE OR REPLACE FUNCTION gate_incremental_billing_close() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.finalized_at IS NULL AND NEW.status IN ('exported','finalized')
       AND EXISTS(SELECT 1 FROM billing_invoice_account a WHERE a.team_id=NEW.team_id AND a.enrolled_at<NEW.period_end) THEN
        IF NOT billing_invoice_close_matches(NEW.team_id,NEW.period_start,NEW.period_end) THEN
            RAISE EXCEPTION 'invoice requires verified cent reconciliation before local close';
        END IF;
        IF NEW.status='finalized' AND NOT EXISTS(SELECT 1 FROM billing_invoice_close j
            WHERE j.team_id=NEW.team_id AND j.period_start=NEW.period_start AND j.period_end=NEW.period_end
              AND NEW.gross_charges_usd=(j.plan->>'expected_cents')::numeric/100
              AND NEW.credits_applied_usd=(j.finalized_evidence->>'credit_applied_cents')::numeric/100
              AND NEW.net_invoice_amount_usd=(j.finalized_evidence->>'net_cents')::numeric/100) THEN
            RAISE EXCEPTION 'local invoice money differs from verified Stripe settlement';
        END IF;
        RETURN NEW;
    END IF;
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

CREATE FUNCTION guard_billing_invoice_plan() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.team_id,NEW.period_start,NEW.period_end,NEW.invoice_id,NEW.plan)
       IS DISTINCT FROM ROW(OLD.team_id,OLD.period_start,OLD.period_end,OLD.invoice_id,OLD.plan)
       OR array_position(ARRAY['prepared','adjusted','finalizing','verified','released'],NEW.state)
          < array_position(ARRAY['prepared','adjusted','finalizing','verified','released'],OLD.state) THEN
        RAISE EXCEPTION 'invoice reconciliation plan is immutable';
    END IF;
    IF OLD.state IN ('verified','released') AND
       ROW(NEW.finalized_evidence,NEW.verified_at) IS DISTINCT FROM ROW(OLD.finalized_evidence,OLD.verified_at) THEN
        RAISE EXCEPTION 'verified invoice settlement is immutable';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER billing_invoice_plan_immutable BEFORE UPDATE ON billing_invoice_close
FOR EACH ROW EXECUTE FUNCTION guard_billing_invoice_plan();
