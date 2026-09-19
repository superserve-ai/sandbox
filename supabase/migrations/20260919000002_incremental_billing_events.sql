-- Enrollment fences the cumulative writer before incremental coverage is allocated.
CREATE TABLE billing_incremental_period (
    team_id uuid NOT NULL,
    period_start timestamptz NOT NULL,
    period_end timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (team_id, period_start, period_end),
    FOREIGN KEY (team_id, period_start, period_end)
        REFERENCES team_billing_period(team_id, period_start, period_end)
);
ALTER TABLE billing_incremental_period ENABLE ROW LEVEL SECURITY;

CREATE TABLE billing_export_allocation (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id uuid NOT NULL,
    period_start timestamptz NOT NULL,
    period_end timestamptz NOT NULL,
    resource_type text NOT NULL CHECK (resource_type IN ('cpu', 'memory', 'storage')),
    coverage_start numeric NOT NULL CHECK (coverage_start >= 0),
    coverage_end numeric NOT NULL CHECK (coverage_end > coverage_start),
    measured_through timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (team_id, period_start, period_end)
        REFERENCES billing_incremental_period(team_id, period_start, period_end),
    CHECK (measured_through > period_start AND measured_through <= period_end),
    UNIQUE (team_id, period_start, period_end, resource_type, coverage_start)
);
CREATE INDEX billing_export_allocation_end ON billing_export_allocation
    (team_id,period_start,period_end,resource_type,coverage_end DESC);
ALTER TABLE billing_export_allocation ENABLE ROW LEVEL SECURITY;

CREATE TABLE billing_export_event (
    id uuid PRIMARY KEY,
    allocation_id uuid NOT NULL REFERENCES billing_export_allocation(id),
    identifier text NOT NULL UNIQUE CHECK (length(identifier) BETWEEN 1 AND 100),
    idempotency_key text NOT NULL UNIQUE,
    event_name text NOT NULL CHECK (btrim(event_name) <> ''),
    customer_id text NOT NULL CHECK (btrim(customer_id) <> ''),
    quantity numeric NOT NULL CHECK (quantity > 0),
    quantity_payload text NOT NULL CHECK (quantity_payload::numeric = quantity),
    event_timestamp bigint NOT NULL,
    source text NOT NULL CHECK (source IN ('export', 'adopted')),
    evidence text,
    recovery_outcome text CHECK (recovery_outcome IN ('accepted', 'rejected')),
    recovery_evidence text,
    CHECK ((recovery_outcome IS NULL AND recovery_evidence IS NULL) OR
           (recovery_outcome IS NOT NULL AND recovery_evidence IS NOT NULL AND btrim(recovery_evidence) <> '')),
    replaces uuid UNIQUE REFERENCES billing_export_event(id),
    active boolean NOT NULL DEFAULT true,
    status text NOT NULL CHECK (status IN ('pending', 'uncertain', 'submitted', 'rejected', 'recovery_required', 'adopted')),
    first_attempt_at timestamptz,
    submitted_at timestamptz,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    lease_token uuid,
    lease_until timestamptz,
    attempt_count integer NOT NULL DEFAULT 0,
    last_error text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (source <> 'adopted' OR (evidence IS NOT NULL AND status IN ('adopted', 'rejected', 'recovery_required')))
);
CREATE UNIQUE INDEX billing_export_event_active ON billing_export_event(allocation_id) WHERE active;
CREATE INDEX billing_export_event_due ON billing_export_event(next_attempt_at, id)
    WHERE active AND status IN ('pending', 'uncertain');
ALTER TABLE billing_export_event ENABLE ROW LEVEL SECURITY;

CREATE TABLE billing_export_observation (
    team_id uuid NOT NULL,
    period_start timestamptz NOT NULL,
    period_end timestamptz NOT NULL,
    resource_type text NOT NULL,
    local_quantity numeric NOT NULL,
    submitted_quantity numeric NOT NULL,
    reserved_quantity numeric NOT NULL,
    counted_quantity numeric,
    observed_at timestamptz NOT NULL DEFAULT now(),
    query_start timestamptz NOT NULL,
    query_end timestamptz NOT NULL,
    last_error text,
    PRIMARY KEY (team_id, period_start, period_end, resource_type),
    FOREIGN KEY (team_id, period_start, period_end)
        REFERENCES billing_incremental_period(team_id, period_start, period_end)
);
ALTER TABLE billing_export_observation ENABLE ROW LEVEL SECURITY;

CREATE FUNCTION protect_billing_export_payload() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'billing export history cannot be deleted';
    END IF;
    IF TG_TABLE_NAME = 'billing_export_allocation' THEN
        RAISE EXCEPTION 'billing export coverage is immutable';
    END IF;
    IF ROW(NEW.id, NEW.allocation_id, NEW.identifier, NEW.idempotency_key,
           NEW.event_name, NEW.customer_id, NEW.quantity, NEW.quantity_payload,
           NEW.event_timestamp, NEW.source, NEW.evidence, NEW.replaces, NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.allocation_id, OLD.identifier, OLD.idempotency_key,
           OLD.event_name, OLD.customer_id, OLD.quantity, OLD.quantity_payload,
           OLD.event_timestamp, OLD.source, OLD.evidence, OLD.replaces, OLD.created_at) THEN
        RAISE EXCEPTION 'billing export payload is immutable';
    END IF;
    IF ROW(NEW.recovery_outcome, NEW.recovery_evidence) IS DISTINCT FROM
       ROW(OLD.recovery_outcome, OLD.recovery_evidence) THEN
        IF OLD.recovery_outcome IS NOT NULL OR OLD.status <> 'recovery_required'
           OR NOT OLD.active OR NOT NEW.active OR OLD.source <> 'export'
           OR NEW.recovery_outcome IS NULL
           OR NEW.status <> (CASE NEW.recovery_outcome WHEN 'accepted' THEN 'submitted' ELSE 'rejected' END) THEN
            RAISE EXCEPTION 'recovery requires an unresolved event and immutable provider evidence';
        END IF;
    END IF;
    IF OLD.status = 'recovery_required' AND NEW.status = 'submitted' AND NEW.recovery_outcome IS DISTINCT FROM 'accepted' THEN
        RAISE EXCEPTION 'acceptance requires reviewed provider evidence';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER billing_export_allocation_immutable BEFORE UPDATE OR DELETE ON billing_export_allocation
    FOR EACH ROW EXECUTE FUNCTION protect_billing_export_payload();
CREATE TRIGGER billing_export_event_immutable BEFORE UPDATE OR DELETE ON billing_export_event
    FOR EACH ROW EXECUTE FUNCTION protect_billing_export_payload();

CREATE FUNCTION fence_cumulative_billing_export() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    -- Same lock order as both allocators: period first, then export rows.
    PERFORM 1 FROM team_billing_period
    WHERE team_id = NEW.team_id AND period_start = NEW.period_start AND period_end = NEW.period_end
    FOR UPDATE;
    IF EXISTS (SELECT 1 FROM billing_incremental_period p
               WHERE p.team_id = NEW.team_id AND p.period_start = NEW.period_start AND p.period_end = NEW.period_end) THEN
        RAISE EXCEPTION 'period uses incremental export accounting';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER billing_usage_export_incremental_fence BEFORE INSERT OR UPDATE ON billing_usage_export
    FOR EACH ROW EXECUTE FUNCTION fence_cumulative_billing_export();

CREATE FUNCTION validate_billing_export_allocation() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE allocated numeric;
BEGIN
    PERFORM 1 FROM team_billing_period p
    WHERE p.team_id = NEW.team_id AND p.period_start = NEW.period_start AND p.period_end = NEW.period_end
      AND p.finalized_at IS NULL AND p.exported_at IS NULL
    FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'billing period is immutable'; END IF;
    SELECT COALESCE((SELECT coverage_end FROM billing_export_allocation a
    WHERE a.team_id = NEW.team_id AND a.period_start = NEW.period_start
      AND a.period_end = NEW.period_end AND a.resource_type = NEW.resource_type
    ORDER BY coverage_end DESC LIMIT 1),0) INTO allocated;
    IF allocated <> NEW.coverage_start THEN RAISE EXCEPTION 'billing coverage must extend existing reservations'; END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER billing_export_allocation_validate BEFORE INSERT ON billing_export_allocation
    FOR EACH ROW EXECUTE FUNCTION validate_billing_export_allocation();

CREATE FUNCTION validate_billing_export_event() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE allocation billing_export_allocation;
BEGIN
    SELECT * INTO STRICT allocation FROM billing_export_allocation WHERE id = NEW.allocation_id;
    IF NEW.quantity <> allocation.coverage_end - allocation.coverage_start THEN
        RAISE EXCEPTION 'event quantity differs from reserved coverage';
    END IF;
    IF to_timestamp(NEW.event_timestamp) < allocation.period_start
       OR to_timestamp(NEW.event_timestamp) >= allocation.period_end THEN
        RAISE EXCEPTION 'event timestamp is outside anniversary period';
    END IF;
    IF NEW.replaces IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM billing_export_event e WHERE e.id = NEW.replaces
          AND e.allocation_id = NEW.allocation_id AND e.status = 'rejected' AND NOT e.active
    ) THEN RAISE EXCEPTION 'only a confirmed rejected event can be replaced'; END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER billing_export_event_validate BEFORE INSERT ON billing_export_event
    FOR EACH ROW EXECUTE FUNCTION validate_billing_export_event();

-- Discovery and consumption run in the exporter, never in rollup transactions.
-- Retain consumed source values so unchanged hours require no queue writes.
CREATE TABLE billing_export_measurement_queue (
    team_id uuid NOT NULL REFERENCES team(id),
    hour_start timestamptz NOT NULL,
    pending boolean NOT NULL DEFAULT true,
    hour_end timestamptz,
    vcpu_seconds numeric,
    memory_mib_seconds numeric,
    storage_mib_seconds numeric,
    PRIMARY KEY (team_id,hour_start)
);
CREATE INDEX billing_export_measurement_pending ON billing_export_measurement_queue(team_id,hour_start) WHERE pending;
ALTER TABLE billing_export_measurement_queue ENABLE ROW LEVEL SECURITY;

CREATE TABLE billing_export_measurement (
    team_id uuid NOT NULL,
    period_start timestamptz NOT NULL,
    period_end timestamptz NOT NULL,
    hour_start timestamptz NOT NULL,
    vcpu_seconds numeric NOT NULL,
    memory_mib_seconds numeric NOT NULL,
    storage_mib_seconds numeric NOT NULL,
    PRIMARY KEY(team_id,period_start,period_end,hour_start),
    FOREIGN KEY(team_id,period_start,period_end) REFERENCES team_billing_period(team_id,period_start,period_end)
);
ALTER TABLE billing_export_measurement ENABLE ROW LEVEL SECURITY;

CREATE TABLE billing_export_work (
    team_id uuid PRIMARY KEY REFERENCES team(id),
    next_run_at timestamptz NOT NULL DEFAULT now(),
    lease_token uuid,
    lease_until timestamptz,
    seed_after timestamptz,
    seed_complete boolean NOT NULL DEFAULT false,
    last_error text,
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX billing_export_work_due ON billing_export_work(next_run_at,team_id);
ALTER TABLE billing_export_work ENABLE ROW LEVEL SECURITY;

CREATE TABLE billing_export_discovery (
    singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
    after_team uuid,
    reset_existing boolean NOT NULL DEFAULT false,
    next_run_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO billing_export_discovery(singleton) VALUES(true);
ALTER TABLE billing_export_discovery ENABLE ROW LEVEL SECURITY;

CREATE TABLE billing_export_usage (
    team_id uuid NOT NULL,
    period_start timestamptz NOT NULL,
    period_end timestamptz NOT NULL,
    vcpu_seconds numeric NOT NULL DEFAULT 0,
    memory_mib_seconds numeric NOT NULL DEFAULT 0,
    storage_mib_seconds numeric NOT NULL DEFAULT 0,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(team_id,period_start,period_end),
    FOREIGN KEY(team_id,period_start,period_end) REFERENCES team_billing_period(team_id,period_start,period_end)
);
ALTER TABLE billing_export_usage ENABLE ROW LEVEL SECURITY;

CREATE FUNCTION gate_incremental_billing_close() RETURNS trigger LANGUAGE plpgsql AS $$
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
                OR o.counted_quantity<>o.local_quantity OR o.reserved_quantity<>o.local_quantity
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
CREATE TRIGGER team_billing_period_incremental_close BEFORE UPDATE ON team_billing_period
    FOR EACH ROW EXECUTE FUNCTION gate_incremental_billing_close();

-- Re-enablement must revisit hours measured while delivery was disabled.
CREATE FUNCTION reset_incremental_billing_seed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.key='billing_export_enabled' AND NEW.enabled
       AND (TG_OP='INSERT' OR NOT OLD.enabled) THEN
        IF TG_TABLE_NAME='team_feature_flag' THEN
            UPDATE billing_export_work SET seed_after=NULL,seed_complete=false,next_run_at=now()
            WHERE team_id=NEW.team_id;
        ELSE
            -- Discovery resets eligible teams in paced pages, not in this transaction.
            UPDATE billing_export_discovery SET after_team=NULL,reset_existing=true,next_run_at=now();
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER team_feature_flag_incremental_seed AFTER INSERT OR UPDATE ON team_feature_flag
    FOR EACH ROW EXECUTE FUNCTION reset_incremental_billing_seed();
CREATE TRIGGER feature_flag_incremental_seed AFTER INSERT OR UPDATE ON feature_flag
    FOR EACH ROW EXECUTE FUNCTION reset_incremental_billing_seed();

-- Bound operational backlog sampling independently of fleet and period size.
CREATE INDEX billing_export_event_metrics ON billing_export_event(status,created_at,id) WHERE active;
