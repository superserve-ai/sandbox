ALTER TABLE billing_incremental_period ADD COLUMN correction_version bigint NOT NULL DEFAULT 0;

-- Operator measurements are evidence, not changes to finalized financial rows.
CREATE TABLE billing_export_correction (
    id uuid PRIMARY KEY,
    team_id uuid NOT NULL,
    period_start timestamptz NOT NULL,
    period_end timestamptz NOT NULL,
    resource_type text NOT NULL CHECK (resource_type IN ('cpu','memory','storage')),
    frozen boolean NOT NULL,
    version bigint NOT NULL,
    measured_quantity numeric NOT NULL CHECK (measured_quantity >= 0),
    baseline_quantity numeric NOT NULL CHECK (baseline_quantity >= 0),
    reserved_quantity numeric NOT NULL CHECK (reserved_quantity >= 0),
    target_quantity numeric NOT NULL CHECK (target_quantity >= measured_quantity),
    previous_id uuid REFERENCES billing_export_correction(id),
    measurement_snapshot text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    applied_at timestamptz,
    applied_by uuid REFERENCES profile(id),
    approval_snapshot text,
    action text CHECK (action IN ('accept_usage','retain_exported')),
    evidence text,
    FOREIGN KEY(team_id,period_start,period_end)
        REFERENCES billing_incremental_period(team_id,period_start,period_end),
    CHECK ((applied_at IS NULL AND applied_by IS NULL AND approval_snapshot IS NULL AND action IS NULL AND evidence IS NULL) OR
           (applied_at IS NOT NULL AND applied_by IS NOT NULL AND approval_snapshot IS NOT NULL AND action IS NOT NULL AND evidence IS NOT NULL AND btrim(evidence) <> ''))
);
CREATE INDEX billing_export_correction_latest ON billing_export_correction
    (team_id,period_start,period_end,resource_type,applied_at DESC,id) WHERE applied_at IS NOT NULL;
CREATE INDEX billing_export_correction_period_cursor ON billing_export_correction
    (team_id,period_start,period_end,id);
ALTER TABLE billing_export_correction ENABLE ROW LEVEL SECURITY;
ALTER TABLE billing_export_allocation ADD COLUMN correction_id uuid REFERENCES billing_export_correction(id);

CREATE FUNCTION protect_billing_export_correction() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' THEN RAISE EXCEPTION 'correction evidence cannot be deleted'; END IF;
    IF OLD.applied_at IS NOT NULL OR
       (to_jsonb(NEW)-'applied_at'-'applied_by'-'approval_snapshot'-'action'-'evidence') IS DISTINCT FROM
       (to_jsonb(OLD)-'applied_at'-'applied_by'-'approval_snapshot'-'action'-'evidence') THEN
        RAISE EXCEPTION 'correction evidence is immutable';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER billing_export_correction_immutable BEFORE UPDATE OR DELETE ON billing_export_correction
    FOR EACH ROW EXECUTE FUNCTION protect_billing_export_correction();

CREATE OR REPLACE FUNCTION validate_billing_export_allocation() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE allocated numeric; is_frozen boolean;
BEGIN
    SELECT p.finalized_at IS NOT NULL OR p.exported_at IS NOT NULL INTO STRICT is_frozen
    FROM team_billing_period p WHERE p.team_id=NEW.team_id AND p.period_start=NEW.period_start
      AND p.period_end=NEW.period_end FOR UPDATE;
    IF NEW.correction_id IS NOT NULL THEN
        IF NOT EXISTS(SELECT 1 FROM billing_export_correction c WHERE c.id=NEW.correction_id
            AND c.team_id=NEW.team_id AND c.period_start=NEW.period_start AND c.period_end=NEW.period_end
            AND c.resource_type=NEW.resource_type AND c.applied_at IS NOT NULL
            AND NEW.coverage_end<=c.target_quantity) THEN
            RAISE EXCEPTION 'allocation requires reviewed correction evidence';
        END IF;
    ELSIF is_frozen THEN RAISE EXCEPTION 'billing period is immutable';
    END IF;
    SELECT COALESCE((SELECT coverage_end FROM billing_export_allocation a
        WHERE a.team_id=NEW.team_id AND a.period_start=NEW.period_start AND a.period_end=NEW.period_end
          AND a.resource_type=NEW.resource_type ORDER BY coverage_end DESC LIMIT 1),0) INTO allocated;
    IF allocated<>NEW.coverage_start THEN RAISE EXCEPTION 'billing coverage must extend existing reservations'; END IF;
    UPDATE billing_incremental_period SET correction_version=correction_version+1
        WHERE team_id=NEW.team_id AND period_start=NEW.period_start AND period_end=NEW.period_end;
    RETURN NEW;
END;
$$;

-- The close snapshot remains the baseline even before provider reconciliation finishes.
CREATE FUNCTION protect_incremental_frozen_usage() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS(SELECT 1 FROM billing_incremental_period i JOIN team_billing_period p
        USING(team_id,period_start,period_end) WHERE i.team_id=OLD.team_id
        AND i.period_start=OLD.period_start AND i.period_end=OLD.period_end
        AND (p.status IN ('exporting','exported','finalized') OR p.exported_at IS NOT NULL OR p.finalized_at IS NOT NULL))
        AND (TG_OP='DELETE' OR ROW(NEW.vcpu_seconds,NEW.memory_mib_seconds,NEW.storage_mib_seconds)
          IS DISTINCT FROM ROW(OLD.vcpu_seconds,OLD.memory_mib_seconds,OLD.storage_mib_seconds)) THEN
        RAISE EXCEPTION 'incremental close measurement is immutable';
    END IF;
    IF TG_OP='DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER team_billing_usage_incremental_freeze BEFORE UPDATE OR DELETE ON team_billing_usage
    FOR EACH ROW EXECUTE FUNCTION protect_incremental_frozen_usage();

CREATE FUNCTION gate_incremental_correction_review() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.status IN ('exported','finalized') AND OLD.finalized_at IS NULL AND EXISTS(
        SELECT 1 FROM billing_period_anomaly a WHERE a.team_id=NEW.team_id
        AND a.period_start=NEW.period_start AND a.period_end=NEW.period_end
        AND a.resolved_at IS NULL AND a.severity IN ('error','critical')
        AND a.kind IN ('usage_after_export_freeze','incremental_export_exceeds_usage')) THEN
        RAISE EXCEPTION 'usage discrepancy requires reviewed correction';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER team_billing_period_correction_review BEFORE UPDATE ON team_billing_period
    FOR EACH ROW EXECUTE FUNCTION gate_incremental_correction_review();
