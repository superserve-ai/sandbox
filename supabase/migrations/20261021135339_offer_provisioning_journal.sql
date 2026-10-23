-- Provider preparation is not commercial authority or permission to issue credit.
CREATE TABLE billing_offer_provisioning_operation (
    id uuid PRIMARY KEY,
    team_id uuid NOT NULL REFERENCES team(id),
    assignment_id uuid NOT NULL UNIQUE,
    accepted_offer jsonb NOT NULL CHECK (jsonb_typeof(accepted_offer) = 'object'),
    state text NOT NULL DEFAULT 'provisioning' CHECK (state IN ('provisioning','outcome_unknown','review_required','grant_pending')),
    held boolean NOT NULL DEFAULT false,
    revoked_at timestamptz,
    control_reason text,
    control_actor uuid,
    control_pending boolean NOT NULL DEFAULT false,
    finalized_at timestamptz,
    verification jsonb,
    last_error text,
    next_check_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE(team_id),
    CHECK ((finalized_at IS NULL) = (verification IS NULL)),
    CHECK (state <> 'grant_pending' OR finalized_at IS NOT NULL),
    CHECK ((NOT held AND revoked_at IS NULL) OR (control_actor IS NOT NULL AND length(control_reason)>0))
);

CREATE TABLE billing_offer_provisioning_request (
    operation_id uuid NOT NULL REFERENCES billing_offer_provisioning_operation(id),
    step text NOT NULL CHECK (step IN ('customer','waiver','fee','usage','usage_hold')),
    idempotency_key text NOT NULL UNIQUE,
    request jsonb NOT NULL CHECK (jsonb_typeof(request) = 'object'),
    state text NOT NULL DEFAULT 'prepared' CHECK (state IN ('prepared','dispatched','confirmed')),
    dispatched_at timestamptz,
    receipt jsonb,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(operation_id,step),
    CHECK ((state='prepared') = (dispatched_at IS NULL)),
    CHECK ((state='confirmed') = (receipt IS NOT NULL))
);
CREATE INDEX billing_offer_provisioning_due ON billing_offer_provisioning_operation(next_check_at,id)
    WHERE finalized_at IS NULL AND NOT held AND revoked_at IS NULL;
CREATE INDEX billing_offer_provisioning_dispatched ON billing_offer_provisioning_request(dispatched_at) WHERE state='dispatched';

CREATE TABLE billing_offer_provisioning_audit (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    operation_id uuid NOT NULL REFERENCES billing_offer_provisioning_operation(id),
    actor_id uuid NOT NULL,
    action text NOT NULL CHECK (action IN ('hold','release','revoke')),
    reason text NOT NULL CHECK (length(reason)>0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE FUNCTION guard_offer_provisioning_journal() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' THEN RAISE EXCEPTION 'provisioning history cannot be deleted'; END IF;
    IF TG_TABLE_NAME='billing_offer_provisioning_operation' THEN
        IF (NEW.id,NEW.team_id,NEW.assignment_id,NEW.accepted_offer,NEW.created_at)
            IS DISTINCT FROM (OLD.id,OLD.team_id,OLD.assignment_id,OLD.accepted_offer,OLD.created_at)
            OR (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at)
            OR (OLD.finalized_at IS NOT NULL AND (NEW.finalized_at,NEW.verification) IS DISTINCT FROM (OLD.finalized_at,OLD.verification)) THEN
            RAISE EXCEPTION 'provisioning identity and confirmed authority are immutable';
        END IF;
    ELSIF TG_TABLE_NAME='billing_offer_provisioning_request' THEN
        IF (NEW.operation_id,NEW.step,NEW.idempotency_key,NEW.request,NEW.created_at)
            IS DISTINCT FROM (OLD.operation_id,OLD.step,OLD.idempotency_key,OLD.request,OLD.created_at)
            OR (OLD.dispatched_at IS NOT NULL AND NEW.dispatched_at IS DISTINCT FROM OLD.dispatched_at)
            OR (OLD.state='dispatched' AND NEW.state NOT IN ('dispatched','confirmed'))
            OR (OLD.state='confirmed' AND (NEW.state,NEW.receipt) IS DISTINCT FROM (OLD.state,OLD.receipt)) THEN
            RAISE EXCEPTION 'provider request and confirmed receipt are immutable';
        END IF;
    ELSE
        RAISE EXCEPTION 'provisioning audit is immutable';
    END IF;
    RETURN NEW;
END $$;
DO $$ DECLARE t text; BEGIN
    IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN
        FOREACH t IN ARRAY ARRAY['billing_offer_provisioning_operation','billing_offer_provisioning_request'] LOOP
            EXECUTE format('GRANT SELECT,INSERT,UPDATE ON %I TO service_role',t);
            EXECUTE format('CREATE POLICY offer_provisioning_backend ON %I TO service_role USING(true) WITH CHECK(true)',t);
        END LOOP;
        GRANT SELECT,INSERT ON billing_offer_provisioning_audit TO service_role;
        GRANT USAGE ON SEQUENCE billing_offer_provisioning_audit_id_seq TO service_role;
        CREATE POLICY offer_provisioning_audit_backend ON billing_offer_provisioning_audit TO service_role USING(true) WITH CHECK(true);
    END IF;
END $$;
CREATE TRIGGER offer_provisioning_operation_guard BEFORE UPDATE OR DELETE ON billing_offer_provisioning_operation
    FOR EACH ROW EXECUTE FUNCTION guard_offer_provisioning_journal();
CREATE TRIGGER offer_provisioning_request_guard BEFORE UPDATE OR DELETE ON billing_offer_provisioning_request
    FOR EACH ROW EXECUTE FUNCTION guard_offer_provisioning_journal();
CREATE TRIGGER offer_provisioning_audit_guard BEFORE UPDATE OR DELETE ON billing_offer_provisioning_audit
    FOR EACH ROW EXECUTE FUNCTION guard_offer_provisioning_journal();

ALTER TABLE billing_offer_provisioning_operation ENABLE ROW LEVEL SECURITY;
ALTER TABLE billing_offer_provisioning_request ENABLE ROW LEVEL SECURITY;
ALTER TABLE billing_offer_provisioning_audit ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON billing_offer_provisioning_operation,billing_offer_provisioning_request,billing_offer_provisioning_audit FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_offer_provisioning_journal() FROM PUBLIC;
DO $$ DECLARE r text; BEGIN
    FOREACH r IN ARRAY ARRAY['anon','authenticated'] LOOP
        IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=r) THEN
            EXECUTE format('REVOKE ALL ON billing_offer_provisioning_operation,billing_offer_provisioning_request,billing_offer_provisioning_audit FROM %I',r);
        END IF;
    END LOOP;
END $$;

-- No operation foreign key: revocation may precede regional operation delivery.
CREATE TABLE billing_offer_financial_fence (
    id uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    team_id uuid NOT NULL,
    assignment_id uuid NOT NULL,
    phase text NOT NULL CHECK (phase IN ('initial','successor')),
    target_id uuid NOT NULL,
    authorization_receipt jsonb CHECK (jsonb_typeof(authorization_receipt)='object'),
    finalized_at timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(team_id,assignment_id,phase,target_id),
    CHECK ((phase='initial')=(target_id=assignment_id)),
    CHECK (finalized_at IS NULL OR authorization_receipt IS NOT NULL)
);
CREATE UNIQUE INDEX billing_offer_financial_authorization_id ON billing_offer_financial_fence ((authorization_receipt->>'authorization_id')) WHERE authorization_receipt IS NOT NULL;
CREATE TABLE billing_offer_financial_revocation (
    id uuid PRIMARY KEY,
    acknowledgement_id uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    team_id uuid NOT NULL,
    assignment_id uuid NOT NULL,
    phase text NOT NULL,
    target_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY(team_id,assignment_id,phase,target_id) REFERENCES billing_offer_financial_fence(team_id,assignment_id,phase,target_id)
);
CREATE FUNCTION guard_offer_financial_fence() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'financial fences are permanent'; END IF;
 IF TG_OP='UPDATE' AND (
   (NEW.id,NEW.team_id,NEW.assignment_id,NEW.phase,NEW.target_id,NEW.created_at) IS DISTINCT FROM (OLD.id,OLD.team_id,OLD.assignment_id,OLD.phase,OLD.target_id,OLD.created_at)
   OR OLD.authorization_receipt IS NOT NULL AND NEW.authorization_receipt IS DISTINCT FROM OLD.authorization_receipt
   OR OLD.finalized_at IS NOT NULL AND NEW.finalized_at IS DISTINCT FROM OLD.finalized_at
   OR OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
   OR OLD.revoked_at IS NOT NULL AND (NEW.authorization_receipt,NEW.finalized_at) IS DISTINCT FROM (OLD.authorization_receipt,OLD.finalized_at)) THEN
   RAISE EXCEPTION 'financial fence history is immutable';
 END IF;
 IF NEW.authorization_receipt IS NOT NULL AND NEW.authorization_receipt->'target' IS DISTINCT FROM jsonb_build_object('team_id',NEW.team_id,'assignment_id',NEW.assignment_id,'phase',NEW.phase,'target_id',NEW.target_id) THEN
   RAISE EXCEPTION 'financial authorization_receipt target differs';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER billing_offer_financial_fence_guard BEFORE INSERT OR UPDATE OR DELETE ON billing_offer_financial_fence FOR EACH ROW EXECUTE FUNCTION guard_offer_financial_fence();
CREATE TRIGGER billing_offer_financial_revocation_immutable BEFORE UPDATE OR DELETE ON billing_offer_financial_revocation FOR EACH ROW EXECUTE FUNCTION guard_offer_provisioning_journal();
ALTER TABLE billing_offer_financial_fence ENABLE ROW LEVEL SECURITY;
ALTER TABLE billing_offer_financial_revocation ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON billing_offer_financial_fence,billing_offer_financial_revocation FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_offer_financial_fence() FROM PUBLIC;
DO $$ DECLARE r text; BEGIN
 FOREACH r IN ARRAY ARRAY['anon','authenticated'] LOOP
  IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=r) THEN
   EXECUTE format('REVOKE ALL ON billing_offer_financial_fence,billing_offer_financial_revocation FROM %I',r);
  END IF;
 END LOOP;
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN
  GRANT SELECT,INSERT,UPDATE ON billing_offer_financial_fence TO service_role;
  GRANT SELECT,INSERT ON billing_offer_financial_revocation TO service_role;
  CREATE POLICY offer_financial_fence_backend ON billing_offer_financial_fence TO service_role USING(true) WITH CHECK(true);
  CREATE POLICY offer_financial_revocation_backend ON billing_offer_financial_revocation TO service_role USING(true) WITH CHECK(true);
 END IF;
END $$;
