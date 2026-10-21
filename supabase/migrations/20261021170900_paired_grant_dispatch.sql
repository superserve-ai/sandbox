-- A committed admission outlives its sender and any process/connection lease.
CREATE TABLE billing_provider_pair_dispatch (
 id uuid PRIMARY KEY,
 entitlement_id uuid NOT NULL UNIQUE REFERENCES billing_usage_entitlement(id),
 contract_id uuid NOT NULL REFERENCES billing_contract_provider_binding(contract_id),
 team_id uuid NOT NULL REFERENCES team(id),
 binding jsonb NOT NULL CHECK(jsonb_typeof(binding)='object'),
 request_payload jsonb NOT NULL CHECK(jsonb_typeof(request_payload)='object'),
 request_form text NOT NULL,
 idempotency_key text NOT NULL CHECK(btrim(idempotency_key)<>''),
 legacy_untracked boolean NOT NULL DEFAULT false,
 admitted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 sender_finished_at timestamptz,
 resolved_at timestamptz,
 grant_id text,
 CHECK(legacy_untracked OR btrim(request_form)<>''),
 CHECK(sender_finished_at IS NULL OR sender_finished_at>=admitted_at),
 CHECK((resolved_at IS NULL AND grant_id IS NULL) OR
  (resolved_at>=sender_finished_at AND sender_finished_at IS NOT NULL AND grant_id LIKE 'credgr_%'))
);
CREATE INDEX billing_provider_pair_dispatch_unresolved ON billing_provider_pair_dispatch(contract_id) WHERE resolved_at IS NULL;
ALTER TABLE billing_provider_pair_dispatch ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON billing_provider_pair_dispatch FROM PUBLIC;

-- An old ambiguous sender cannot be proved finished by a new process.
INSERT INTO billing_provider_pair_dispatch(id,entitlement_id,contract_id,team_id,binding,request_payload,request_form,idempotency_key,legacy_untracked)
SELECT gen_random_uuid(),e.id,e.contract_id,e.team_id,b.binding,e.request_payload,'',e.idempotency_key,true
FROM billing_usage_entitlement e JOIN billing_contract_provider_binding b ON b.contract_id=e.contract_id
WHERE e.state='uncertain';

CREATE FUNCTION guard_billing_provider_pair_dispatch() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e billing_usage_entitlement; b billing_contract_provider_binding;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'dispatch history is immutable'; END IF;
 SELECT * INTO STRICT e FROM billing_usage_entitlement WHERE id=NEW.entitlement_id;
 SELECT * INTO STRICT b FROM billing_contract_provider_binding WHERE contract_id=NEW.contract_id;
 IF (NEW.team_id,NEW.contract_id,NEW.binding,NEW.request_payload,NEW.idempotency_key)
  IS DISTINCT FROM (e.team_id,e.contract_id,b.binding,e.request_payload,e.idempotency_key) THEN
  RAISE EXCEPTION 'dispatch differs from immutable entitlement and binding';
 END IF;
 IF TG_OP='INSERT' THEN
  IF e.state<>'uncertain' OR NEW.legacy_untracked OR NEW.sender_finished_at IS NOT NULL OR NEW.resolved_at IS NOT NULL
   OR EXISTS(SELECT 1 FROM billing_provider_pair_revocation WHERE contract_id=NEW.contract_id) THEN
   RAISE EXCEPTION 'dispatch admission is inactive or revoked';
  END IF;
 ELSE
  IF (NEW.id,NEW.entitlement_id,NEW.contract_id,NEW.team_id,NEW.binding,NEW.request_payload,NEW.request_form,NEW.idempotency_key,NEW.legacy_untracked,NEW.admitted_at)
   IS DISTINCT FROM (OLD.id,OLD.entitlement_id,OLD.contract_id,OLD.team_id,OLD.binding,OLD.request_payload,OLD.request_form,OLD.idempotency_key,OLD.legacy_untracked,OLD.admitted_at)
   OR OLD.legacy_untracked
   OR (OLD.sender_finished_at IS NOT NULL AND NEW.sender_finished_at IS DISTINCT FROM OLD.sender_finished_at)
   OR (OLD.resolved_at IS NOT NULL AND (NEW.resolved_at,NEW.grant_id) IS DISTINCT FROM (OLD.resolved_at,OLD.grant_id)) THEN
   RAISE EXCEPTION 'dispatch identity and completed evidence are immutable';
  END IF;
  IF NEW.resolved_at IS NOT NULL AND (e.state<>'issued' OR NEW.grant_id IS DISTINCT FROM e.stripe_credit_grant_id) THEN
   RAISE EXCEPTION 'dispatch requires confirmed exact grant';
  END IF;
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER billing_provider_pair_dispatch_guard BEFORE INSERT OR UPDATE OR DELETE ON billing_provider_pair_dispatch
FOR EACH ROW EXECUTE FUNCTION guard_billing_provider_pair_dispatch();
REVOKE ALL ON FUNCTION guard_billing_provider_pair_dispatch() FROM PUBLIC;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN
  GRANT SELECT,INSERT,UPDATE ON billing_provider_pair_dispatch TO service_role;
  CREATE POLICY provider_pair_dispatch_backend ON billing_provider_pair_dispatch TO service_role USING(true) WITH CHECK(true);
 END IF;
END $$;
