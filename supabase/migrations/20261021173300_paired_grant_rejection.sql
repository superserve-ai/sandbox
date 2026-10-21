ALTER TABLE billing_provider_pair_dispatch
 ADD COLUMN rejected_at timestamptz,
 ADD COLUMN rejection_evidence jsonb,
 ADD CONSTRAINT provider_pair_dispatch_rejection CHECK (
  (rejected_at IS NULL AND rejection_evidence IS NULL) OR
  COALESCE((rejected_at IS NOT NULL AND sender_finished_at IS NOT NULL AND rejected_at>=sender_finished_at
   AND resolved_at IS NULL AND NOT legacy_untracked AND rejection_evidence IS NOT NULL
   AND jsonb_typeof(rejection_evidence)='object'
   AND rejection_evidence->>'status'='400'
   AND rejection_evidence->>'type'='invalid_request_error'
   AND rejection_evidence->>'code' IN ('parameter_missing','parameter_unknown','parameter_invalid_integer')
   AND left(rejection_evidence->>'request_id',4)='req_' AND length(rejection_evidence->>'request_id')>4
   AND rejection_evidence->>'idempotency_key'=idempotency_key
   AND rejection_evidence ?& ARRAY['status','type','code','request_id','idempotency_key']),false)
 );

CREATE FUNCTION guard_billing_provider_pair_rejection() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.rejected_at IS NOT NULL OR NEW.rejection_evidence IS NOT NULL THEN
   RAISE EXCEPTION 'dispatch must be admitted before rejection';
  END IF;
 ELSIF OLD.rejected_at IS NOT NULL THEN
  IF NEW IS DISTINCT FROM OLD THEN RAISE EXCEPTION 'rejected dispatch is immutable'; END IF;
 ELSIF NEW.rejected_at IS NOT NULL THEN
  IF OLD.sender_finished_at IS NOT NULL OR OLD.resolved_at IS NOT NULL OR OLD.legacy_untracked
   OR NOT EXISTS(SELECT 1 FROM billing_usage_entitlement WHERE id=NEW.entitlement_id AND state='uncertain') THEN
   RAISE EXCEPTION 'only the original returning sender can record rejection';
  END IF;
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER billing_provider_pair_rejection_guard BEFORE INSERT OR UPDATE ON billing_provider_pair_dispatch
FOR EACH ROW EXECUTE FUNCTION guard_billing_provider_pair_rejection();
REVOKE ALL ON FUNCTION guard_billing_provider_pair_rejection() FROM PUBLIC;
