-- Shared Auth only. Preserve the existing approval mail RPC attributes and privileges.
BEGIN;
DO $migration$
DECLARE
 definition text;
 body text;
 original_branch constant text := $original$ ELSIF op='lease' THEN
  SELECT q.* INTO m FROM yc_claim_approval_mail q JOIN yc_claim c ON c.id=q.claim_id
   JOIN auth.users u ON u.id=q.approved_user_id
   WHERE q.sent_at IS NULL AND q.attempts<8 AND COALESCE(q.last_error,'') NOT IN ('delivery_unknown','delivery_rejected') AND q.next_attempt_at<=v_now AND (q.lease_until IS NULL OR q.lease_until<v_now)
    AND c.state='bound' AND c.approval_id=q.approval_id AND c.claimed_user_id=q.approved_user_id
    AND c.claimed_team_id=q.approved_team_id AND c.home_region=q.home_region
    AND EXISTS(SELECT 1 FROM public.read_yc_activation_authority(c.company_identity,c.claimed_team_id) a WHERE a.approval_id=q.approval_id AND a.revoked_at IS NULL)
    AND u.deleted_at IS NULL AND u.email_confirmed_at IS NOT NULL AND lower(btrim(u.email))=q.approved_email
   ORDER BY q.next_attempt_at LIMIT 1 FOR UPDATE OF q SKIP LOCKED;
  IF NOT FOUND THEN RETURN '{}'::jsonb; END IF;
  -- Mark uncertain before dispatch. A crash or lost acknowledgement must never
  -- automatically resubmit to a transport without provider idempotency.
  UPDATE yc_claim_approval_mail SET last_error='delivery_unknown',attempts=attempts+1,lease_id=(p->>'lease_id')::uuid,lease_until=v_now+interval '1 minute' WHERE claim_id=m.claim_id;
  RETURN jsonb_build_object('claim_id',m.claim_id,'message_id',m.message_id,'email',m.approved_email);
$original$;
 scoped_branch constant text := $scoped$ ELSIF op IN ('lease','lease-for-claim') THEN
  IF op='lease-for-claim' AND (p IS NULL OR jsonb_typeof(p)<>'object'
   OR NULLIF((p->>'claim_id')::uuid,'00000000-0000-0000-0000-000000000000'::uuid) IS NULL
   OR NULLIF((p->>'lease_id')::uuid,'00000000-0000-0000-0000-000000000000'::uuid) IS NULL) THEN
   RAISE EXCEPTION 'exact approval mail scope required' USING ERRCODE='22023';
  END IF;
  SELECT q.* INTO m FROM yc_claim_approval_mail q JOIN yc_claim c ON c.id=q.claim_id
   JOIN auth.users u ON u.id=q.approved_user_id
   WHERE q.sent_at IS NULL AND q.attempts<8 AND COALESCE(q.last_error,'') NOT IN ('delivery_unknown','delivery_rejected') AND q.next_attempt_at<=v_now AND (q.lease_until IS NULL OR q.lease_until<v_now)
    AND c.state='bound' AND c.approval_id=q.approval_id AND c.claimed_user_id=q.approved_user_id
    AND c.claimed_team_id=q.approved_team_id AND c.home_region=q.home_region
    AND EXISTS(SELECT 1 FROM public.read_yc_activation_authority(c.company_identity,c.claimed_team_id) a WHERE a.approval_id=q.approval_id AND a.revoked_at IS NULL)
    AND u.deleted_at IS NULL AND u.email_confirmed_at IS NOT NULL AND lower(btrim(u.email))=q.approved_email
    AND CASE WHEN op='lease-for-claim' THEN q.claim_id=(p->>'claim_id')::uuid ELSE true END
   ORDER BY q.next_attempt_at LIMIT 1 FOR UPDATE OF q SKIP LOCKED;
  IF NOT FOUND THEN RETURN '{}'::jsonb; END IF;
  -- Mark uncertain before dispatch. A crash or lost acknowledgement must never
  -- automatically resubmit to a transport without provider idempotency.
  UPDATE yc_claim_approval_mail SET last_error='delivery_unknown',attempts=attempts+1,lease_id=(p->>'lease_id')::uuid,lease_until=v_now+interval '1 minute' WHERE claim_id=m.claim_id;
  RETURN jsonb_build_object('claim_id',m.claim_id,'message_id',m.message_id,'email',m.approved_email);
$scoped$;
BEGIN
 SELECT pg_get_functiondef(oid),prosrc INTO STRICT definition,body
 FROM pg_proc WHERE oid='public.yc_claim_approval_mail_rpc(text,jsonb)'::regprocedure;
 IF encode(sha256(convert_to(body,'UTF8')),'hex')<>'08616f2f13b3c8edf6f51b036206db2c2dac59b976b60aac1712d34b32e045a5' THEN
  RAISE EXCEPTION 'unexpected approval mail RPC body; inspect before updating';
 END IF;
 definition := replace(definition,original_branch,scoped_branch);
 EXECUTE definition;
 IF (SELECT encode(sha256(convert_to(prosrc,'UTF8')),'hex') FROM pg_proc
     WHERE oid='public.yc_claim_approval_mail_rpc(text,jsonb)'::regprocedure)<>'5f3544387c1f0731454cf82af02dbd63e00aaed107d5dac94c4238edafa93b64' THEN
  RAISE EXCEPTION 'approval mail scope update verification failed';
 END IF;
END $migration$;
COMMIT;
