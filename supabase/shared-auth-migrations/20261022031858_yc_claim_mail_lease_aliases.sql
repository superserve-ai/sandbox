-- Shared Auth only. Preserve the existing claim RPC attributes and privileges.
BEGIN;
DO $migration$
DECLARE
 definition text;
 body text;
 original_branch constant text := $original$ ELSIF op='mail-lease' THEN
  UPDATE yc_claim_mail SET confirmation_token=NULL WHERE claim_id IN
   (SELECT q.claim_id FROM yc_claim_mail q JOIN yc_claim c ON c.id=q.claim_id
    WHERE q.confirmation_token IS NOT NULL AND c.token_expires_at<=v_now LIMIT 100);
  SELECT q.* INTO m FROM yc_claim_mail q JOIN yc_claim c ON c.id=q.claim_id
   WHERE q.sent_at IS NULL AND q.attempts<8 AND q.next_attempt_at<=v_now
    AND (q.lease_until IS NULL OR q.lease_until<v_now) AND c.state='awaiting_confirmation'
    AND c.token_expires_at>v_now+interval '5 minutes'
   ORDER BY q.next_attempt_at LIMIT 1 FOR UPDATE OF q SKIP LOCKED;
  IF NOT FOUND THEN RETURN '{}'::jsonb; END IF;
  UPDATE yc_claim_mail SET lease_id=(p->>'lease_id')::uuid,lease_until=v_now+interval '1 minute',attempts=attempts+1 WHERE claim_id=m.claim_id;
  SELECT * INTO STRICT c FROM yc_claim WHERE id=m.claim_id;
  RETURN jsonb_build_object('claim_id',c.id,'message_id',m.message_id,'email',c.submitted_email,'token',m.confirmation_token);
$original$;
 corrected_branch constant text := $corrected$ ELSIF op='mail-lease' THEN
  UPDATE yc_claim_mail SET confirmation_token=NULL WHERE claim_id IN
   (SELECT q.claim_id FROM yc_claim_mail q JOIN yc_claim claim_row ON claim_row.id=q.claim_id
    WHERE q.confirmation_token IS NOT NULL AND claim_row.token_expires_at<=v_now LIMIT 100);
  SELECT q.* INTO m FROM yc_claim_mail q JOIN yc_claim claim_row ON claim_row.id=q.claim_id
   WHERE q.sent_at IS NULL AND q.attempts<8 AND q.next_attempt_at<=v_now
    AND (q.lease_until IS NULL OR q.lease_until<v_now) AND claim_row.state='awaiting_confirmation'
    AND claim_row.token_expires_at>v_now+interval '5 minutes'
   ORDER BY q.next_attempt_at LIMIT 1 FOR UPDATE OF q SKIP LOCKED;
  IF NOT FOUND THEN RETURN '{}'::jsonb; END IF;
  UPDATE yc_claim_mail SET lease_id=(p->>'lease_id')::uuid,lease_until=v_now+interval '1 minute',attempts=attempts+1 WHERE claim_id=m.claim_id;
  SELECT * INTO STRICT c FROM yc_claim WHERE id=m.claim_id;
  RETURN jsonb_build_object('claim_id',c.id,'message_id',m.message_id,'email',c.submitted_email,'token',m.confirmation_token);
$corrected$;
BEGIN
 SELECT pg_get_functiondef(oid),prosrc INTO STRICT definition,body
 FROM pg_proc WHERE oid='public.yc_claim_rpc(text,jsonb)'::regprocedure;
 IF encode(sha256(convert_to(body,'UTF8')),'hex')<>'5a65f3209776bc61823756927a40f399b84ed0db578132ab4aa0d4a984901273' THEN
  RAISE EXCEPTION 'unexpected claim RPC body; inspect before updating';
 END IF;
 definition := replace(definition,original_branch,corrected_branch);
 EXECUTE definition;
 IF (SELECT encode(sha256(convert_to(prosrc,'UTF8')),'hex') FROM pg_proc
     WHERE oid='public.yc_claim_rpc(text,jsonb)'::regprocedure)<>'1a95c22740b395df59e14f9164810d53ef07d978ac130341d69cf8fd0c6f08b7' THEN
  RAISE EXCEPTION 'claim mail lease update verification failed';
 END IF;
END $migration$;
COMMIT;
