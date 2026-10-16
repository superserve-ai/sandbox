-- Shared Auth/control-plane database only, never a regional claim replica.
BEGIN;
CREATE TABLE public.yc_claim (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 verification_reference text NOT NULL CHECK (verification_reference ~ '^[a-f0-9]{64}$'),
 submitted_email text NOT NULL,
 founder_email text NOT NULL,
 evidence jsonb NOT NULL CHECK (jsonb_typeof(evidence)='object'),
 company_identity text,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 verified_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 state text NOT NULL CHECK (state IN ('manual_review','awaiting_confirmation','confirmed','bound','rejected','revoked')),
 reason text NOT NULL,
 token_hash text UNIQUE CHECK (token_hash ~ '^[a-f0-9]{64}$'),
 token_expires_at timestamptz,
 confirmed_at timestamptz,
 intent_user_id uuid,
 intent_team_id uuid,
 intent_region text,
 capture_user_id uuid,
 lifecycle_changed boolean NOT NULL DEFAULT false,
 claimed_user_id uuid,
 claimed_team_id uuid,
 home_region text,
 claimed_at timestamptz,
 approval_id uuid,
 billing_contract_id uuid,
 billing_state text,
 billing_checked_at timestamptz,
 revision bigint NOT NULL DEFAULT 0,
 UNIQUE(verification_reference,submitted_email),
 CHECK ((claimed_user_id IS NULL AND claimed_team_id IS NULL AND home_region IS NULL AND claimed_at IS NULL AND approval_id IS NULL)
 OR (claimed_user_id IS NOT NULL AND claimed_team_id IS NOT NULL AND home_region IS NOT NULL AND claimed_at IS NOT NULL AND approval_id IS NOT NULL))
);
CREATE INDEX yc_claim_email ON public.yc_claim(submitted_email,created_at DESC);
CREATE INDEX yc_claim_company ON public.yc_claim(company_identity);
CREATE TABLE public.yc_claim_decision (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 claim_id uuid NOT NULL REFERENCES public.yc_claim(id),
 revision bigint NOT NULL,
 decision text NOT NULL,
 actor_id uuid,
 reason text NOT NULL,
 evidence_reference text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(claim_id,revision)
);
CREATE TABLE public.yc_claim_mail (
 claim_id uuid PRIMARY KEY REFERENCES public.yc_claim(id),
 message_id uuid NOT NULL DEFAULT gen_random_uuid(),
 confirmation_token text,
 next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 attempts integer NOT NULL DEFAULT 0,
 lease_id uuid,
 lease_until timestamptz,
 sent_at timestamptz,
 last_error text,
 CHECK (confirmation_token IS NULL OR confirmation_token ~ '^[A-Za-z0-9_-]{43}$')
);
CREATE INDEX yc_claim_mail_due ON public.yc_claim_mail(next_attempt_at) WHERE sent_at IS NULL AND attempts<8;
CREATE TABLE public.yc_claim_rate (
 bucket text PRIMARY KEY,
 window_start timestamptz NOT NULL,
 requests integer NOT NULL
);

CREATE INDEX yc_claim_rate_expiry ON public.yc_claim_rate(window_start);

CREATE TABLE public.yc_claim_identity_history (
 email_hash text PRIMARY KEY,
 prior_user_id uuid NOT NULL,
 changed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE FUNCTION public.yc_claim_view(c public.yc_claim) RETURNS jsonb
LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $$
 SELECT jsonb_build_object('id',c.id,'state',c.state,'reason',c.reason,'company_identity',c.company_identity,
 'submitted_email',c.submitted_email,'founder_email',c.founder_email,'evidence',c.evidence,
 'confirmed_at',c.confirmed_at,'team_id',c.claimed_team_id,'home_region',c.home_region,
 'billing_contract_id',c.billing_contract_id,'billing_state',c.billing_state,'billing_checked_at',c.billing_checked_at,'approval_id',c.approval_id,'offer','yc_2026','offer_version',1,'claimed_user_id',c.claimed_user_id,
 'lifecycle_changed',c.lifecycle_changed,'intent_team_id',c.intent_team_id,'intent_region',c.intent_region,'claimed_at',c.claimed_at,'verification_reference',c.verification_reference,'verified_at',c.verified_at,
 'approval_method',(SELECT decision FROM yc_claim_decision WHERE claim_id=c.id AND decision IN ('operator','verified_claim') ORDER BY revision DESC LIMIT 1),
 'confirmation_status',CASE WHEN c.state IN ('awaiting_confirmation','confirmed') AND c.token_expires_at<=now() THEN 'expired'
 WHEN c.confirmed_at IS NOT NULL THEN 'confirmed'
 WHEN EXISTS(SELECT 1 FROM yc_claim_mail WHERE claim_id=c.id AND sent_at IS NOT NULL) THEN 'sent'
 WHEN EXISTS(SELECT 1 FROM yc_claim_mail WHERE claim_id=c.id AND attempts>=8) THEN 'delivery_failed' ELSE 'pending' END,
 'revision',c.revision,'created_at',c.created_at)
$$;

CREATE FUNCTION public.yc_claim_rpc(op text,p jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $$
DECLARE c public.yc_claim; u record; g public.yc_claim_rate; m public.yc_claim_mail; n integer; k text;
 v_now timestamptz:=clock_timestamp(); v_approval uuid; v_method text; v_prior_operator boolean:=false;
BEGIN
 IF p IS NULL OR jsonb_typeof(p)<>'object' THEN RAISE EXCEPTION 'invalid claim request' USING ERRCODE='22023'; END IF;
 IF op='pending' THEN
  RETURN jsonb_build_object('claims',COALESCE((SELECT jsonb_agg(yc_claim_view(q)) FROM
   (SELECT * FROM yc_claim WHERE state='bound' AND id>COALESCE((p->>'after_id')::uuid,'00000000-0000-0000-0000-000000000000'::uuid)
    ORDER BY id LIMIT 100) q),'[]'::jsonb));
 ELSIF op='budget' THEN
  IF COALESCE(p->>'email_hash','') !~ '^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'invalid rate identity' USING ERRCODE='22023'; END IF;
  INSERT INTO yc_claim_rate(bucket,window_start,requests) VALUES('global',v_now,0) ON CONFLICT DO NOTHING;
  SELECT * INTO STRICT g FROM yc_claim_rate WHERE bucket='global' FOR UPDATE;
  IF g.window_start<v_now-interval '1 hour' THEN
   UPDATE yc_claim_rate SET window_start=v_now,requests=0 WHERE bucket='global' RETURNING * INTO g;
  END IF;
  DELETE FROM yc_claim_rate WHERE bucket IN (SELECT bucket FROM yc_claim_rate WHERE bucket<>'global' AND window_start<v_now-interval '2 hours' ORDER BY window_start LIMIT 100);
  IF g.requests>=120 THEN RETURN '{"allowed":false}'::jsonb; END IF;
  INSERT INTO yc_claim_rate(bucket,window_start,requests) VALUES(p->>'email_hash',v_now,1)
  ON CONFLICT(bucket) DO UPDATE SET
   requests=CASE WHEN yc_claim_rate.window_start<v_now-interval '1 hour' THEN 1 ELSE LEAST(6,yc_claim_rate.requests+1) END,
   window_start=CASE WHEN yc_claim_rate.window_start<v_now-interval '1 hour' THEN v_now ELSE yc_claim_rate.window_start END
  RETURNING requests INTO n;
  IF n>5 THEN RETURN '{"allowed":false}'::jsonb; END IF;
  UPDATE yc_claim_rate SET requests=requests+1 WHERE bucket='global';
  RETURN '{"allowed":true}'::jsonb;
 ELSIF op='submit' THEN
  IF COALESCE(p->>'submitted_email','')='' OR length(p->>'submitted_email')>254 OR
   COALESCE(p->>'verification_reference','') !~ '^[a-f0-9]{64}$' OR
   COALESCE(p->>'state','') NOT IN ('awaiting_confirmation','manual_review') OR
   COALESCE((p->'evidence'->>'verified')::boolean,false) IS NOT TRUE THEN
   RAISE EXCEPTION 'invalid verified claim' USING ERRCODE='22023';
  END IF;
  IF p->>'state'='awaiting_confirmation' AND (p->>'submitted_email' IS DISTINCT FROM p->>'founder_email' OR
   COALESCE(p->>'company_identity','')='' OR COALESCE(p->>'token_hash','') !~ '^[a-f0-9]{64}$' OR
   COALESCE(p->>'confirmation_token','') !~ '^[A-Za-z0-9_-]{43}$') THEN
   RAISE EXCEPTION 'invalid automatic claim' USING ERRCODE='22023';
  END IF;
  INSERT INTO yc_claim(capture_user_id,lifecycle_changed,verification_reference,submitted_email,founder_email,evidence,company_identity,state,reason,token_hash,token_expires_at)
  VALUES((SELECT id FROM auth.users WHERE lower(btrim(email))=p->>'submitted_email' AND deleted_at IS NULL LIMIT 1),EXISTS(SELECT 1 FROM yc_claim_identity_history WHERE email_hash=encode(sha256(convert_to(p->>'submitted_email','UTF8')),'hex')),p->>'verification_reference',p->>'submitted_email',COALESCE(p->>'founder_email',''),p->'evidence',NULLIF(p->>'company_identity',''),p->>'state',p->>'reason',p->>'token_hash',CASE WHEN p->>'token_hash' IS NOT NULL THEN v_now+interval '24 hours' END)
  ON CONFLICT(verification_reference,submitted_email) DO NOTHING RETURNING * INTO c;
  IF NOT FOUND THEN
   SELECT * INTO STRICT c FROM yc_claim WHERE verification_reference=p->>'verification_reference' AND submitted_email=p->>'submitted_email';
   RETURN yc_claim_view(c);
  END IF;
  INSERT INTO yc_claim_decision(claim_id,revision,decision,reason,evidence_reference)
   VALUES(c.id,0,c.state,c.reason,c.verification_reference);
  IF c.state='awaiting_confirmation' THEN INSERT INTO yc_claim_mail(claim_id,confirmation_token) VALUES(c.id,p->>'confirmation_token'); END IF;
  RETURN yc_claim_view(c);
 ELSIF op='mail-lease' THEN
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
 ELSIF op='mail-finish' THEN
  UPDATE yc_claim_mail SET sent_at=CASE WHEN (p->>'success')::boolean THEN v_now ELSE NULL END,
   confirmation_token=CASE WHEN (p->>'success')::boolean THEN NULL ELSE confirmation_token END,
   last_error=CASE WHEN (p->>'success')::boolean THEN NULL ELSE 'delivery_failed' END,
   next_attempt_at=v_now+interval '1 minute'*LEAST(60,power(2,attempts)::integer),lease_until=NULL
   WHERE claim_id=(p->>'id')::uuid AND lease_id=(p->>'lease_id')::uuid;
  RETURN '{}'::jsonb;
 END IF;

 IF op='lookup' AND p->>'id' IS NULL THEN
  SELECT email,email_confirmed_at,deleted_at INTO u FROM auth.users WHERE id=(p->>'user_id')::uuid;
  IF NOT FOUND OR u.email_confirmed_at IS NULL OR u.deleted_at IS NOT NULL THEN RETURN '{"claims":[]}'::jsonb; END IF;
  RETURN jsonb_build_object('claims',COALESCE((SELECT jsonb_agg(yc_claim_view(q)) FROM
   (SELECT * FROM yc_claim WHERE submitted_email=lower(btrim(u.email)) AND (claimed_user_id IS NULL OR claimed_user_id=(p->>'user_id')::uuid) ORDER BY created_at DESC LIMIT 20) q),'[]'::jsonb));
 END IF;
 SELECT * INTO c FROM yc_claim WHERE id=(p->>'id')::uuid FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'claim unavailable' USING ERRCODE='P0002'; END IF;
 IF op='confirm' THEN
  IF c.token_hash IS NULL OR c.token_hash IS DISTINCT FROM p->>'token_hash' OR c.token_expires_at<=v_now OR c.state NOT IN ('awaiting_confirmation','confirmed','bound') THEN
   RAISE EXCEPTION 'confirmation unavailable' USING ERRCODE='22023';
  END IF;
  IF c.state='awaiting_confirmation' THEN
   UPDATE yc_claim SET state='confirmed',confirmed_at=v_now,reason='email_confirmed',revision=revision+1 WHERE id=c.id RETURNING * INTO c;
   UPDATE yc_claim_mail SET confirmation_token=NULL WHERE claim_id=c.id;
   INSERT INTO yc_claim_decision(claim_id,revision,decision,reason,evidence_reference) VALUES(c.id,c.revision,'confirmed','email_confirmed',c.verification_reference);
  END IF;
  RETURN yc_claim_view(c);
 ELSIF op='operator-get' THEN
  RETURN yc_claim_view(c)||jsonb_build_object('decisions',COALESCE((SELECT jsonb_agg(d ORDER BY revision) FROM yc_claim_decision d WHERE claim_id=c.id),'[]'::jsonb));
 ELSIF op='account-get' THEN
  SELECT email,email_confirmed_at,deleted_at INTO u FROM auth.users WHERE id=(p->>'user_id')::uuid;
  IF NOT FOUND OR u.email_confirmed_at IS NULL OR u.deleted_at IS NOT NULL OR lower(btrim(u.email))<>c.submitted_email
    OR c.claimed_user_id IS DISTINCT FROM (p->>'user_id')::uuid THEN RAISE EXCEPTION 'claim unavailable' USING ERRCODE='P0002'; END IF;
  RETURN yc_claim_view(c);
 ELSIF op='billing-status' THEN
  IF c.approval_id IS DISTINCT FROM (p->>'approval_id')::uuid OR c.claimed_team_id IS DISTINCT FROM (p->>'team_id')::uuid
   OR c.approval_id IS NULL THEN RAISE EXCEPTION 'billing binding mismatch' USING ERRCODE='22023'; END IF;
  IF c.billing_contract_id IS NOT NULL AND c.billing_contract_id IS DISTINCT FROM (p->>'contract_id')::uuid THEN
   RAISE EXCEPTION 'billing contract changed' USING ERRCODE='22023'; END IF;
  UPDATE yc_claim SET billing_contract_id=(p->>'contract_id')::uuid,billing_state=p->>'state',billing_checked_at=v_now WHERE id=c.id RETURNING * INTO c;
  RETURN yc_claim_view(c);
 ELSIF op='retry-email' THEN
  IF p->>'actor_id' IS NULL OR COALESCE(p->>'reason','')='' OR COALESCE(p->>'evidence_reference','')='' THEN RAISE EXCEPTION 'audited retry required' USING ERRCODE='22023'; END IF;
  IF c.state<>'awaiting_confirmation' OR c.token_expires_at<=v_now+interval '5 minutes' THEN RAISE EXCEPTION 'claim requires manual review' USING ERRCODE='22023'; END IF;
  UPDATE yc_claim_mail SET attempts=0,next_attempt_at=v_now WHERE claim_id=c.id AND sent_at IS NULL AND confirmation_token IS NOT NULL AND (lease_until IS NULL OR lease_until<v_now);
  UPDATE yc_claim SET revision=revision+1 WHERE id=c.id RETURNING * INTO c;
  INSERT INTO yc_claim_decision(claim_id,revision,decision,actor_id,reason,evidence_reference) VALUES(c.id,c.revision,op,(p->>'actor_id')::uuid,p->>'reason',p->>'evidence_reference');
  RETURN yc_claim_view(c);
 ELSIF op IN ('prepare','prepare-approve','bind','approve') THEN
  SELECT id,email,email_confirmed_at,created_at,deleted_at INTO u FROM auth.users WHERE id=(p->>'user_id')::uuid FOR SHARE;
  IF NOT FOUND OR u.deleted_at IS NOT NULL OR u.email_confirmed_at IS NULL OR lower(btrim(u.email))<>c.submitted_email THEN
   RAISE EXCEPTION 'verified account mismatch' USING ERRCODE='22023';
  END IF;
  IF c.state IN ('rejected','revoked') THEN RAISE EXCEPTION 'claim requires operator recovery' USING ERRCODE='22023'; END IF;
  IF c.claimed_user_id IS NOT NULL THEN
   IF c.claimed_user_id<>u.id OR c.claimed_team_id<>(p->>'team_id')::uuid OR c.home_region<>p->>'home_region' THEN
    RAISE EXCEPTION 'claim binding conflict' USING ERRCODE='23505';
   END IF;
   RETURN yc_claim_view(c);
  END IF;
  IF c.intent_team_id IS NOT NULL AND (c.intent_user_id IS DISTINCT FROM u.id OR c.intent_team_id IS DISTINCT FROM (p->>'team_id')::uuid OR c.intent_region IS DISTINCT FROM p->>'home_region') THEN
   RAISE EXCEPTION 'claim completion already targets another team' USING ERRCODE='23505';
  END IF;
  IF op IN ('approve','prepare-approve') AND p->>'company_identity' IS NOT NULL THEN c.company_identity:=p->>'company_identity'; END IF;
  IF to_regprocedure('public.read_yc_activation_authority(text,uuid)') IS NOT NULL THEN
   EXECUTE 'SELECT EXISTS(SELECT 1 FROM public.read_yc_activation_authority($1,$2) WHERE company_identity=$1 AND team_id=$2 AND home_region=$3 AND approval_method=''operator'' AND revoked_at IS NULL)' INTO v_prior_operator
    USING c.company_identity,(p->>'team_id')::uuid,p->>'home_region';
  END IF;
  IF op IN ('bind','prepare') THEN
   IF c.state<>'confirmed' OR c.confirmed_at IS NULL OR c.token_hash IS DISTINCT FROM p->>'token_hash' OR c.token_expires_at<=v_now OR
    c.submitted_email<>c.founder_email OR c.lifecycle_changed OR EXISTS(SELECT 1 FROM yc_claim_identity_history WHERE email_hash=encode(sha256(convert_to(c.submitted_email,'UTF8')),'hex')) OR (c.capture_user_id IS NOT NULL AND c.capture_user_id<>u.id) OR u.created_at<c.created_at OR (p->>'team_created_at')::timestamptz<c.created_at OR COALESCE((p->>'team_eligible')::boolean,false) IS NOT TRUE OR c.created_at<v_now-interval '24 hours' THEN
    IF c.state<>'manual_review' THEN
     UPDATE yc_claim SET state='manual_review',reason='manual_account_review_required',revision=revision+1 WHERE id=c.id RETURNING * INTO c;
     INSERT INTO yc_claim_decision(claim_id,revision,decision,actor_id,reason,evidence_reference)
      VALUES(c.id,c.revision,'manual_review',u.id,c.reason,c.verification_reference);
    END IF;
    RETURN yc_claim_view(c);
   END IF;
   v_method:='verified_claim';
  ELSE
   IF COALESCE(p->>'reason','')='' OR COALESCE(p->>'evidence_reference','')='' OR p->>'actor_id' IS NULL THEN
    RAISE EXCEPTION 'audited approval required' USING ERRCODE='22023';
   END IF;
   IF NOT v_prior_operator AND (u.created_at<c.created_at OR (p->>'team_created_at')::timestamptz<c.created_at OR COALESCE((p->>'team_eligible')::boolean,false) IS NOT TRUE) AND COALESCE((p->>'existing_customer_exception')::boolean,false) IS NOT TRUE THEN
    RAISE EXCEPTION 'existing customer exception required' USING ERRCODE='22023';
   END IF;
   v_method:='operator';
  END IF;

  IF COALESCE(c.company_identity,'')='' THEN RAISE EXCEPTION 'company identity required' USING ERRCODE='22023'; END IF;
  IF op IN ('prepare','prepare-approve') THEN
   UPDATE yc_claim SET intent_user_id=u.id,intent_team_id=(p->>'team_id')::uuid,intent_region=p->>'home_region' WHERE id=c.id RETURNING * INTO c;
   RETURN yc_claim_view(c);
  END IF;
  IF c.intent_team_id IS NULL THEN RAISE EXCEPTION 'durable team intent required' USING ERRCODE='22023'; END IF;
  IF COALESCE(c.company_identity,'')='' THEN RAISE EXCEPTION 'company identity required' USING ERRCODE='22023'; END IF;
  -- The billing-owned RPC adopts an existing manual approval or reserves the
  -- same global company/team authority before a claim becomes bound.
  EXECUTE 'SELECT approval_id FROM public.reserve_yc_activation_authority($1,$2,$3,$4,$5,$6,$7)' INTO v_approval
   USING c.company_identity,(p->>'team_id')::uuid,p->>'home_region',
    COALESCE((p->>'actor_id')::uuid,u.id),v_method,COALESCE(p->>'evidence_reference',c.verification_reference),c.id;
  UPDATE yc_claim SET state='bound',reason='activation_pending',company_identity=c.company_identity,
   claimed_user_id=u.id,claimed_team_id=(p->>'team_id')::uuid,home_region=p->>'home_region',claimed_at=v_now,
   approval_id=v_approval,revision=revision+1 WHERE id=c.id RETURNING * INTO c;
  INSERT INTO yc_claim_decision(claim_id,revision,decision,actor_id,reason,evidence_reference)
   VALUES(c.id,c.revision,v_method,COALESCE((p->>'actor_id')::uuid,u.id),COALESCE(p->>'reason','email_match_and_possession'),COALESCE(p->>'evidence_reference',c.verification_reference));
  RETURN yc_claim_view(c);
 ELSIF op IN ('reject','revoke') THEN
  IF c.intent_region IS NOT NULL AND c.intent_region IS DISTINCT FROM p->>'home_region' THEN RAISE EXCEPTION 'use intended home region' USING ERRCODE='22023'; END IF;
  IF p->>'actor_id' IS NULL OR COALESCE(p->>'reason','')='' OR COALESCE(p->>'evidence_reference','')='' THEN RAISE EXCEPTION 'audited decision required' USING ERRCODE='22023'; END IF;
  IF c.state IN ('rejected','revoked') THEN RETURN yc_claim_view(c); END IF;
  IF c.approval_id IS NOT NULL THEN
   EXECUTE 'SELECT approval_id FROM public.revoke_yc_activation_authority($1,$2,$3)' INTO v_approval USING c.approval_id,c.claimed_team_id,(p->>'actor_id')::uuid;
  END IF;
  UPDATE yc_claim SET state=CASE WHEN op='reject' THEN 'rejected' ELSE 'revoked' END,reason=p->>'reason',revision=revision+1 WHERE id=c.id RETURNING * INTO c;
  UPDATE yc_claim_mail SET confirmation_token=NULL WHERE claim_id=c.id;
  INSERT INTO yc_claim_decision(claim_id,revision,decision,actor_id,reason,evidence_reference) VALUES(c.id,c.revision,c.state,(p->>'actor_id')::uuid,p->>'reason',p->>'evidence_reference');
  RETURN yc_claim_view(c);
 END IF;
 RAISE EXCEPTION 'unknown claim operation' USING ERRCODE='22023';
END $$;

CREATE FUNCTION public.yc_claim_auth_lifecycle() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE old_email text; new_email text;
BEGIN
 old_email:=lower(btrim(OLD.email));
 IF TG_OP='UPDATE' THEN
  new_email:=lower(btrim(NEW.email));
  IF old_email IS NOT DISTINCT FROM new_email AND OLD.deleted_at IS NOT DISTINCT FROM NEW.deleted_at THEN RETURN NEW; END IF;
 END IF;
 INSERT INTO public.yc_claim_identity_history(email_hash,prior_user_id)
 SELECT encode(sha256(convert_to(e,'UTF8')),'hex'),OLD.id FROM (SELECT DISTINCT unnest(ARRAY[old_email,new_email]) AS e) q WHERE e IS NOT NULL AND e<>''
 ON CONFLICT(email_hash) DO UPDATE SET prior_user_id=excluded.prior_user_id,changed_at=clock_timestamp();
 -- Do not lock claim rows from an Auth trigger: binding holds an Auth SHARE
 -- lock while it checks this tombstone, avoiding reversed lock acquisition.
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION public.yc_claim_auth_lifecycle() FROM PUBLIC;
CREATE TRIGGER yc_claim_auth_lifecycle AFTER UPDATE OF email,deleted_at OR DELETE ON auth.users
 FOR EACH ROW EXECUTE FUNCTION public.yc_claim_auth_lifecycle();

CREATE FUNCTION public.yc_claim_preserve_evidence() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$ BEGIN
 IF TG_TABLE_NAME='yc_claim_decision' OR TG_OP='DELETE' THEN RAISE EXCEPTION 'claim audit history is immutable'; END IF;
 IF (NEW.id,NEW.verification_reference,NEW.submitted_email,NEW.founder_email,NEW.evidence,NEW.created_at,NEW.verified_at)
 IS DISTINCT FROM (OLD.id,OLD.verification_reference,OLD.submitted_email,OLD.founder_email,OLD.evidence,OLD.created_at,OLD.verified_at)
 THEN RAISE EXCEPTION 'claim evidence is immutable'; END IF;
 IF OLD.claimed_user_id IS NOT NULL AND (NEW.claimed_user_id,NEW.claimed_team_id,NEW.home_region,NEW.claimed_at,NEW.approval_id,NEW.company_identity)
 IS DISTINCT FROM (OLD.claimed_user_id,OLD.claimed_team_id,OLD.home_region,OLD.claimed_at,OLD.approval_id,OLD.company_identity)
 THEN RAISE EXCEPTION 'claim binding is immutable'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER yc_claim_evidence_immutable BEFORE UPDATE OR DELETE ON public.yc_claim FOR EACH ROW EXECUTE FUNCTION public.yc_claim_preserve_evidence();
CREATE TRIGGER yc_claim_decision_immutable BEFORE UPDATE OR DELETE ON public.yc_claim_decision FOR EACH ROW EXECUTE FUNCTION public.yc_claim_preserve_evidence();
REVOKE ALL ON FUNCTION public.yc_claim_preserve_evidence() FROM PUBLIC;

ALTER TABLE public.yc_claim ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.yc_claim_decision ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.yc_claim_mail ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.yc_claim_rate ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.yc_claim_identity_history ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.yc_claim,public.yc_claim_decision,public.yc_claim_mail,public.yc_claim_rate,public.yc_claim_identity_history FROM PUBLIC;
REVOKE ALL ON FUNCTION public.yc_claim_view(public.yc_claim),public.yc_claim_rpc(text,jsonb) FROM PUBLIC;
DO $$ DECLARE r text; BEGIN
 FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role','promotion_evidence_proxy'] LOOP
  IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=r) THEN
   EXECUTE format('REVOKE ALL ON public.yc_claim,public.yc_claim_decision,public.yc_claim_mail,public.yc_claim_rate,public.yc_claim_identity_history FROM %I',r);
   EXECUTE format('REVOKE ALL ON FUNCTION public.yc_claim_view(public.yc_claim),public.yc_claim_rpc(text,jsonb) FROM %I',r);
  END IF;
 END LOOP;
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='promotion_evidence_proxy') THEN GRANT EXECUTE ON FUNCTION public.yc_claim_rpc(text,jsonb) TO promotion_evidence_proxy; END IF;
END $$;
COMMIT;
