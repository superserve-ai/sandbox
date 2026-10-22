-- Shared Auth only. Staff eligibility remains separate from customer acceptance.
BEGIN;
ALTER TABLE public.yc_claim ADD COLUMN acceptance_required boolean NOT NULL DEFAULT false;
CREATE TABLE public.yc_claim_approval_mail (
 claim_id uuid PRIMARY KEY REFERENCES public.yc_claim(id),
 decision_revision bigint NOT NULL,
 message_id uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
 approved_email text NOT NULL,
 approved_user_id uuid NOT NULL,
 approved_team_id uuid NOT NULL,
 home_region text NOT NULL,
 approval_id uuid NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 attempts integer NOT NULL DEFAULT 0,
 next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 lease_id uuid,
 lease_until timestamptz,
 sent_at timestamptz,
 last_error text,
 FOREIGN KEY(claim_id,decision_revision) REFERENCES public.yc_claim_decision(claim_id,revision)
);
CREATE INDEX yc_claim_approval_mail_pending ON public.yc_claim_approval_mail(next_attempt_at) WHERE sent_at IS NULL;
CREATE INDEX yc_claim_approval_mail_backlog ON public.yc_claim_approval_mail(created_at) WHERE sent_at IS NULL;
CREATE TABLE public.yc_staff_claim_request (
 request_id uuid PRIMARY KEY,
 claim_id uuid NOT NULL REFERENCES public.yc_claim(id),
 parameters jsonb NOT NULL,
 decision text NOT NULL,
 decision_revision bigint NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE OR REPLACE FUNCTION public.yc_claim_view(c public.yc_claim) RETURNS jsonb
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
 'acceptance_required',c.acceptance_required,
 'approval_notification', (SELECT jsonb_build_object('revision',m.decision_revision,'sent_at',m.sent_at,'attempts',m.attempts,
 'status',CASE WHEN c.state<>'bound' OR NOT EXISTS(SELECT 1 FROM public.read_yc_activation_authority(c.company_identity,c.claimed_team_id) a WHERE a.approval_id=m.approval_id AND a.revoked_at IS NULL) THEN 'cancelled'
 WHEN m.sent_at IS NOT NULL THEN 'sent'
 WHEN NOT EXISTS(SELECT 1 FROM auth.users u WHERE u.id=m.approved_user_id AND u.deleted_at IS NULL AND u.email_confirmed_at IS NOT NULL AND lower(btrim(u.email))=m.approved_email) THEN 'recipient_unavailable'
 WHEN m.last_error='delivery_unknown' AND (m.lease_until IS NULL OR m.lease_until<=clock_timestamp()) THEN 'delivery_unknown'
 WHEN m.attempts>=8 OR m.last_error='delivery_rejected' THEN 'delivery_failed' ELSE 'pending' END) FROM yc_claim_approval_mail m WHERE m.claim_id=c.id),
 'revision',c.revision,'created_at',c.created_at)
$$;

-- Authority is the dispatch serialization point. Reservation takes its exclusive
-- lock before eligibility becomes visible; dispatch holds a shared lock through
-- provider work. Claim checks never acquire a claim lock from the dispatch path:
-- admission already holds regional billing locks while preparing a claim.
CREATE OR REPLACE FUNCTION public.reserve_yc_activation_authority(p_company text,p_team uuid,p_region text,p_actor uuid,p_method text,p_evidence text,p_claim uuid DEFAULT NULL)
RETURNS public.yc_company_activation_authority
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE a public.yc_company_activation_authority;
BEGIN
 IF p_method='verified_claim' AND p_claim IS NULL THEN RAISE EXCEPTION 'verified claim identity required'; END IF;
 INSERT INTO public.yc_company_activation_authority(company_identity,team_id,home_region,approved_by,approval_method,evidence_reference,claim_id)
 VALUES(p_company,p_team,p_region,p_actor,p_method,p_evidence,p_claim) ON CONFLICT(company_identity) DO NOTHING;
 SELECT * INTO STRICT a FROM public.yc_company_activation_authority WHERE company_identity=p_company FOR UPDATE;
 IF a.team_id<>p_team OR a.home_region<>p_region OR a.revoked_at IS NOT NULL THEN RAISE EXCEPTION 'company approval belongs to another team, region, or is revoked'; END IF;
 IF EXISTS(SELECT 1 FROM yc_claim WHERE acceptance_required AND
  (claimed_team_id=p_team OR intent_team_id=p_team OR company_identity=p_company)) THEN
  RAISE EXCEPTION 'YC offer requires customer acceptance' USING ERRCODE='22023'; END IF;
 RETURN a;
END $$;
CREATE OR REPLACE FUNCTION public.lock_yc_activation_authority(p_approval uuid,p_team uuid,p_region text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE a public.yc_company_activation_authority;
BEGIN
 SELECT * INTO a FROM public.yc_company_activation_authority WHERE approval_id=p_approval AND team_id=p_team AND home_region=p_region FOR SHARE;
 IF NOT FOUND OR a.revoked_at IS NOT NULL THEN RETURN false; END IF;
 RETURN NOT EXISTS(SELECT 1 FROM yc_claim WHERE acceptance_required AND
  (claimed_team_id=p_team OR intent_team_id=p_team OR company_identity=a.company_identity));
END $$;

CREATE FUNCTION public.yc_staff_claim_rpc(op text,p jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $$
DECLARE c public.yc_claim; prior public.yc_staff_claim_request; result jsonb; canonical jsonb;
 action text:=CASE WHEN op='prepare-approve' THEN 'approve' ELSE op END;
BEGIN
 IF p IS NULL OR jsonb_typeof(p)<>'object' THEN RAISE EXCEPTION 'invalid request' USING ERRCODE='22023'; END IF;
 IF op='activation-allowed' THEN
  -- Read-only preflight; the shared authority RPC enforces dispatch atomically.
  RETURN jsonb_build_object('allowed',NOT EXISTS(SELECT 1 FROM yc_claim WHERE
   (claimed_team_id=(p->>'team_id')::uuid OR intent_team_id=(p->>'team_id')::uuid) AND acceptance_required));
 ELSIF op='activation-pending' THEN
  RETURN jsonb_build_object('claims',COALESCE((SELECT jsonb_agg(yc_claim_view(q)) FROM
   (SELECT * FROM yc_claim WHERE state='bound' AND NOT acceptance_required
    AND id>COALESCE((p->>'after_id')::uuid,'00000000-0000-0000-0000-000000000000'::uuid) ORDER BY id LIMIT 100) q),'[]'::jsonb));
 ELSIF op='list' THEN
  IF COALESCE(p->>'state','') NOT IN ('manual_review','awaiting_confirmation','confirmed','bound','rejected','revoked') THEN RAISE EXCEPTION 'invalid state' USING ERRCODE='22023'; END IF;
  RETURN jsonb_build_object('claims',COALESCE((SELECT jsonb_agg(yc_claim_view(q)) FROM
   (SELECT * FROM yc_claim WHERE state=p->>'state' AND id>COALESCE((p->>'after_id')::uuid,'00000000-0000-0000-0000-000000000000'::uuid) ORDER BY id LIMIT 100) q),'[]'::jsonb));
 END IF;
 IF action NOT IN ('approve','reject','revoke','retry-approval-email') OR p->>'request_id' IS NULL OR p->>'actor_id' IS NULL OR p->>'expected_revision' IS NULL
  OR btrim(COALESCE(p->>'reason',''))='' OR btrim(COALESCE(p->>'evidence_reference',''))='' THEN RAISE EXCEPTION 'audited decision required' USING ERRCODE='22023'; END IF;
 SELECT * INTO c FROM yc_claim WHERE id=(p->>'id')::uuid FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'claim unavailable' USING ERRCODE='P0002'; END IF;
 canonical:=p-ARRAY['team_created_at','team_eligible'];
 SELECT * INTO prior FROM yc_staff_claim_request WHERE request_id=(p->>'request_id')::uuid;
 IF FOUND THEN
  IF prior.claim_id<>c.id OR prior.parameters<>canonical OR prior.decision<>action THEN RAISE EXCEPTION 'request identity changed' USING ERRCODE='23505'; END IF;
  RETURN yc_claim_view(c);
 END IF;
 IF c.revision<>(p->>'expected_revision')::bigint THEN RAISE EXCEPTION 'claim revision changed' USING ERRCODE='23505'; END IF;
 IF c.intent_region IS NOT NULL AND c.intent_region IS DISTINCT FROM p->>'home_region' THEN RAISE EXCEPTION 'use intended home region' USING ERRCODE='22023'; END IF;
 IF action='approve' THEN
  -- This route cannot invoke the legacy existing-customer exception, including
  -- adoption of a prior operator authority. Historical recovery stays manual.
  IF c.state IN ('bound','rejected','revoked') OR COALESCE((p->>'team_eligible')::boolean,false) IS NOT TRUE OR
   (p->>'team_created_at')::timestamptz<c.created_at OR NOT EXISTS(SELECT 1 FROM auth.users WHERE id=(p->>'user_id')::uuid AND created_at>=c.created_at) THEN
   RAISE EXCEPTION 'new signup required' USING ERRCODE='22023'; END IF;
  IF op='prepare-approve' THEN RETURN yc_claim_rpc(op,p-'existing_customer_exception'); END IF;
  IF EXISTS(SELECT 1 FROM public.read_yc_activation_authority(COALESCE(p->>'company_identity',c.company_identity),(p->>'team_id')::uuid)) THEN
   RAISE EXCEPTION 'existing authority requires manual recovery' USING ERRCODE='22023'; END IF;
  result:=yc_claim_rpc('approve',p-'existing_customer_exception');
  SELECT * INTO STRICT c FROM yc_claim WHERE id=c.id;
  -- A concurrent manual reservation must not be converted to staff approval.
  IF NOT EXISTS(SELECT 1 FROM public.read_yc_activation_authority(c.company_identity,c.claimed_team_id) a WHERE a.approval_id=c.approval_id AND a.claim_id=c.id) THEN
   RAISE EXCEPTION 'existing authority requires manual recovery' USING ERRCODE='22023'; END IF;
  UPDATE yc_claim SET acceptance_required=true WHERE id=c.id RETURNING * INTO c;
  INSERT INTO yc_claim_approval_mail(claim_id,decision_revision,approved_email,approved_user_id,approved_team_id,home_region,approval_id)
   VALUES(c.id,c.revision,c.submitted_email,c.claimed_user_id,c.claimed_team_id,c.home_region,c.approval_id);
 ELSIF action='retry-approval-email' THEN
  IF c.state<>'bound' OR NOT c.acceptance_required THEN RAISE EXCEPTION 'approval unavailable' USING ERRCODE='22023'; END IF;
  UPDATE yc_claim_approval_mail SET attempts=0,next_attempt_at=clock_timestamp(),last_error=NULL
   WHERE claim_id=c.id AND sent_at IS NULL AND (lease_until IS NULL OR lease_until<clock_timestamp());
  IF NOT FOUND THEN RAISE EXCEPTION 'notification cannot retry' USING ERRCODE='22023'; END IF;
  UPDATE yc_claim SET revision=revision+1 WHERE id=c.id RETURNING * INTO c;
  INSERT INTO yc_claim_decision(claim_id,revision,decision,actor_id,reason,evidence_reference)
   VALUES(c.id,c.revision,action,(p->>'actor_id')::uuid,p->>'reason',p->>'evidence_reference');
 ELSE
  result:=yc_claim_rpc(action,p);
  SELECT * INTO STRICT c FROM yc_claim WHERE id=c.id;
 END IF;
 INSERT INTO yc_staff_claim_request(request_id,claim_id,parameters,decision,decision_revision)
 VALUES((p->>'request_id')::uuid,c.id,canonical,action,c.revision);
 RETURN yc_claim_view(c);
END $$;

CREATE FUNCTION public.yc_claim_approval_mail_rpc(op text,p jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $$
DECLARE m public.yc_claim_approval_mail; v_now timestamptz:=clock_timestamp();
BEGIN
 IF op='backlog' THEN
  RETURN (SELECT jsonb_build_object('count',count(*),'oldest_seconds',COALESCE(max(extract(epoch FROM v_now-q.created_at)),0))
   FROM yc_claim_approval_mail q JOIN yc_claim c ON c.id=q.claim_id
   WHERE q.sent_at IS NULL AND q.created_at<v_now-interval '30 minutes' AND c.state='bound'
    AND EXISTS(SELECT 1 FROM public.read_yc_activation_authority(c.company_identity,c.claimed_team_id) a WHERE a.approval_id=q.approval_id AND a.revoked_at IS NULL));
 ELSIF op='lease' THEN
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
 ELSIF op='finish' THEN
  UPDATE yc_claim_approval_mail SET sent_at=CASE WHEN (p->>'success')::boolean THEN v_now ELSE NULL END,
   last_error=CASE WHEN (p->>'success')::boolean THEN NULL WHEN COALESCE((p->>'unknown')::boolean,false) THEN 'delivery_unknown' WHEN COALESCE((p->>'rejected')::boolean,false) THEN 'delivery_rejected' ELSE 'delivery_failed' END,
   next_attempt_at=v_now+interval '1 minute'*LEAST(60,power(2,attempts)::integer),lease_id=NULL,lease_until=NULL
   WHERE claim_id=(p->>'id')::uuid AND message_id=(p->>'message_id')::uuid AND lease_id=(p->>'lease_id')::uuid AND lease_until>v_now;
  RETURN '{}'::jsonb;
 END IF;
 RAISE EXCEPTION 'unknown mail operation' USING ERRCODE='22023';
END $$;
ALTER TABLE public.yc_claim_approval_mail ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.yc_staff_claim_request ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.yc_claim_approval_mail,public.yc_staff_claim_request FROM PUBLIC;
REVOKE ALL ON FUNCTION public.yc_staff_claim_rpc(text,jsonb),public.yc_claim_approval_mail_rpc(text,jsonb) FROM PUBLIC;
DO $$ DECLARE r text; BEGIN
 FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role','promotion_evidence_proxy'] LOOP
  IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=r) THEN
   EXECUTE format('REVOKE ALL ON public.yc_claim_approval_mail,public.yc_staff_claim_request FROM %I',r);
   EXECUTE format('REVOKE ALL ON FUNCTION public.yc_staff_claim_rpc(text,jsonb),public.yc_claim_approval_mail_rpc(text,jsonb) FROM %I',r);
  END IF;
 END LOOP;
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='promotion_evidence_proxy') THEN
  GRANT EXECUTE ON FUNCTION public.yc_staff_claim_rpc(text,jsonb),public.yc_claim_approval_mail_rpc(text,jsonb) TO promotion_evidence_proxy;
 END IF;
END $$;
COMMIT;
