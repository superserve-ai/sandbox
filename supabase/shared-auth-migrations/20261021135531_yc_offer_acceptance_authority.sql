-- Shared Auth only. Acceptance is separate from approval and provider execution.
BEGIN;
-- These reachable predecessors otherwise let session temporary tables replace
-- the claim, acceptance fence, audit view or approval outbox. Preserve bodies/ACLs.
ALTER FUNCTION public.yc_claim_rpc(text,jsonb) SET search_path=pg_catalog,public,auth,pg_temp;
ALTER FUNCTION public.yc_staff_claim_rpc(text,jsonb) SET search_path=pg_catalog,public,auth,pg_temp;
ALTER FUNCTION public.yc_claim_approval_mail_rpc(text,jsonb) SET search_path=pg_catalog,public,auth,pg_temp;
ALTER FUNCTION public.yc_claim_view(public.yc_claim) SET search_path=pg_catalog,public,pg_temp;
ALTER FUNCTION public.reserve_yc_activation_authority(text,uuid,text,uuid,text,text,uuid) SET search_path=pg_catalog,public,pg_temp;
ALTER FUNCTION public.lock_yc_activation_authority(uuid,uuid,text) SET search_path=pg_catalog,public,pg_temp;

CREATE TABLE public.yc_preferred_identity_review (
 request_id uuid PRIMARY KEY,
 claim_id uuid NOT NULL UNIQUE REFERENCES public.yc_claim(id),
 revision bigint NOT NULL,
 user_id uuid NOT NULL,
 email text NOT NULL,
 team_id uuid NOT NULL UNIQUE,
 home_region text NOT NULL,
 company_identity text NOT NULL,
 verification_reference text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 ready boolean NOT NULL DEFAULT false,
 approved_revision bigint,
 FOREIGN KEY(claim_id,revision) REFERENCES public.yc_claim_decision(claim_id,revision),
 FOREIGN KEY(claim_id,approved_revision) REFERENCES public.yc_claim_decision(claim_id,revision)
);

CREATE FUNCTION public.yc_preferred_identity_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$ BEGIN
 IF TG_OP='DELETE' OR (to_jsonb(NEW)-ARRAY['ready','approved_revision']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['ready','approved_revision'])
 OR (OLD.ready AND NOT NEW.ready) OR (OLD.approved_revision IS NOT NULL AND NEW.approved_revision IS DISTINCT FROM OLD.approved_revision) THEN
  RAISE EXCEPTION 'preferred identity evidence is immutable';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER yc_preferred_identity_immutable BEFORE UPDATE OR DELETE ON public.yc_preferred_identity_review
 FOR EACH ROW EXECUTE FUNCTION public.yc_preferred_identity_immutable();

CREATE FUNCTION public.yc_preferred_claim_view(c public.yc_claim) RETURNS jsonb
LANGUAGE sql STABLE SET search_path=pg_catalog,public,pg_temp AS $$
 SELECT public.yc_claim_view(c)||jsonb_build_object('preferred_identity_review',
  (SELECT jsonb_build_object('review_request_id',r.request_id,'review_revision',r.revision,'user_id',r.user_id,
   'email',r.email,'team_id',r.team_id,'home_region',r.home_region,'company_identity',r.company_identity,
   'ready',r.ready,'approved_revision',r.approved_revision) FROM public.yc_preferred_identity_review r WHERE r.claim_id=c.id))
$$;

CREATE FUNCTION public.yc_preferred_claim_rpc(op text,p jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,auth,pg_temp AS $$
DECLARE c public.yc_claim; r public.yc_preferred_identity_review; u record;
BEGIN
 IF p IS NULL OR jsonb_typeof(p)<>'object' OR op IS NULL OR op NOT IN ('lookup','prepare','review') THEN
  RAISE EXCEPTION 'invalid preferred identity request' USING ERRCODE='22023';
 END IF;
 IF op='lookup' THEN
  SELECT * INTO u FROM auth.users WHERE id=(p->>'user_id')::uuid;
  IF NOT FOUND OR u.deleted_at IS NOT NULL OR u.email_confirmed_at IS NULL THEN RETURN '{"claims":[]}'::jsonb; END IF;
  RETURN jsonb_build_object('claims',COALESCE((SELECT jsonb_agg(public.yc_preferred_claim_view(q)) FROM
   (SELECT qc.* FROM public.yc_claim qc WHERE
    (qc.submitted_email=lower(btrim(u.email)) AND (qc.claimed_user_id IS NULL OR qc.claimed_user_id=u.id) AND
     NOT EXISTS(SELECT 1 FROM public.yc_preferred_identity_review qr WHERE qr.claim_id=qc.id AND qr.user_id<>u.id))
    OR EXISTS(SELECT 1 FROM public.yc_preferred_identity_review qr WHERE qr.claim_id=qc.id AND qr.user_id=u.id AND qr.email=lower(btrim(u.email))
     AND (qr.approved_revision IS NOT NULL OR NOT EXISTS(SELECT 1 FROM public.yc_claim_identity_history WHERE email_hash=encode(sha256(convert_to(qr.email,'UTF8')),'hex'))))
    ORDER BY qc.created_at DESC LIMIT 20) q),'[]'::jsonb));
 END IF;
 SELECT * INTO c FROM public.yc_claim WHERE id=(p->>'id')::uuid FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'claim unavailable' USING ERRCODE='P0002'; END IF;
 SELECT * INTO u FROM auth.users WHERE id=(p->>'user_id')::uuid FOR SHARE;
 IF NOT FOUND OR u.deleted_at IS NOT NULL OR u.email_confirmed_at IS NULL OR u.created_at<c.created_at
 OR c.lifecycle_changed OR c.state IN ('bound','rejected','revoked') OR c.claimed_user_id IS NOT NULL
 OR (p->>'team_created_at')::timestamptz IS NULL OR (p->>'team_created_at')::timestamptz<c.created_at
 OR COALESCE((p->>'team_eligible')::boolean,false) IS NOT TRUE
 OR p->>'verification_reference' IS DISTINCT FROM c.verification_reference
 OR p->>'company_identity' IS DISTINCT FROM c.company_identity OR COALESCE(c.company_identity,'')=''
 OR EXISTS(SELECT 1 FROM public.yc_claim_identity_history WHERE email_hash IN
  (encode(sha256(convert_to(lower(btrim(u.email)),'UTF8')),'hex'),encode(sha256(convert_to(c.submitted_email,'UTF8')),'hex')))
 OR EXISTS(SELECT 1 FROM public.yc_company_activation_authority WHERE company_identity=c.company_identity OR team_id=(p->>'team_id')::uuid) THEN
  RAISE EXCEPTION 'preferred account requires review' USING ERRCODE='22023';
 END IF;
 IF c.intent_team_id IS NOT NULL AND (c.intent_user_id IS DISTINCT FROM u.id OR c.intent_team_id IS DISTINCT FROM (p->>'team_id')::uuid OR c.intent_region IS DISTINCT FROM p->>'home_region') THEN
  RAISE EXCEPTION 'claim intent conflict' USING ERRCODE='23505';
 END IF;
 SELECT * INTO r FROM public.yc_preferred_identity_review WHERE claim_id=c.id;
 IF NOT FOUND THEN
  IF op<>'prepare' THEN RAISE EXCEPTION 'review preparation required' USING ERRCODE='22023'; END IF;
  UPDATE public.yc_claim SET state='manual_review',reason='preferred_identity_review',revision=revision+1,
   intent_user_id=u.id,intent_team_id=(p->>'team_id')::uuid,intent_region=p->>'home_region' WHERE id=c.id RETURNING * INTO c;
  INSERT INTO public.yc_claim_decision(claim_id,revision,decision,actor_id,reason,evidence_reference)
   VALUES(c.id,c.revision,'manual_review',u.id,'preferred_identity_review',c.verification_reference);
  INSERT INTO public.yc_preferred_identity_review(request_id,claim_id,revision,user_id,email,team_id,home_region,company_identity,verification_reference)
   VALUES((p->>'request_id')::uuid,c.id,c.revision,u.id,lower(btrim(u.email)),(p->>'team_id')::uuid,p->>'home_region',c.company_identity,c.verification_reference)
   RETURNING * INTO r;
 END IF;
 IF r.request_id IS DISTINCT FROM (p->>'request_id')::uuid OR r.user_id<>u.id OR r.email<>lower(btrim(u.email))
 OR r.team_id IS DISTINCT FROM (p->>'team_id')::uuid OR r.home_region IS DISTINCT FROM p->>'home_region' THEN
  RAISE EXCEPTION 'review identity changed' USING ERRCODE='23505';
 END IF;
 IF op='review' THEN UPDATE public.yc_preferred_identity_review SET ready=true WHERE request_id=r.request_id; END IF;
 RETURN jsonb_build_object('id',c.id,'claim_id',c.id,'state',CASE WHEN op='prepare' THEN 'review_prepared' ELSE 'review_required' END,
  'team_id',r.team_id,'home_region',r.home_region,'review_request_id',r.request_id,'review_revision',r.revision);
END $$;

CREATE FUNCTION public.yc_preferred_staff_rpc(op text,p jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,auth,pg_temp AS $$
DECLARE c public.yc_claim; r public.yc_preferred_identity_review; u record; prior public.yc_staff_claim_request;
 canonical jsonb; approval uuid; result jsonb;
BEGIN
 IF op='list' THEN
  result:=public.yc_staff_claim_rpc(op,p);
  RETURN jsonb_build_object('claims',COALESCE((SELECT jsonb_agg(public.yc_preferred_claim_view(qc)) FROM jsonb_array_elements(result->'claims') j
   JOIN public.yc_claim qc ON qc.id=(j->>'id')::uuid),'[]'::jsonb));
 ELSIF op='operator-get' THEN
  SELECT * INTO c FROM public.yc_claim WHERE id=(p->>'id')::uuid;
  IF NOT FOUND THEN RAISE EXCEPTION 'claim unavailable' USING ERRCODE='P0002'; END IF;
  RETURN public.yc_claim_rpc(op,p)||public.yc_preferred_claim_view(c);
 ELSIF p->>'review_request_id' IS NULL THEN
  IF op IN ('approve','prepare-approve') AND EXISTS(SELECT 1 FROM public.yc_preferred_identity_review WHERE claim_id=(p->>'id')::uuid) THEN
   RAISE EXCEPTION 'exact preferred review decision required' USING ERRCODE='22023';
  END IF;
  result:=public.yc_staff_claim_rpc(op,p);
  IF result ? 'id' THEN
   SELECT * INTO c FROM public.yc_claim WHERE id=(result->>'id')::uuid;
   RETURN result||public.yc_preferred_claim_view(c);
  END IF;
  RETURN result;
 END IF;
 IF op NOT IN ('prepare-approve','approve') OR p->>'actor_id' IS NULL OR p->>'request_id' IS NULL OR p->>'expected_revision' IS NULL
 OR btrim(COALESCE(p->>'reason',''))='' OR btrim(COALESCE(p->>'evidence_reference',''))='' THEN
  RAISE EXCEPTION 'audited preferred review decision required' USING ERRCODE='22023';
 END IF;
 SELECT * INTO c FROM public.yc_claim WHERE id=(p->>'id')::uuid FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'claim unavailable' USING ERRCODE='P0002'; END IF;
 canonical:=p-ARRAY['team_created_at','team_eligible'];
 SELECT * INTO prior FROM public.yc_staff_claim_request WHERE request_id=(p->>'request_id')::uuid;
 IF FOUND THEN
  IF prior.claim_id<>c.id OR prior.parameters<>canonical OR prior.decision<>'approve' THEN RAISE EXCEPTION 'decision identity changed' USING ERRCODE='23505'; END IF;
  RETURN public.yc_preferred_claim_view(c);
 END IF;
 SELECT * INTO r FROM public.yc_preferred_identity_review WHERE claim_id=c.id;
 IF NOT FOUND OR NOT r.ready OR r.request_id IS DISTINCT FROM (p->>'review_request_id')::uuid OR r.revision IS DISTINCT FROM (p->>'review_revision')::bigint
 OR r.user_id IS DISTINCT FROM (p->>'user_id')::uuid OR r.team_id IS DISTINCT FROM (p->>'team_id')::uuid
 OR r.home_region IS DISTINCT FROM p->>'home_region' OR r.approved_revision IS NOT NULL OR c.revision IS DISTINCT FROM (p->>'expected_revision')::bigint
 OR c.state<>'manual_review' OR c.lifecycle_changed OR c.intent_user_id IS DISTINCT FROM r.user_id
 OR c.intent_team_id IS DISTINCT FROM r.team_id OR c.intent_region IS DISTINCT FROM r.home_region
 OR c.company_identity IS DISTINCT FROM r.company_identity OR (p->>'company_identity' IS NOT NULL AND p->>'company_identity'<>r.company_identity)
 OR COALESCE((p->>'team_eligible')::boolean,false) IS NOT TRUE OR (p->>'team_created_at')::timestamptz IS NULL
 OR (p->>'team_created_at')::timestamptz<c.created_at THEN
  RAISE EXCEPTION 'preferred review changed' USING ERRCODE='23505';
 END IF;
 SELECT * INTO u FROM auth.users WHERE id=r.user_id FOR SHARE;
 IF NOT FOUND OR u.deleted_at IS NOT NULL OR u.email_confirmed_at IS NULL OR lower(btrim(u.email))<>r.email OR u.created_at<c.created_at
 OR EXISTS(SELECT 1 FROM public.yc_claim_identity_history WHERE email_hash IN
  (encode(sha256(convert_to(r.email,'UTF8')),'hex'),encode(sha256(convert_to(c.submitted_email,'UTF8')),'hex'))) THEN
  RAISE EXCEPTION 'preferred account changed' USING ERRCODE='22023';
 END IF;
 IF op='prepare-approve' THEN RETURN public.yc_preferred_claim_view(c); END IF;
 IF EXISTS(SELECT 1 FROM public.yc_company_activation_authority WHERE company_identity=r.company_identity OR team_id=r.team_id) THEN
  RAISE EXCEPTION 'existing authority requires review' USING ERRCODE='23505';
 END IF;
 SELECT approval_id INTO approval FROM public.reserve_yc_activation_authority(r.company_identity,r.team_id,r.home_region,(p->>'actor_id')::uuid,'operator',p->>'evidence_reference',c.id);
 UPDATE public.yc_claim SET state='bound',reason='activation_pending',claimed_user_id=r.user_id,claimed_team_id=r.team_id,
  home_region=r.home_region,claimed_at=clock_timestamp(),approval_id=approval,acceptance_required=true,revision=revision+1
  WHERE id=c.id RETURNING * INTO c;
 INSERT INTO public.yc_claim_decision(claim_id,revision,decision,actor_id,reason,evidence_reference)
  VALUES(c.id,c.revision,'operator',(p->>'actor_id')::uuid,p->>'reason',p->>'evidence_reference');
 UPDATE public.yc_preferred_identity_review SET approved_revision=c.revision WHERE request_id=r.request_id;
 INSERT INTO public.yc_claim_approval_mail(claim_id,decision_revision,approved_email,approved_user_id,approved_team_id,home_region,approval_id)
  VALUES(c.id,c.revision,r.email,r.user_id,r.team_id,r.home_region,approval);
 INSERT INTO public.yc_staff_claim_request(request_id,claim_id,parameters,decision,decision_revision)
  VALUES((p->>'request_id')::uuid,c.id,canonical,'approve',c.revision);
 RETURN public.yc_preferred_claim_view(c);
END $$;

CREATE TABLE public.yc_offer_acceptance_authority (
 acceptance_id uuid PRIMARY KEY,
 claim_id uuid NOT NULL UNIQUE REFERENCES public.yc_claim(id),
 team_id uuid NOT NULL UNIQUE,
 user_id uuid NOT NULL,
 company_identity text NOT NULL UNIQUE,
 home_region text NOT NULL,
 approval_id uuid NOT NULL UNIQUE,
 approval_revision bigint NOT NULL,
 offer_key text NOT NULL,
 offer_version integer NOT NULL CHECK (offer_version>0),
 terms_digest text NOT NULL CHECK (terms_digest ~ '^[a-f0-9]{64}$'),
 renewal_terms_digest text NOT NULL CHECK (renewal_terms_digest ~ '^[a-f0-9]{64}$'),
 request_id uuid NOT NULL UNIQUE,
 accepted_at timestamptz NOT NULL,
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 assignment_id uuid UNIQUE,
 FOREIGN KEY(claim_id,approval_revision) REFERENCES public.yc_claim_decision(claim_id,revision)
);

CREATE FUNCTION public.yc_offer_acceptance_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$ BEGIN
 IF TG_OP='DELETE' OR (to_jsonb(NEW)-'assignment_id') IS DISTINCT FROM (to_jsonb(OLD)-'assignment_id')
 OR OLD.assignment_id IS NOT NULL OR NEW.assignment_id IS NULL THEN
  RAISE EXCEPTION 'acceptance history is immutable';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER yc_offer_acceptance_immutable BEFORE UPDATE OR DELETE ON public.yc_offer_acceptance_authority
 FOR EACH ROW EXECUTE FUNCTION public.yc_offer_acceptance_immutable();

-- Dispatch never locks a claim. Revocation takes claim then authority; Auth
-- lifecycle takes only the user and its history, so user then authority is safe.
CREATE FUNCTION public.yc_offer_acceptance_rpc(op text,p jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,auth,pg_temp AS $$
DECLARE c public.yc_claim; a public.yc_company_activation_authority;
 r public.yc_offer_acceptance_authority; wanted public.yc_offer_acceptance_authority; u record; revision bigint; approved_email text; preferred_identity boolean;
BEGIN
 IF p IS NULL OR jsonb_typeof(p)<>'object' OR op IS NULL OR op NOT IN ('offer','accept','admit','guard','link') THEN
  RAISE EXCEPTION 'invalid acceptance request' USING ERRCODE='22023';
 END IF;
 SELECT * INTO c FROM public.yc_claim WHERE id=(p->>'claim_id')::uuid;
 IF NOT FOUND THEN RAISE EXCEPTION 'claim unavailable' USING ERRCODE='P0002'; END IF;
 SELECT email INTO approved_email FROM public.yc_preferred_identity_review WHERE claim_id=c.id AND user_id=c.claimed_user_id
  AND team_id=c.claimed_team_id AND ready AND approved_revision IS NOT NULL;
 preferred_identity:=FOUND;
 approved_email:=COALESCE(approved_email,c.submitted_email);
 SELECT * INTO u FROM auth.users WHERE id=(p->>'user_id')::uuid FOR SHARE;
 IF NOT FOUND OR u.deleted_at IS NOT NULL OR u.email_confirmed_at IS NULL OR u.created_at<c.created_at
 OR lower(btrim(u.email)) IS DISTINCT FROM approved_email OR c.lifecycle_changed
 -- Explicit staff approval makes the preferred identity authoritative. Original
 -- submission history remains evidence, not a fence on an unrelated later account.
 OR EXISTS(SELECT 1 FROM public.yc_claim_identity_history WHERE
  email_hash=encode(sha256(convert_to(approved_email,'UTF8')),'hex') OR
  (NOT preferred_identity AND email_hash=encode(sha256(convert_to(c.submitted_email,'UTF8')),'hex'))) THEN
  RAISE EXCEPTION 'account requires review' USING ERRCODE='22023';
 END IF;
 SELECT * INTO a FROM public.yc_company_activation_authority WHERE company_identity=c.company_identity FOR SHARE;
 IF NOT FOUND OR a.revoked_at IS NOT NULL THEN RAISE EXCEPTION 'approval unavailable' USING ERRCODE='22023'; END IF;
 -- Read again after the serialization point, including a revoke that committed
 -- while the authority lock was being acquired. Notification revisions differ.
 SELECT * INTO STRICT c FROM public.yc_claim WHERE id=c.id;
 SELECT d.revision INTO revision FROM public.yc_claim_decision d WHERE d.claim_id=c.id
  AND d.decision IN ('operator','verified_claim') ORDER BY d.revision DESC LIMIT 1;
 IF c.state<>'bound' OR c.lifecycle_changed OR c.claimed_user_id IS DISTINCT FROM u.id OR c.claimed_team_id IS DISTINCT FROM (p->>'team_id')::uuid
 OR c.home_region IS DISTINCT FROM p->>'home_region' OR a.team_id IS DISTINCT FROM c.claimed_team_id
 OR a.home_region IS DISTINCT FROM c.home_region OR a.approval_id IS DISTINCT FROM c.approval_id
 OR a.claim_id IS DISTINCT FROM c.id OR revision IS NULL THEN
  RAISE EXCEPTION 'claim binding requires review' USING ERRCODE='22023';
 END IF;
 IF op='offer' THEN
  RETURN jsonb_build_object('claim_id',c.id,'user_id',u.id,'team_id',c.claimed_team_id,'home_region',c.home_region,
   'company_identity',c.company_identity,'approval_id',a.approval_id,'approval_revision',revision,
   'offer_key',a.offer_key,'offer_version',a.offer_version,'claim_created_at',c.created_at);
 END IF;
 IF (p->>'approval_id')::uuid IS DISTINCT FROM a.approval_id OR (p->>'approval_revision')::bigint IS DISTINCT FROM revision
 OR p->>'company_identity' IS DISTINCT FROM a.company_identity OR p->>'offer_key' IS DISTINCT FROM a.offer_key
 OR (p->>'offer_version')::integer IS DISTINCT FROM a.offer_version THEN
  RAISE EXCEPTION 'accepted authority changed' USING ERRCODE='23505';
 END IF;
 wanted:=jsonb_populate_record(NULL::public.yc_offer_acceptance_authority,p);
 IF op='accept' THEN
  IF (p->>'accepted_at')::timestamptz IS NULL OR (p->>'accepted_at')::timestamptz>clock_timestamp()+interval '1 minute'
   OR (p->>'accepted_at')::timestamptz<c.claimed_at THEN RAISE EXCEPTION 'invalid acceptance time' USING ERRCODE='22023'; END IF;
  INSERT INTO public.yc_offer_acceptance_authority(acceptance_id,claim_id,team_id,user_id,company_identity,home_region,approval_id,approval_revision,offer_key,offer_version,terms_digest,renewal_terms_digest,request_id,accepted_at)
  VALUES((p->>'acceptance_id')::uuid,c.id,c.claimed_team_id,u.id,c.company_identity,c.home_region,a.approval_id,revision,a.offer_key,a.offer_version,p->>'terms_digest',p->>'renewal_terms_digest',(p->>'request_id')::uuid,(p->>'accepted_at')::timestamptz)
  ON CONFLICT DO NOTHING;
 END IF;
 SELECT * INTO r FROM public.yc_offer_acceptance_authority WHERE acceptance_id=(p->>'acceptance_id')::uuid;
 IF NOT FOUND OR (to_jsonb(r)-ARRAY['recorded_at','assignment_id']) IS DISTINCT FROM (to_jsonb(wanted)-ARRAY['recorded_at','assignment_id']) THEN
  RAISE EXCEPTION 'acceptance identity changed' USING ERRCODE='23505';
 END IF;
 IF op='link' THEN
  IF p->>'assignment_id' IS NULL THEN RAISE EXCEPTION 'assignment required' USING ERRCODE='22023'; END IF;
  UPDATE public.yc_offer_acceptance_authority SET assignment_id=(p->>'assignment_id')::uuid
   WHERE acceptance_id=r.acceptance_id AND assignment_id IS NULL;
  SELECT * INTO STRICT r FROM public.yc_offer_acceptance_authority WHERE acceptance_id=r.acceptance_id;
 END IF;
 IF op IN ('guard','link') AND r.assignment_id IS DISTINCT FROM (p->>'assignment_id')::uuid THEN
  RAISE EXCEPTION 'assignment identity changed' USING ERRCODE='23505';
 END IF;
 RETURN to_jsonb(r);
END $$;

ALTER TABLE public.yc_offer_acceptance_authority ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.yc_preferred_identity_review ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.yc_offer_acceptance_authority,public.yc_preferred_identity_review FROM PUBLIC;
REVOKE ALL ON FUNCTION public.yc_offer_acceptance_immutable(),public.yc_offer_acceptance_rpc(text,jsonb),public.yc_preferred_identity_immutable(),public.yc_preferred_claim_view(public.yc_claim),public.yc_preferred_claim_rpc(text,jsonb),public.yc_preferred_staff_rpc(text,jsonb) FROM PUBLIC;
DO $$ DECLARE role_name text; BEGIN
 FOREACH role_name IN ARRAY ARRAY['anon','authenticated','service_role','promotion_evidence_proxy'] LOOP
  IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=role_name) THEN
   EXECUTE format('REVOKE ALL ON public.yc_offer_acceptance_authority,public.yc_preferred_identity_review FROM %I',role_name);
   EXECUTE format('REVOKE ALL ON FUNCTION public.yc_offer_acceptance_immutable(),public.yc_offer_acceptance_rpc(text,jsonb),public.yc_preferred_identity_immutable(),public.yc_preferred_claim_view(public.yc_claim),public.yc_preferred_claim_rpc(text,jsonb),public.yc_preferred_staff_rpc(text,jsonb) FROM %I',role_name);
  END IF;
 END LOOP;
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='promotion_evidence_proxy') THEN
  GRANT EXECUTE ON FUNCTION public.yc_offer_acceptance_rpc(text,jsonb),public.yc_preferred_claim_rpc(text,jsonb),public.yc_preferred_staff_rpc(text,jsonb) TO promotion_evidence_proxy;
 END IF;
END $$;
-- Shared permits commit before regional financial effects. Invalidation keeps a
-- permanent target until its regional fence and commercial revocation commit.
CREATE TABLE public.yc_financial_serialization (
 key text PRIMARY KEY,
 generation bigint NOT NULL DEFAULT 1
);
CREATE TABLE public.yc_financial_authorization (
 authorization_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 acceptance_id uuid NOT NULL REFERENCES public.yc_offer_acceptance_authority(acceptance_id),
 claim_id uuid NOT NULL,
 team_id uuid NOT NULL,
 user_id uuid NOT NULL,
 home_region text NOT NULL,
 company_identity text NOT NULL,
 approved_email_hash text NOT NULL,
 approval_id uuid NOT NULL,
 approval_revision bigint NOT NULL,
 assignment_id uuid NOT NULL,
 phase text NOT NULL CHECK(phase IN ('initial','successor')),
 operation_id uuid NOT NULL UNIQUE,
 terms_digest text NOT NULL,
 renewal_terms_digest text NOT NULL,
 target_terms_digest text NOT NULL CHECK(target_terms_digest ~ '^[a-f0-9]{64}$'),
 authorized_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 invalidated_at timestamptz,
 UNIQUE(acceptance_id,phase,operation_id)
);
CREATE UNIQUE INDEX yc_financial_initial_once ON public.yc_financial_authorization(acceptance_id) WHERE phase='initial';
CREATE INDEX yc_financial_claim ON public.yc_financial_authorization(claim_id) WHERE invalidated_at IS NULL;
CREATE INDEX yc_financial_user ON public.yc_financial_authorization(user_id) WHERE invalidated_at IS NULL;
CREATE INDEX yc_financial_email ON public.yc_financial_authorization(approved_email_hash) WHERE invalidated_at IS NULL;
CREATE INDEX yc_financial_company ON public.yc_financial_authorization(company_identity) WHERE invalidated_at IS NULL;
CREATE TABLE public.yc_financial_invalidation (
 invalidation_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 authorization_id uuid NOT NULL UNIQUE REFERENCES public.yc_financial_authorization(authorization_id),
 acceptance_id uuid NOT NULL,
 team_id uuid NOT NULL,
 home_region text NOT NULL,
 assignment_id uuid NOT NULL,
 phase text NOT NULL,
 operation_id uuid NOT NULL,
 invalidated_at timestamptz NOT NULL,
 reason text NOT NULL,
 lease_id uuid,
 lease_until timestamptz,
 acknowledgement_id uuid UNIQUE,
 regional_fence_id uuid,
 acknowledged_at timestamptz,
 CHECK ((acknowledgement_id IS NULL)=(acknowledged_at IS NULL)),
 CHECK ((regional_fence_id IS NULL)=(acknowledged_at IS NULL))
);
CREATE INDEX yc_financial_invalidation_acceptance ON public.yc_financial_invalidation(acceptance_id) WHERE acknowledged_at IS NULL;
CREATE INDEX yc_financial_invalidation_pending ON public.yc_financial_invalidation(home_region,invalidated_at,invalidation_id) WHERE acknowledged_at IS NULL;

CREATE FUNCTION public.yc_financial_touch(k text) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$ BEGIN
 -- A persisted write also detects unseen concurrent issuance under fixed
 -- transaction snapshots. A read/advisory lock alone cannot provide that proof.
 INSERT INTO public.yc_financial_serialization(key) VALUES(k)
 ON CONFLICT(key) DO UPDATE SET generation=public.yc_financial_serialization.generation+1;
END $$;
CREATE FUNCTION public.yc_financial_authorization_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$ BEGIN
 IF TG_OP='DELETE' OR (to_jsonb(NEW)-'invalidated_at') IS DISTINCT FROM (to_jsonb(OLD)-'invalidated_at')
 OR OLD.invalidated_at IS NOT NULL OR NEW.invalidated_at IS NULL THEN
  RAISE EXCEPTION 'financial authorization history is immutable';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER yc_financial_authorization_immutable BEFORE UPDATE OR DELETE ON public.yc_financial_authorization
 FOR EACH ROW EXECUTE FUNCTION public.yc_financial_authorization_immutable();

CREATE FUNCTION public.yc_financial_invalidate(kind text,target text,why text) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE r public.yc_financial_authorization; invalidated timestamptz:=clock_timestamp(); predicate text;
BEGIN
 -- Only this closed list supplies SQL; the target remains a bound parameter.
 -- Replanning keeps every Auth lifecycle lookup indexable, independent of a
 -- cached generic plan for other invalidation kinds.
 predicate:=CASE kind WHEN 'user' THEN 'user_id=$1::uuid' WHEN 'email' THEN 'approved_email_hash=$1'
  WHEN 'company' THEN 'company_identity=$1' WHEN 'claim' THEN 'claim_id=$1::uuid' END;
 IF predicate IS NULL THEN RAISE EXCEPTION 'invalid financial invalidation kind' USING ERRCODE='22023'; END IF;
 -- Callers serialize the relevant writer before this separate, fresh scan.
 FOR r IN EXECUTE 'SELECT * FROM public.yc_financial_authorization WHERE invalidated_at IS NULL AND '
  ||predicate||' ORDER BY authorization_id FOR UPDATE' USING target LOOP
  UPDATE public.yc_financial_authorization SET invalidated_at=invalidated WHERE authorization_id=r.authorization_id;
  INSERT INTO public.yc_financial_invalidation(authorization_id,acceptance_id,team_id,home_region,assignment_id,phase,operation_id,invalidated_at,reason)
   VALUES(r.authorization_id,r.acceptance_id,r.team_id,r.home_region,r.assignment_id,r.phase,r.operation_id,invalidated,why);
 END LOOP;
END $$;

CREATE FUNCTION public.yc_financial_writer() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public,auth,pg_temp AS $$
DECLARE company text; email_key text;
BEGIN
 IF TG_TABLE_SCHEMA='auth' AND TG_TABLE_NAME='users' THEN
  IF TG_OP='UPDATE' AND (NEW.id,lower(btrim(NEW.email)),NEW.email_confirmed_at,NEW.deleted_at,NEW.created_at)
   IS NOT DISTINCT FROM (OLD.id,lower(btrim(OLD.email)),OLD.email_confirmed_at,OLD.deleted_at,OLD.created_at) THEN RETURN NEW; END IF;
  PERFORM public.yc_financial_touch('user/'||OLD.id::text);
  -- Take both tombstone keys in a deterministic order before the legacy Auth
  -- lifecycle trigger inserts them in its own query order.
  IF TG_OP='DELETE' OR lower(btrim(NEW.email)) IS DISTINCT FROM lower(btrim(OLD.email)) OR NEW.deleted_at IS DISTINCT FROM OLD.deleted_at THEN
   FOR email_key IN SELECT DISTINCT encode(sha256(convert_to(e,'UTF8')),'hex') FROM
    unnest(ARRAY[lower(btrim(OLD.email)),CASE WHEN TG_OP='UPDATE' THEN lower(btrim(NEW.email)) END]) e
    WHERE e IS NOT NULL AND e<>'' ORDER BY 1 LOOP
    PERFORM public.yc_financial_touch('email/'||email_key);
   END LOOP;
  END IF;
  PERFORM public.yc_financial_invalidate('user',OLD.id::text,'approved_account_changed');
 ELSIF TG_TABLE_NAME='yc_claim_identity_history' THEN
  IF TG_OP='UPDATE' AND NEW.email_hash IS DISTINCT FROM OLD.email_hash THEN
   RAISE EXCEPTION 'identity tombstone key is immutable';
  END IF;
  PERFORM public.yc_financial_touch('email/'||NEW.email_hash);
  PERFORM public.yc_financial_invalidate('email',NEW.email_hash,'approved_identity_history');
 ELSIF TG_TABLE_NAME='yc_company_activation_authority' THEN
  IF NEW.revoked_at IS NOT DISTINCT FROM OLD.revoked_at THEN RETURN NEW; END IF;
  PERFORM public.yc_financial_touch('company/'||NEW.company_identity);
  PERFORM public.yc_financial_invalidate('company',NEW.company_identity,'company_authority_revoked');
 ELSIF TG_TABLE_NAME='yc_claim' THEN
  IF (NEW.state,NEW.lifecycle_changed) IS NOT DISTINCT FROM (OLD.state,OLD.lifecycle_changed) THEN RETURN NEW; END IF;
  SELECT company_identity INTO company FROM public.yc_company_activation_authority WHERE claim_id=NEW.id FOR UPDATE;
  IF company IS NOT NULL THEN
   PERFORM public.yc_financial_touch('company/'||company);
  END IF;
  PERFORM public.yc_financial_touch('claim/'||NEW.id::text);
  PERFORM public.yc_financial_invalidate('claim',NEW.id::text,'claim_authority_changed');
 ELSIF TG_TABLE_NAME='yc_claim_decision' AND NEW.decision IN ('operator','verified_claim') THEN
  SELECT company_identity INTO company FROM public.yc_company_activation_authority WHERE claim_id=NEW.claim_id FOR UPDATE;
  IF company IS NOT NULL THEN
   PERFORM public.yc_financial_touch('company/'||company);
  END IF;
  PERFORM public.yc_financial_touch('claim/'||NEW.claim_id::text);
  PERFORM public.yc_financial_invalidate('claim',NEW.claim_id::text,'semantic_approval_changed');
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER yc_financial_auth_writer BEFORE UPDATE OF id,email,email_confirmed_at,deleted_at,created_at OR DELETE ON auth.users
 FOR EACH ROW EXECUTE FUNCTION public.yc_financial_writer();
CREATE TRIGGER yc_financial_history_writer BEFORE INSERT OR UPDATE ON public.yc_claim_identity_history
 FOR EACH ROW EXECUTE FUNCTION public.yc_financial_writer();
CREATE TRIGGER yc_financial_company_writer AFTER UPDATE ON public.yc_company_activation_authority
 FOR EACH ROW EXECUTE FUNCTION public.yc_financial_writer();
CREATE TRIGGER yc_financial_claim_writer AFTER UPDATE ON public.yc_claim
 FOR EACH ROW EXECUTE FUNCTION public.yc_financial_writer();
CREATE TRIGGER yc_financial_decision_writer AFTER INSERT ON public.yc_claim_decision
 FOR EACH ROW EXECUTE FUNCTION public.yc_financial_writer();

CREATE FUNCTION public.yc_financial_state(claim uuid,automated boolean DEFAULT false) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,auth,pg_temp AS $$
DECLARE c public.yc_claim; r public.yc_offer_acceptance_authority; pending integer; valid boolean; approved_email text; result text; accepted boolean;
BEGIN
 SELECT * INTO c FROM public.yc_claim WHERE id=claim;
 IF NOT FOUND THEN RAISE EXCEPTION 'claim unavailable' USING ERRCODE='P0002'; END IF;
 SELECT * INTO r FROM public.yc_offer_acceptance_authority WHERE claim_id=claim;
 accepted:=FOUND;
 IF NOT accepted THEN
  IF NOT automated AND NOT c.acceptance_required AND NOT EXISTS(SELECT 1 FROM public.yc_preferred_identity_review WHERE claim_id=claim) THEN RETURN NULL; END IF;
  IF c.state<>'bound' OR c.lifecycle_changed THEN
   RETURN jsonb_build_object('kind','accepted_offer','state',CASE WHEN c.state IN ('revoked','rejected') OR c.lifecycle_changed THEN 'revoked' ELSE 'acceptance_pending' END,'pending_invalidations',0);
  END IF;
  -- A bound claim without shared acceptance can still lose account/company
  -- authority while its regional offer or confirmation is pending.
  r.claim_id:=c.id; r.user_id:=c.claimed_user_id; r.team_id:=c.claimed_team_id;
  r.home_region:=c.home_region; r.company_identity:=c.company_identity; r.approval_id:=c.approval_id;
  SELECT a.offer_key,a.offer_version INTO r.offer_key,r.offer_version FROM public.yc_company_activation_authority a WHERE a.company_identity=c.company_identity;
  SELECT revision INTO r.approval_revision FROM public.yc_claim_decision WHERE claim_id=c.id AND decision IN ('operator','verified_claim') ORDER BY revision DESC LIMIT 1;
 END IF;
 SELECT COALESCE((SELECT pr.email FROM public.yc_preferred_identity_review pr WHERE claim_id=c.id AND user_id=r.user_id AND team_id=r.team_id AND ready AND approved_revision IS NOT NULL),c.submitted_email) INTO approved_email;
 SELECT c.state='bound' AND NOT c.lifecycle_changed AND c.claimed_user_id=r.user_id AND c.claimed_team_id=r.team_id
  AND c.home_region=r.home_region AND c.company_identity=r.company_identity AND c.approval_id=r.approval_id
  AND EXISTS(SELECT 1 FROM auth.users u WHERE u.id=r.user_id AND u.deleted_at IS NULL AND u.email_confirmed_at IS NOT NULL AND u.created_at>=c.created_at AND lower(btrim(u.email))=approved_email)
  AND NOT EXISTS(SELECT 1 FROM public.yc_claim_identity_history WHERE email_hash=encode(sha256(convert_to(approved_email,'UTF8')),'hex'))
  AND EXISTS(SELECT 1 FROM public.yc_company_activation_authority a WHERE a.company_identity=r.company_identity AND a.approval_id=r.approval_id AND a.team_id=r.team_id AND a.home_region=r.home_region AND a.claim_id=r.claim_id AND a.revoked_at IS NULL AND a.offer_key=r.offer_key AND a.offer_version=r.offer_version)
  AND r.approval_revision=(SELECT revision FROM public.yc_claim_decision WHERE claim_id=c.id AND decision IN ('operator','verified_claim') ORDER BY revision DESC LIMIT 1)
  AND NOT EXISTS(SELECT 1 FROM public.yc_financial_authorization WHERE acceptance_id=r.acceptance_id AND invalidated_at IS NOT NULL) INTO valid;
 SELECT count(*) INTO pending FROM public.yc_financial_invalidation WHERE acceptance_id=r.acceptance_id AND acknowledged_at IS NULL;
 result:=CASE WHEN pending>0 THEN 'revocation_pending' WHEN COALESCE(valid,false) THEN CASE WHEN accepted THEN 'valid' ELSE 'acceptance_pending' END ELSE 'revoked' END;
 RETURN jsonb_build_object('kind','accepted_offer','state',result,'pending_invalidations',pending);
END $$;

CREATE FUNCTION public.yc_financial_authority_rpc(op text,p jsonb) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public,auth,pg_temp AS $$
DECLARE accepted public.yc_offer_acceptance_authority; r public.yc_financial_authorization; wanted public.yc_financial_authorization;
 d public.yc_financial_invalidation; email text; result jsonb; batch integer;
BEGIN
 IF p IS NULL OR jsonb_typeof(p)<>'object' OR op IS NULL OR op NOT IN ('issue','read','lease-invalidations','ack-invalidation','state') THEN
  RAISE EXCEPTION 'invalid financial authority request' USING ERRCODE='22023';
 END IF;
 IF op='state' THEN RETURN public.yc_financial_state((p->>'claim_id')::uuid,COALESCE((p->>'automated')::boolean,false)); END IF;
 IF op='read' THEN
  SELECT * INTO r FROM public.yc_financial_authorization WHERE acceptance_id=(p->>'acceptance_id')::uuid AND phase=p->>'phase' AND operation_id=(p->>'operation_id')::uuid;
  IF NOT FOUND THEN RAISE EXCEPTION 'authorization unavailable' USING ERRCODE='P0002'; END IF;
  RETURN to_jsonb(r)-'approved_email_hash';
 END IF;
 IF op='lease-invalidations' THEN
  batch:=(p->>'limit')::integer;
  IF batch IS NULL OR batch NOT BETWEEN 1 AND 25 OR (p->>'lease_id')::uuid IS NULL OR COALESCE(p->>'home_region','')='' THEN
   RAISE EXCEPTION 'invalid delivery lease' USING ERRCODE='22023'; END IF;
  WITH candidates AS (SELECT invalidation_id FROM public.yc_financial_invalidation WHERE home_region=p->>'home_region' AND acknowledged_at IS NULL
    AND (lease_until IS NULL OR lease_until<=clock_timestamp()) ORDER BY invalidated_at,invalidation_id LIMIT batch FOR UPDATE SKIP LOCKED),
   leased AS (UPDATE public.yc_financial_invalidation q SET lease_id=(p->>'lease_id')::uuid,lease_until=clock_timestamp()+interval '1 minute'
    FROM candidates c WHERE q.invalidation_id=c.invalidation_id RETURNING q.*)
   SELECT COALESCE(jsonb_agg(to_jsonb(leased)),'[]'::jsonb) INTO result FROM leased;
  RETURN result;
 END IF;
 IF op='ack-invalidation' THEN
  SELECT * INTO d FROM public.yc_financial_invalidation WHERE invalidation_id=(p->>'invalidation_id')::uuid FOR UPDATE;
  IF NOT FOUND OR d.home_region IS DISTINCT FROM p->>'home_region' OR d.lease_id IS DISTINCT FROM (p->>'lease_id')::uuid
   OR (p->>'acknowledgement_id')::uuid IS NULL OR (p->>'regional_fence_id')::uuid IS NULL THEN
   RAISE EXCEPTION 'invalidation identity changed' USING ERRCODE='23505'; END IF;
  IF d.acknowledged_at IS NOT NULL THEN
   IF d.acknowledgement_id IS DISTINCT FROM (p->>'acknowledgement_id')::uuid OR d.regional_fence_id IS DISTINCT FROM (p->>'regional_fence_id')::uuid THEN
    RAISE EXCEPTION 'acknowledgement identity changed' USING ERRCODE='23505'; END IF;
   RETURN to_jsonb(d);
  END IF;
  IF d.lease_until IS NULL OR d.lease_until<=clock_timestamp() THEN RAISE EXCEPTION 'delivery lease expired' USING ERRCODE='23505'; END IF;
  UPDATE public.yc_financial_invalidation SET acknowledgement_id=(p->>'acknowledgement_id')::uuid,regional_fence_id=(p->>'regional_fence_id')::uuid,acknowledged_at=clock_timestamp()
   WHERE invalidation_id=d.invalidation_id RETURNING * INTO d;
  RETURN to_jsonb(d);
 END IF;
 IF p->>'phase' IS NULL OR p->>'phase' NOT IN ('initial','successor') OR (p->>'operation_id')::uuid IS NULL
  OR (p->>'assignment_id')::uuid IS NULL OR p->>'target_terms_digest' IS NULL OR p->>'target_terms_digest' !~ '^[a-f0-9]{64}$'
  OR (p->>'phase'='initial' AND p->>'target_terms_digest' IS DISTINCT FROM p->>'terms_digest') THEN
  RAISE EXCEPTION 'exact financial target required' USING ERRCODE='22023'; END IF;
 SELECT lower(btrim(u.email)) INTO email FROM auth.users u WHERE id=(p->>'user_id')::uuid FOR SHARE;
 IF NOT FOUND OR email IS NULL THEN RAISE EXCEPTION 'approved account unavailable' USING ERRCODE='22023'; END IF;
 PERFORM public.yc_financial_touch('user/'||((p->>'user_id')::uuid)::text);
 PERFORM public.yc_financial_touch('email/'||encode(sha256(convert_to(email,'UTF8')),'hex'));
 PERFORM public.yc_offer_acceptance_rpc('guard',p);
 PERFORM public.yc_financial_touch('company/'||(p->>'company_identity'));
 PERFORM public.yc_financial_touch('claim/'||((p->>'claim_id')::uuid)::text);
 IF public.yc_financial_state((p->>'claim_id')::uuid,true)->>'state'<>'valid' THEN
  RAISE EXCEPTION 'financial authority invalid' USING ERRCODE='22023'; END IF;
 SELECT * INTO STRICT accepted FROM public.yc_offer_acceptance_authority WHERE acceptance_id=(p->>'acceptance_id')::uuid;
 wanted:=jsonb_populate_record(NULL::public.yc_financial_authorization,to_jsonb(accepted)||p||jsonb_build_object('approved_email_hash',encode(sha256(convert_to(email,'UTF8')),'hex')));
 INSERT INTO public.yc_financial_authorization(acceptance_id,claim_id,team_id,user_id,home_region,company_identity,approved_email_hash,approval_id,approval_revision,assignment_id,phase,operation_id,terms_digest,renewal_terms_digest,target_terms_digest)
 VALUES(wanted.acceptance_id,wanted.claim_id,wanted.team_id,wanted.user_id,wanted.home_region,wanted.company_identity,wanted.approved_email_hash,wanted.approval_id,wanted.approval_revision,wanted.assignment_id,wanted.phase,wanted.operation_id,wanted.terms_digest,wanted.renewal_terms_digest,wanted.target_terms_digest)
 ON CONFLICT DO NOTHING;
 SELECT * INTO r FROM public.yc_financial_authorization WHERE operation_id=wanted.operation_id;
 IF NOT FOUND OR (to_jsonb(r)-ARRAY['authorization_id','authorized_at','invalidated_at']) IS DISTINCT FROM (to_jsonb(wanted)-ARRAY['authorization_id','authorized_at','invalidated_at']) OR r.invalidated_at IS NOT NULL THEN
  RAISE EXCEPTION 'financial authorization identity changed' USING ERRCODE='23505'; END IF;
 RETURN to_jsonb(r)-'approved_email_hash';
END $$;

ALTER TABLE public.yc_financial_serialization ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.yc_financial_authorization ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.yc_financial_invalidation ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.yc_financial_serialization,public.yc_financial_authorization,public.yc_financial_invalidation FROM PUBLIC;
REVOKE ALL ON FUNCTION public.yc_financial_touch(text),public.yc_financial_authorization_immutable(),public.yc_financial_invalidate(text,text,text),public.yc_financial_writer(),public.yc_financial_state(uuid,boolean),public.yc_financial_authority_rpc(text,jsonb) FROM PUBLIC;
DO $$ DECLARE role_name text; BEGIN
 FOREACH role_name IN ARRAY ARRAY['anon','authenticated','service_role','promotion_evidence_proxy'] LOOP
  IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=role_name) THEN
   EXECUTE format('REVOKE ALL ON public.yc_financial_serialization,public.yc_financial_authorization,public.yc_financial_invalidation FROM %I',role_name);
   EXECUTE format('REVOKE ALL ON FUNCTION public.yc_financial_touch(text),public.yc_financial_authorization_immutable(),public.yc_financial_invalidate(text,text,text),public.yc_financial_writer(),public.yc_financial_state(uuid,boolean),public.yc_financial_authority_rpc(text,jsonb) FROM %I',role_name);
  END IF;
 END LOOP;
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='promotion_evidence_proxy') THEN
  GRANT EXECUTE ON FUNCTION public.yc_financial_authority_rpc(text,jsonb) TO promotion_evidence_proxy;
 END IF;
END $$;
CREATE OR REPLACE FUNCTION public.yc_preferred_claim_view(c public.yc_claim) RETURNS jsonb
LANGUAGE sql STABLE SET search_path=pg_catalog,public,pg_temp AS $$
 SELECT public.yc_claim_view(c)||jsonb_build_object('financial_authority',public.yc_financial_state(c.id,false))||jsonb_build_object('preferred_identity_review',
  (SELECT jsonb_build_object('review_request_id',r.request_id,'review_revision',r.revision,'user_id',r.user_id,
   'email',r.email,'team_id',r.team_id,'home_region',r.home_region,'company_identity',r.company_identity,
   'ready',r.ready,'approved_revision',r.approved_revision) FROM public.yc_preferred_identity_review r WHERE r.claim_id=c.id))
$$;

COMMIT;
