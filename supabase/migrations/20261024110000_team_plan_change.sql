-- A requested move of a team to another plan that takes effect later or needs
-- follow-up work: downgrades wait for the end of the billing period and can be
-- undone until then; a move to Free pauses the team's running sandboxes once
-- it applies. Upgrades are not recorded here: they apply on payment.
CREATE TABLE team_plan_change (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 team_id uuid NOT NULL,
 from_assignment_id uuid NOT NULL REFERENCES team_plan_assignment(id),
 target_plan_key text NOT NULL CHECK(btrim(target_plan_key)<>''),
 target_kind text NOT NULL CHECK(target_kind IN ('free','prepaid','subscription','legacy_payg','custom')),
 target_terms jsonb NOT NULL CHECK(jsonb_typeof(target_terms)='object'),
 target_limits jsonb NOT NULL CHECK(jsonb_typeof(target_limits)='object' AND (jsonb_typeof(target_limits->'max_concurrent')='number') IS TRUE),
 effective_at timestamptz NOT NULL,
 pauses_running boolean NOT NULL,
 subscription_id text CHECK(subscription_id IS NULL OR btrim(subscription_id)<>''),
 requested_by uuid NOT NULL,
 requested_via text NOT NULL CHECK(requested_via IN ('customer','staff')),
 reason text NOT NULL CHECK(length(btrim(reason)) BETWEEN 1 AND 2000),
 idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 200),
 requested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 terminal_undo_of uuid UNIQUE REFERENCES team_plan_change(id),
 state text NOT NULL DEFAULT 'scheduled' CHECK(state IN ('scheduled','applied','completed','undone')),
 -- The worker records that it is about to tell Stripe not to renew before it
 -- does, and whether the subscription was already set to end; undoing a change
 -- turns renewal back on only if this change turned it off.
 provider_cancel_requested_at timestamptz,
 provider_cancel_preexisting boolean NOT NULL DEFAULT false,
 provider_cancel_at timestamptz,
 provider_renewed_at timestamptz,
 undone_at timestamptz,
 undone_by uuid,
 undo_reason text CHECK(undo_reason IS NULL OR length(btrim(undo_reason)) BETWEEN 1 AND 2000),
 applied_at timestamptz,
 applied_assignment_id uuid UNIQUE REFERENCES team_plan_assignment(id),
 completed_at timestamptz,
 next_check_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 lease_token uuid,
 lease_until timestamptz,
 failures integer NOT NULL DEFAULT 0 CHECK(failures>=0),
 last_error text,
 UNIQUE(team_id,idempotency_key),
 CHECK((state='undone')=(undo_reason IS NOT NULL)),
 CHECK((state='undone')=(undone_at IS NOT NULL) AND (state IN ('applied','completed'))=(applied_at IS NOT NULL AND applied_assignment_id IS NOT NULL)
  AND (state='completed')=(completed_at IS NOT NULL))
);
CREATE UNIQUE INDEX team_plan_change_pending ON team_plan_change(team_id) WHERE state='scheduled';
CREATE INDEX team_plan_change_due ON team_plan_change(next_check_at,id)
 WHERE state IN ('scheduled','applied') OR (state='undone' AND subscription_id IS NOT NULL AND provider_renewed_at IS NULL);
CREATE INDEX team_plan_change_history ON team_plan_change(team_id,requested_at DESC);

ALTER TABLE billing_plan_release ADD COLUMN plan_change_id uuid REFERENCES team_plan_change(id);
CREATE UNIQUE INDEX billing_plan_release_change ON billing_plan_release(plan_change_id) WHERE plan_change_id IS NOT NULL;

CREATE FUNCTION guard_team_plan_change() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE bookkeeping text[]:=ARRAY['next_check_at','lease_token','lease_until','failures','last_error'];
 progress text[]:=ARRAY['state','effective_at','provider_cancel_requested_at','provider_cancel_preexisting','provider_cancel_at','provider_renewed_at',
  'undone_at','undone_by','undo_reason','applied_at','applied_assignment_id','completed_at'];
BEGIN
 IF TG_OP<>'UPDATE' AND TG_OP<>'INSERT' THEN RAISE EXCEPTION 'plan change history is immutable'; END IF;
 IF TG_OP='INSERT' THEN
  PERFORM 1 FROM team WHERE id=NEW.team_id FOR KEY SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'plan change team does not exist' USING ERRCODE='23503'; END IF;
  IF NEW.state<>'scheduled' OR NEW.provider_cancel_preexisting OR num_nonnulls(NEW.provider_cancel_requested_at,NEW.provider_cancel_at,NEW.provider_renewed_at,
   NEW.undone_at,NEW.undone_by,NEW.undo_reason,NEW.applied_at,NEW.applied_assignment_id,NEW.completed_at)<>0 THEN
   RAISE EXCEPTION 'a plan change starts scheduled';
  END IF;
  IF NEW.terminal_undo_of IS NOT NULL AND NOT EXISTS(SELECT 1 FROM team_plan_change p WHERE p.id=NEW.terminal_undo_of AND p.state='undone'
   AND p.subscription_id IS NOT NULL AND p.team_id=NEW.team_id AND p.from_assignment_id=NEW.from_assignment_id
   AND p.subscription_id=NEW.subscription_id AND p.target_plan_key=NEW.target_plan_key AND p.target_kind=NEW.target_kind
   AND p.target_terms=NEW.target_terms AND p.target_limits=NEW.target_limits AND p.pauses_running=NEW.pauses_running
   AND p.requested_by=NEW.requested_by AND p.requested_via=NEW.requested_via) THEN
   RAISE EXCEPTION 'terminal undo settlement must preserve its original commitment';
  END IF;
  RETURN NEW;
 END IF;
 IF (to_jsonb(NEW)-bookkeeping-progress) IS DISTINCT FROM (to_jsonb(OLD)-bookkeeping-progress) THEN
  RAISE EXCEPTION 'a plan change request is immutable';
 END IF;
 IF OLD.state IN ('completed','undone') AND (to_jsonb(NEW)-bookkeeping-'provider_renewed_at') IS DISTINCT FROM (to_jsonb(OLD)-bookkeeping-'provider_renewed_at') THEN
  RAISE EXCEPTION 'a finished plan change is immutable';
 END IF;
 IF NEW.provider_renewed_at IS DISTINCT FROM OLD.provider_renewed_at AND (OLD.provider_renewed_at IS NOT NULL OR NEW.state<>'undone'
  OR OLD.subscription_id IS NULL) THEN
  RAISE EXCEPTION 'a subscription undo is reconciled once';
 END IF;
 IF (NEW.provider_cancel_requested_at IS DISTINCT FROM OLD.provider_cancel_requested_at
  OR NEW.provider_cancel_preexisting IS DISTINCT FROM OLD.provider_cancel_preexisting)
  AND (OLD.provider_cancel_requested_at IS NOT NULL OR OLD.state<>'scheduled' OR NEW.state<>'scheduled') THEN
  RAISE EXCEPTION 'a subscription cancellation is requested once, while scheduled';
 END IF;
 IF NEW.state IS DISTINCT FROM OLD.state AND NOT (OLD.state,NEW.state) IN (('scheduled','applied'),('scheduled','undone'),('applied','completed')) THEN
  RAISE EXCEPTION 'plan change cannot move from % to %',OLD.state,NEW.state;
 END IF;
 IF OLD.provider_cancel_at IS NOT NULL AND NEW.provider_cancel_at IS DISTINCT FROM OLD.provider_cancel_at
  OR NEW.provider_cancel_at IS NOT NULL AND OLD.provider_cancel_at IS NULL AND (OLD.state<>'scheduled' OR NEW.provider_cancel_requested_at IS NULL) THEN
  RAISE EXCEPTION 'a subscription cancellation is confirmed once, after it was requested, while scheduled';
 END IF;
 -- A change whose subscription cancellation never reached Stripe before the
 -- period ended waits for the next period end rather than applying early.
 IF NEW.effective_at IS DISTINCT FROM OLD.effective_at AND NOT (
  OLD.state='scheduled' AND NEW.state='scheduled' AND NEW.effective_at>OLD.effective_at
  OR OLD.state='scheduled' AND NEW.state='applied' AND NEW.effective_at<OLD.effective_at
   AND NEW.effective_at<=clock_timestamp() AND EXISTS(SELECT 1 FROM billing_plan_release r
    WHERE r.plan_change_id=NEW.id AND r.team_id=NEW.team_id AND r.subscription_id=NEW.subscription_id
     AND r.provider_status IN ('canceled','incomplete_expired') AND r.released_at>=NEW.requested_at)) THEN
  RAISE EXCEPTION 'effective time requires a scheduled deferral or an applied terminal-subscription release';
 END IF;
 IF NEW.state='applied' AND OLD.state='scheduled' AND NEW.effective_at>clock_timestamp() THEN
  RAISE EXCEPTION 'a plan change cannot apply before it takes effect';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER team_plan_change_guard BEFORE INSERT OR UPDATE OR DELETE ON team_plan_change
 FOR EACH ROW EXECUTE FUNCTION guard_team_plan_change();
CREATE TRIGGER team_plan_change_truncate_guard BEFORE TRUNCATE ON team_plan_change
 FOR EACH STATEMENT EXECUTE FUNCTION guard_team_plan_change();

CREATE FUNCTION finish_deleted_team_plan_changes() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 UPDATE team_plan_change SET
  state=CASE WHEN state='scheduled' THEN 'undone' WHEN state='applied' THEN 'completed' ELSE state END,
  undone_at=CASE WHEN state='scheduled' THEN clock_timestamp() ELSE undone_at END,
  undo_reason=CASE WHEN state='scheduled' THEN 'the team was deleted' ELSE undo_reason END,
  provider_renewed_at=CASE WHEN state IN ('scheduled','undone') AND subscription_id IS NOT NULL
   THEN COALESCE(provider_renewed_at,clock_timestamp()) ELSE provider_renewed_at END,
  completed_at=CASE WHEN state='applied' THEN clock_timestamp() ELSE completed_at END,
  next_check_at='infinity',lease_token=NULL,lease_until=NULL
 WHERE team_id=OLD.id AND (state IN ('scheduled','applied') OR (state='undone' AND provider_renewed_at IS NULL));
 RETURN OLD;
END $$;
CREATE TRIGGER team_plan_change_team_deleted AFTER DELETE ON team
 FOR EACH ROW EXECUTE FUNCTION finish_deleted_team_plan_changes();
REVOKE ALL ON FUNCTION finish_deleted_team_plan_changes() FROM PUBLIC;

ALTER TABLE team_plan_change ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON team_plan_change FROM PUBLIC;
DO $$ DECLARE r text; BEGIN
 FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
  IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=r) THEN
   EXECUTE format('REVOKE ALL ON team_plan_change FROM %I',r);
   IF r='service_role' THEN
    GRANT SELECT,INSERT,UPDATE ON team_plan_change TO service_role;
    CREATE POLICY team_plan_change_backend ON team_plan_change TO service_role USING(true) WITH CHECK(true);
   END IF;
  END IF;
 END LOOP;
 REVOKE ALL ON FUNCTION guard_team_plan_change() FROM PUBLIC;
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN GRANT EXECUTE ON FUNCTION guard_team_plan_change() TO service_role; END IF;
END $$;
