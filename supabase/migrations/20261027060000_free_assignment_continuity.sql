-- Preserve an unchanged Free allowance when a plan assignment changes without
-- adding a history walk to sandbox admission or resume.
ALTER TABLE team_plan_assignment ADD COLUMN free_allowance_since timestamptz
 CHECK (free_allowance_since IS NULL OR
  (kind='free' AND isfinite(free_allowance_since) AND free_allowance_since<=effective_from));

CREATE INDEX team_plan_assignment_prior_boundary
 ON team_plan_assignment(team_id,effective_to,effective_from DESC,created_at DESC,id)
 WHERE effective_to IS NOT NULL;

CREATE FUNCTION derive_free_assignment_continuity() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE previous team_plan_assignment; expected timestamptz;
BEGIN
 -- Assignment changes already serialize here. Raw inserts must do the same
 -- before deriving continuity, rather than trusting a caller's earlier floor.
 PERFORM 1 FROM team WHERE id=NEW.team_id FOR NO KEY UPDATE;
 IF NEW.kind='free' THEN
  expected:=NEW.effective_from;
  SELECT * INTO previous FROM team_plan_assignment
  WHERE team_id=NEW.team_id AND effective_to=NEW.effective_from
  ORDER BY effective_from DESC,created_at DESC,id LIMIT 1;
  IF FOUND AND previous.kind='free' AND previous.effective_from<NEW.effective_from
   -- amount_usd is a derived display string, never allowance authority.
   AND (CASE WHEN jsonb_typeof(previous.terms->'allowance')='object'
     THEN (previous.terms->'allowance')-'amount_usd' ELSE previous.terms->'allowance' END)
    IS NOT DISTINCT FROM
    (CASE WHEN jsonb_typeof(NEW.terms->'allowance')='object'
     THEN (NEW.terms->'allowance')-'amount_usd' ELSE NEW.terms->'allowance' END) THEN
   expected:=COALESCE(previous.free_allowance_since,previous.effective_from);
  END IF;
 END IF;
 IF NEW.free_allowance_since IS NOT NULL AND NEW.free_allowance_since IS DISTINCT FROM expected THEN
  RAISE EXCEPTION 'Free allowance continuity must match the preceding assignment';
 END IF;
 NEW.free_allowance_since:=expected;
 RETURN NEW;
END $$;
CREATE TRIGGER team_plan_assignment_continuity BEFORE INSERT ON team_plan_assignment
 FOR EACH ROW EXECUTE FUNCTION derive_free_assignment_continuity();
REVOKE ALL ON FUNCTION derive_free_assignment_continuity() FROM PUBLIC;

-- Legacy rows retain NULL and use their existing assignment start. New rows
-- freeze the derived floor once; the existing assignment guard makes it immutable.
CREATE OR REPLACE FUNCTION billing_free_plan(p_team uuid)
RETURNS TABLE(free_since timestamptz, allowance jsonb, max_vcpu int, max_memory_mib int, max_disk_mib int)
LANGUAGE sql STABLE AS $$
 SELECT COALESCE(a.free_allowance_since,a.effective_from),
        CASE WHEN jsonb_typeof(a.terms->'allowance')='object' THEN a.terms->'allowance' ELSE '{}'::jsonb END,
        COALESCE(CASE WHEN t.limits_customized THEN t.max_template_vcpu END,billing_json_cap(a.limits->'max_vcpu')),
        COALESCE(CASE WHEN t.limits_customized THEN t.max_template_memory_mib END,billing_json_cap(a.limits->'max_memory_mib')),
        COALESCE(CASE WHEN t.limits_customized THEN t.max_template_disk_mib END,billing_json_cap(a.limits->'max_disk_mib'))
 FROM team_plan_assignment a JOIN team t ON t.id=a.team_id
 WHERE a.team_id=p_team AND a.effective_to IS NULL AND a.kind='free';
$$;
