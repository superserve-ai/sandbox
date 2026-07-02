-- Quota frees the slot at BeginPause, not FinalizePause: 'pausing' leaves the
-- counted set. Counted = destroyed_at IS NULL AND status NOT IN
-- ('failed','paused','pausing').
--
-- Why: FinalizePause is now a fire-and-forget write that lands after the pause
-- response, so counting 'pausing' made the documented pause-then-create
-- workflow transiently 429 for teams at max_sandboxes. BeginPause is the
-- commitment point of a pause (the VM will stop or the row reverts), so it is
-- also the right quota-release point — and it runs before the response, which
-- makes pause→create deterministic again.
--
-- Tradeoffs, both bounded and rare:
--   * While the VMD snapshot is in flight (seconds), a team can briefly run
--     cap+1 physical VMs. The quota bounds sustained concurrency, not the
--     instantaneous VM count.
--   * A failed pause reverts pausing→active, re-entering the counted set.
--     That revert is exempt from the cap (see sandbox_quota_on_update): the
--     VM never stopped, so refusing the write can't reclaim anything — it
--     would only strand truth, and the reaper's revert path escalates a
--     failed revert to a terminal 'failed' on a healthy VM.
--   * A crash between BeginPause and the VMD pause leaves a running VM whose
--     row sits in 'pausing', now uncounted (before this migration the same
--     crash leaked the slot in the opposite direction: counted but stuck).
--     Either way the row is stranded transitional; the reconciler follow-up
--     that repairs transitional rows covers both.

BEGIN;

-- Block sandbox writes so no transition lands between backfill and trigger swap.
LOCK TABLE sandbox IN EXCLUSIVE MODE;

CREATE OR REPLACE FUNCTION sandbox_quota_on_insert() RETURNS trigger
    LANGUAGE plpgsql
AS $$
DECLARE
  new_count integer;
  effective_max integer;
BEGIN
  IF NEW.destroyed_at IS NOT NULL OR NEW.status IN ('failed', 'paused', 'pausing') THEN
    RETURN NEW;
  END IF;

  UPDATE team
  SET active_sandbox_count = active_sandbox_count + 1
  WHERE id = NEW.team_id
  RETURNING active_sandbox_count, max_sandboxes
  INTO new_count, effective_max;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'team % does not exist', NEW.team_id;
  END IF;

  IF new_count > effective_max THEN
    RAISE EXCEPTION 'sandbox quota exceeded (count=%, max=%)', new_count, effective_max
      USING ERRCODE = 'SS001';
  END IF;

  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION sandbox_quota_on_update() RETURNS trigger
    LANGUAGE plpgsql
AS $$
DECLARE
  was_counted boolean;
  is_counted boolean;
  new_count integer;
  effective_max integer;
BEGIN
  was_counted := (OLD.destroyed_at IS NULL AND OLD.status NOT IN ('failed', 'paused', 'pausing'));
  is_counted  := (NEW.destroyed_at IS NULL AND NEW.status NOT IN ('failed', 'paused', 'pausing'));

  IF was_counted AND NOT is_counted THEN
    UPDATE team
    SET active_sandbox_count = GREATEST(active_sandbox_count - 1, 0)
    WHERE id = NEW.team_id;
  ELSIF NOT was_counted AND is_counted THEN
    UPDATE team
    SET active_sandbox_count = active_sandbox_count + 1
    WHERE id = NEW.team_id
    RETURNING active_sandbox_count, max_sandboxes
    INTO new_count, effective_max;

    -- Genuine admissions (resume: paused→resuming) are capped like creation.
    -- A pause revert (pausing→active) is NOT: the VM never stopped, so the
    -- write only records reality. Blocking it would let the reaper mark a
    -- healthy VM 'failed' whenever a create raced into the freed slot —
    -- routine under auto-pause, the default lifecycle. The transient cap+1
    -- heals when the pause is retried.
    IF OLD.status <> 'pausing' AND new_count > effective_max THEN
      RAISE EXCEPTION 'sandbox quota exceeded (count=%, max=%)', new_count, effective_max
        USING ERRCODE = 'SS001';
    END IF;
  END IF;

  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION sandbox_quota_on_delete() RETURNS trigger
    LANGUAGE plpgsql
AS $$
BEGIN
  IF OLD.destroyed_at IS NULL AND OLD.status NOT IN ('failed', 'paused', 'pausing') THEN
    UPDATE team
    SET active_sandbox_count = GREATEST(active_sandbox_count - 1, 0)
    WHERE id = OLD.team_id;
  END IF;
  RETURN OLD;
END;
$$;

-- Recompute every team's counter under the new definition. Idempotent.
UPDATE team t
SET active_sandbox_count = COALESCE((
  SELECT COUNT(*)
  FROM sandbox s
  WHERE s.team_id = t.id
    AND s.destroyed_at IS NULL
    AND s.status NOT IN ('failed', 'paused', 'pausing')
), 0);

COMMIT;
