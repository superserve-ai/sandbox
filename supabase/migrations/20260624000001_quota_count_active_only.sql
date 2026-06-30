-- Quota counts only sandboxes holding an active compute slot: paused no longer
-- counts against team.max_sandboxes. Counted = destroyed_at IS NULL AND status
-- NOT IN ('failed','paused') — new sandboxes insert as 'starting', so create
-- still enforces. Since paused frees a slot, the UPDATE trigger also caps resume
-- (paused→resuming), else a team could pause, create to the limit, then resume past it.

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
  IF NEW.destroyed_at IS NOT NULL OR NEW.status IN ('failed', 'paused') THEN
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
  was_counted := (OLD.destroyed_at IS NULL AND OLD.status NOT IN ('failed', 'paused'));
  is_counted  := (NEW.destroyed_at IS NULL AND NEW.status NOT IN ('failed', 'paused'));

  IF was_counted AND NOT is_counted THEN
    UPDATE team
    SET active_sandbox_count = GREATEST(active_sandbox_count - 1, 0)
    WHERE id = NEW.team_id;
  ELSIF NOT was_counted AND is_counted THEN
    -- Entering the counted set (resume) is capped like creation.
    UPDATE team
    SET active_sandbox_count = active_sandbox_count + 1
    WHERE id = NEW.team_id
    RETURNING active_sandbox_count, max_sandboxes
    INTO new_count, effective_max;

    IF new_count > effective_max THEN
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
  IF OLD.destroyed_at IS NULL AND OLD.status NOT IN ('failed', 'paused') THEN
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
    AND s.status NOT IN ('failed', 'paused')
), 0);

COMMIT;
