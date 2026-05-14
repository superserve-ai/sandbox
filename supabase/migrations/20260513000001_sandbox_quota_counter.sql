-- team.active_sandbox_count mirrors `count(*) from sandbox where
-- destroyed_at is null and status != 'failed'`. Triggers maintain it
-- in sync; the INSERT trigger raises SQLSTATE 'SS001' on quota exceed.

-- Wrap as a single tx so LOCK TABLE works under `supabase db push`
-- (it runs statements autocommit otherwise).
BEGIN;

-- Hold EXCLUSIVE on sandbox so concurrent INSERTs can't land between
-- the backfill SELECT and the trigger creation. Reads stay allowed.
LOCK TABLE sandbox IN EXCLUSIVE MODE;

ALTER TABLE team
  ADD COLUMN active_sandbox_count integer NOT NULL DEFAULT 0;

-- Backfill from existing data. Table is small in prod; one statement is fine.
UPDATE team t
SET active_sandbox_count = sub.cnt
FROM (
  SELECT team_id, COUNT(*)::int AS cnt
  FROM sandbox
  WHERE destroyed_at IS NULL AND status != 'failed'
  GROUP BY team_id
) sub
WHERE t.id = sub.team_id;

-- Make max_sandboxes the single source of truth (was COALESCEd in two places).
UPDATE team SET max_sandboxes = 50 WHERE max_sandboxes IS NULL;
ALTER TABLE team ALTER COLUMN max_sandboxes SET DEFAULT 50;
ALTER TABLE team ALTER COLUMN max_sandboxes SET NOT NULL;

-- System team's quota exemption is reconciled by the controlplane on startup.

CREATE OR REPLACE FUNCTION sandbox_quota_on_insert() RETURNS trigger
    LANGUAGE plpgsql
AS $$
DECLARE
  new_count integer;
  effective_max integer;
BEGIN
  IF NEW.destroyed_at IS NOT NULL OR NEW.status = 'failed' THEN
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

CREATE TRIGGER trg_sandbox_quota_on_insert
  BEFORE INSERT ON sandbox
  FOR EACH ROW
  EXECUTE FUNCTION sandbox_quota_on_insert();

CREATE OR REPLACE FUNCTION sandbox_quota_on_update() RETURNS trigger
    LANGUAGE plpgsql
AS $$
DECLARE
  was_active boolean;
  is_active boolean;
BEGIN
  was_active := (OLD.destroyed_at IS NULL AND OLD.status != 'failed');
  is_active := (NEW.destroyed_at IS NULL AND NEW.status != 'failed');

  IF was_active AND NOT is_active THEN
    UPDATE team
    SET active_sandbox_count = GREATEST(active_sandbox_count - 1, 0)
    WHERE id = NEW.team_id;
  ELSIF NOT was_active AND is_active THEN
    UPDATE team
    SET active_sandbox_count = active_sandbox_count + 1
    WHERE id = NEW.team_id;
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_sandbox_quota_on_update
  AFTER UPDATE ON sandbox
  FOR EACH ROW
  WHEN (OLD.destroyed_at IS DISTINCT FROM NEW.destroyed_at OR OLD.status IS DISTINCT FROM NEW.status)
  EXECUTE FUNCTION sandbox_quota_on_update();

CREATE OR REPLACE FUNCTION sandbox_quota_on_delete() RETURNS trigger
    LANGUAGE plpgsql
AS $$
BEGIN
  IF OLD.destroyed_at IS NULL AND OLD.status != 'failed' THEN
    UPDATE team
    SET active_sandbox_count = GREATEST(active_sandbox_count - 1, 0)
    WHERE id = OLD.team_id;
  END IF;
  RETURN OLD;
END;
$$;

CREATE TRIGGER trg_sandbox_quota_on_delete
  AFTER DELETE ON sandbox
  FOR EACH ROW
  EXECUTE FUNCTION sandbox_quota_on_delete();

COMMIT;
