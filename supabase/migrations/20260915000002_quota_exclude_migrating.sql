-- A 'migrating' row is the operator's claim on a paused sandbox, not the
-- owner's usage: it stays outside the counted set like 'paused'. Its
-- activation is recorded, not admitted: the VM is already running and will
-- be paused again by the timeout reaper within a minute, so refusing the
-- write could not reclaim anything, only strand the row (the same reasoning
-- as the pause revert). The transient count heals on that pause.
--
-- Separate from the enum change: a new enum value cannot be referenced in
-- the transaction that adds it.

BEGIN;

CREATE OR REPLACE FUNCTION sandbox_quota_counted(p_destroyed_at timestamptz, p_status sandbox_status)
RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  SELECT p_destroyed_at IS NULL AND p_status NOT IN ('failed', 'paused', 'pausing', 'migrating')
$$;

CREATE OR REPLACE FUNCTION sandbox_quota_on_update() RETURNS trigger
    LANGUAGE plpgsql
AS $$
DECLARE
  was_counted boolean;
  is_counted boolean;
BEGIN
  was_counted := sandbox_quota_counted(OLD.destroyed_at, OLD.status);
  is_counted  := sandbox_quota_counted(NEW.destroyed_at, NEW.status);

  IF was_counted AND NOT is_counted THEN
    PERFORM sandbox_quota_release(NEW.team_id);
  ELSIF NOT was_counted AND is_counted THEN
    -- Genuine admissions (resume: paused->resuming) are capped like creation.
    -- A pause revert (pausing->active) is not: the VM never stopped, so the
    -- write only records reality. Blocking it would let the reaper mark a
    -- healthy VM 'failed' whenever a create raced into the freed slot —
    -- routine under auto-pause, the default lifecycle. The transient cap+1
    -- heals when the pause is retried. An operator's migration boot
    -- (migrating->active) is recorded the same way: the VM is up and about
    -- to be paused again.
    PERFORM sandbox_quota_admit(NEW.team_id, OLD.status NOT IN ('pausing', 'migrating'));
  END IF;

  RETURN NEW;
END;
$$;

COMMIT;
