-- Shard the per-team active-sandbox counter: the old single-row `UPDATE team
-- SET active_sandbox_count = ...` held the team row's lock until commit, so
-- concurrent creates for one team serialized single-file. Writes now land on
-- one of 16 random shard rows and enforcement reads SUM(shards) — lock-free
-- when far from the limit, serialized on an advisory lock and re-checked
-- exactly when near it.
--
-- Enforcement bound: fast-path admissions are invisible to concurrent boundary
-- checks until they commit, so exceeding max_sandboxes would require a single
-- fast-path INSERT to stay in flight while an entire margin's worth of
-- boundary admissions serially commit — practically unreachable. The margin
-- must exceed the maximum concurrent in-flight inserts (bounded by the API's
-- DB connection pools); the default 64 covers that with headroom and is
-- runtime-tunable: ALTER DATABASE postgres SET app.sandbox_quota_margin = '96'.
-- Teams whose max_sandboxes <= margin always take the exact path — identical
-- to the single-row behavior they had before.
--
-- team.active_sandbox_count is no longer written but stays in place, so
-- rollback is one reverse migration (restore the previous function bodies,
-- recompute the column from shard sums). Readers move to the
-- team_active_sandbox_counts view.

BEGIN;

-- Block counted-set transitions so nothing lands between backfill and the
-- trigger-function swap. Reads stay allowed.
LOCK TABLE sandbox IN EXCLUSIVE MODE;

CREATE TABLE IF NOT EXISTS team_sandbox_counter (
  team_id uuid     NOT NULL REFERENCES team(id) ON DELETE CASCADE,
  shard   smallint NOT NULL,
  cnt     integer  NOT NULL DEFAULT 0,
  PRIMARY KEY (team_id, shard)
);

-- Internal table: only the service role and trigger functions touch it.
ALTER TABLE team_sandbox_counter ENABLE ROW LEVEL SECURITY;

-- Individual shards may go negative (an increment lands on shard 3, the
-- matching decrement on shard 7); only the SUM is meaningful, floored at 0
-- like the old column was.
CREATE OR REPLACE VIEW team_active_sandbox_counts AS
SELECT team_id,
       GREATEST(COALESCE(SUM(cnt), 0), 0)::int AS active_sandbox_count
FROM team_sandbox_counter
GROUP BY team_id;

-- Seed every team's count onto shard 0; it spreads across shards with traffic.
INSERT INTO team_sandbox_counter (team_id, shard, cnt)
SELECT id, 0, active_sandbox_count
FROM team
WHERE active_sandbox_count > 0
ON CONFLICT (team_id, shard) DO NOTHING;

-- Admit one sandbox into the counted set. p_enforce=false records the
-- transition without the cap check (the pause-revert exemption: the VM never
-- stopped, refusing the write would only strand truth).
CREATE OR REPLACE FUNCTION sandbox_quota_admit(p_team uuid, p_enforce boolean)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
  lim    integer;
  total  integer;
  margin integer;
BEGIN
  SELECT max_sandboxes INTO lim FROM team WHERE id = p_team;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'team % does not exist', p_team;
  END IF;

  INSERT INTO team_sandbox_counter AS c (team_id, shard, cnt)
  VALUES (p_team, floor(random() * 16)::smallint, 1)
  ON CONFLICT (team_id, shard) DO UPDATE SET cnt = c.cnt + 1;

  IF NOT p_enforce THEN
    RETURN;
  END IF;

  margin := COALESCE(NULLIF(current_setting('app.sandbox_quota_margin', true), ''), '64')::integer;

  SELECT COALESCE(SUM(cnt), 0) INTO total FROM team_sandbox_counter WHERE team_id = p_team;
  IF total <= lim - margin THEN
    RETURN; -- fast path: no team-level serialization
  END IF;

  -- Near the limit: serialize this team's admissions and re-check exactly.
  -- xact-scoped (releases on commit/abort, pooler-safe); key namespaced away
  -- from the team-mutation advisory lock.
  PERFORM pg_advisory_xact_lock(hashtext('sandbox_quota:' || p_team::text));
  SELECT COALESCE(SUM(cnt), 0) INTO total FROM team_sandbox_counter WHERE team_id = p_team;
  IF total > lim THEN
    RAISE EXCEPTION 'sandbox quota exceeded (count=%, max=%)', total, lim
      USING ERRCODE = 'SS001';
  END IF;
END;
$$;

-- Release one sandbox from the counted set.
CREATE OR REPLACE FUNCTION sandbox_quota_release(p_team uuid)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO team_sandbox_counter AS c (team_id, shard, cnt)
  VALUES (p_team, floor(random() * 16)::smallint, -1)
  ON CONFLICT (team_id, shard) DO UPDATE SET cnt = c.cnt - 1;
END;
$$;

-- Trigger bodies swap to the sharded counter; trigger definitions (BEFORE
-- INSERT / AFTER UPDATE / AFTER DELETE and their WHEN clauses) are unchanged.
-- Counted set stays: destroyed_at IS NULL AND status NOT IN
-- ('failed','paused','pausing').

CREATE OR REPLACE FUNCTION sandbox_quota_on_insert() RETURNS trigger
    LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.destroyed_at IS NOT NULL OR NEW.status IN ('failed', 'paused', 'pausing') THEN
    RETURN NEW;
  END IF;
  PERFORM sandbox_quota_admit(NEW.team_id, true);
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION sandbox_quota_on_update() RETURNS trigger
    LANGUAGE plpgsql
AS $$
DECLARE
  was_counted boolean;
  is_counted boolean;
BEGIN
  was_counted := (OLD.destroyed_at IS NULL AND OLD.status NOT IN ('failed', 'paused', 'pausing'));
  is_counted  := (NEW.destroyed_at IS NULL AND NEW.status NOT IN ('failed', 'paused', 'pausing'));

  IF was_counted AND NOT is_counted THEN
    PERFORM sandbox_quota_release(NEW.team_id);
  ELSIF NOT was_counted AND is_counted THEN
    -- Genuine admissions (resume: paused->resuming) are capped like creation.
    -- A pause revert (pausing->active) is not: the VM never stopped, so the
    -- write only records reality. Blocking it would let the reaper mark a
    -- healthy VM 'failed' whenever a create raced into the freed slot —
    -- routine under auto-pause, the default lifecycle. The transient cap+1
    -- heals when the pause is retried.
    PERFORM sandbox_quota_admit(NEW.team_id, OLD.status <> 'pausing');
  END IF;

  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION sandbox_quota_on_delete() RETURNS trigger
    LANGUAGE plpgsql
AS $$
BEGIN
  IF OLD.destroyed_at IS NULL AND OLD.status NOT IN ('failed', 'paused', 'pausing') THEN
    PERFORM sandbox_quota_release(OLD.team_id);
  END IF;
  RETURN OLD;
END;
$$;

COMMIT;
