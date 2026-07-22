-- Shard the per-team active-sandbox counter: the old single-row `UPDATE team
-- SET active_sandbox_count = ...` held the team row's lock until commit, so
-- concurrent creates for one team serialized single-file. Writes now land on
-- one of 16 shard rows and enforcement reads the shard sum — lock-free when
-- far from the limit, serialized on an advisory lock and re-checked exactly
-- when near it.
--
-- Enforcement bound: fast-path admissions are invisible to concurrent boundary
-- checks until they commit, so exceeding max_sandboxes would require a single
-- fast-path INSERT to stay in flight while an entire margin's worth of
-- boundary admissions serially commit — practically unreachable. The margin
-- must exceed the maximum concurrent in-flight inserts (bounded by the API's
-- DB connection pools); the default 64 covers that with headroom and is
-- runtime-tunable: ALTER DATABASE postgres SET app.sandbox_quota_margin = '96'
-- (invalid or non-positive values fall back to the default). Teams whose
-- max_sandboxes <= margin always take the exact path — identical to the
-- single-row behavior they had before.
--
-- team.active_sandbox_count is no longer written but stays in place, so
-- rollback is one reverse migration (restore the previous function bodies,
-- recompute the column from shard sums). Readers move to the
-- team_active_sandbox_counts view.

BEGIN;

-- Bound the wait for the table lock: while queued behind a long-running
-- sandbox writer, this LOCK would also block every new sandbox write behind
-- it. Better to abort and retry the push than stall creates platform-wide.
SET LOCAL lock_timeout = '5s';

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
-- like the old column was. security_invoker so the underlying table's RLS
-- applies to callers — a default (owner-rights) view in the exposed schema
-- would let API-key holders read every team's counts.
CREATE OR REPLACE VIEW team_active_sandbox_counts
WITH (security_invoker = true) AS
SELECT team_id,
       GREATEST(COALESCE(SUM(cnt), 0), 0)::int AS active_sandbox_count
FROM team_sandbox_counter
GROUP BY team_id;

-- Single definition of the counted set. The last three quota migrations each
-- existed to edit this predicate; a missed copy in one trigger body would make
-- admit and release disagree and drift the counter permanently.
CREATE OR REPLACE FUNCTION sandbox_quota_counted(p_destroyed_at timestamptz, p_status sandbox_status)
RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  SELECT p_destroyed_at IS NULL AND p_status NOT IN ('failed', 'paused', 'pausing')
$$;

-- The fast-path margin, tunable at runtime without a deploy. Defensive parse:
-- a mistyped ALTER DATABASE value must not turn every create into an error,
-- and a negative value must not silently widen the fast path past the limit.
CREATE OR REPLACE FUNCTION sandbox_quota_margin()
RETURNS integer LANGUAGE plpgsql STABLE AS $$
DECLARE
  raw text;
BEGIN
  raw := NULLIF(current_setting('app.sandbox_quota_margin', true), '');
  IF raw IS NULL THEN
    RETURN 64;
  END IF;
  BEGIN
    RETURN GREATEST(raw::integer, 1);
  EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN
    RETURN 64;
  END;
END;
$$;

-- Seed shard 0 with an exact recount of the counted set, not the old column —
-- it was clamp-protected rather than provably exact, which is why the previous
-- quota migrations also ended with a recount. The table lock makes this race-free.
INSERT INTO team_sandbox_counter (team_id, shard, cnt)
SELECT team_id, 0, COUNT(*)::int
FROM sandbox
WHERE sandbox_quota_counted(destroyed_at, status)
GROUP BY team_id
ON CONFLICT (team_id, shard) DO NOTHING;

-- Admit one sandbox into the counted set. p_enforce=false records the
-- transition without the cap check (the pause-revert exemption: the VM never
-- stopped, refusing the write would only strand truth).
--
-- The shard is chosen per backend, not per row: a multi-row statement (e.g. a
-- reaper batch) then locks at most one shard row per team, so concurrent
-- batches can't hold-and-wait on each other's shards (random per-row choice
-- deadlocks them), while concurrent backends still spread. Enforcement sums
-- are floored at 0 so a drifted negative sum can never widen a team's quota.
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
  VALUES (p_team, (pg_backend_pid() % 16)::smallint, 1)
  ON CONFLICT (team_id, shard) DO UPDATE SET cnt = c.cnt + 1;

  IF NOT p_enforce THEN
    RETURN;
  END IF;

  margin := sandbox_quota_margin();

  -- The fast path only exists for teams whose limit exceeds the margin;
  -- for the rest the check below could never pass, so skip its SUM.
  IF lim > margin THEN
    SELECT GREATEST(COALESCE(SUM(cnt), 0), 0) INTO total
    FROM team_sandbox_counter WHERE team_id = p_team;
    IF total <= lim - margin THEN
      RETURN; -- fast path: no team-level serialization
    END IF;
  END IF;

  -- Near the limit: serialize this team's admissions and re-check exactly.
  -- xact-scoped (releases on commit/abort, pooler-safe); key namespaced away
  -- from the team-mutation advisory lock. The limit is re-read under the lock:
  -- it may have been lowered (abuse response) while this admission was queued,
  -- and the team row cannot vanish — the shard insert's FK holds KEY SHARE.
  PERFORM pg_advisory_xact_lock(hashtext('sandbox_quota:' || p_team::text));
  SELECT max_sandboxes INTO lim FROM team WHERE id = p_team;
  SELECT GREATEST(COALESCE(SUM(cnt), 0), 0) INTO total
  FROM team_sandbox_counter WHERE team_id = p_team;
  IF total > lim THEN
    RAISE EXCEPTION 'sandbox quota exceeded (count=%, max=%)', total, lim
      USING ERRCODE = 'SS001';
  END IF;
END;
$$;

-- Release one sandbox from the counted set. Same per-backend shard choice as
-- admit, for the same batch-deadlock reason.
CREATE OR REPLACE FUNCTION sandbox_quota_release(p_team uuid)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO team_sandbox_counter AS c (team_id, shard, cnt)
  VALUES (p_team, (pg_backend_pid() % 16)::smallint, -1)
  ON CONFLICT (team_id, shard) DO UPDATE SET cnt = c.cnt - 1;
END;
$$;

-- Trigger bodies swap to the sharded counter; trigger definitions (BEFORE
-- INSERT / AFTER UPDATE / AFTER DELETE and their WHEN clauses) are unchanged.

CREATE OR REPLACE FUNCTION sandbox_quota_on_insert() RETURNS trigger
    LANGUAGE plpgsql
AS $$
BEGIN
  IF NOT sandbox_quota_counted(NEW.destroyed_at, NEW.status) THEN
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
  IF sandbox_quota_counted(OLD.destroyed_at, OLD.status) THEN
    PERFORM sandbox_quota_release(OLD.team_id);
  END IF;
  RETURN OLD;
END;
$$;

COMMIT;
