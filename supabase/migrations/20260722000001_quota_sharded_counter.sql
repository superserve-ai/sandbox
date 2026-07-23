-- Shard the per-team active-sandbox counter: the old single-row `UPDATE team
-- SET active_sandbox_count = ...` held the team row's lock until commit, so
-- concurrent creates for one team serialized single-file. Writes now land on
-- one of 16 shard rows and enforcement reads the shard sum — lock-free when
-- far from the limit, serialized on an advisory lock and re-checked exactly
-- when near it.
--
-- Enforcement bound: fast-path admissions are invisible to each other until
-- they commit, so the margin must exceed the number of admissions that can
-- be in flight at once. The API's own connection pools do NOT bound that
-- (instances scale out, each with its own pool); the real cap is the
-- connection pooler's server pool size. Transaction duration stretches the
-- window too: an admission inside a multi-statement transaction stays
-- invisible until that transaction commits, so the bound assumes create
-- transactions are short-lived. The default margin of 128 covers both with
-- room for a substantial pooler resize; anyone raising the pooler pool size
-- past the margin must raise the margin first:
--   UPDATE sandbox_quota_config SET margin = 192;
-- A table read takes effect immediately on every session — a database-level
-- GUC would not (pooled sessions only merge those at connect time) — and a
-- mistyped value fails the UPDATE loudly instead of silently keeping the
-- old margin. Values below the floor read as the floor. Teams whose
-- max_sandboxes <= margin always take the exact path — identical to the
-- single-row behavior they had before.
--
-- team.active_sandbox_count is no longer written but stays in place, so
-- rollback is one reverse migration (restore the previous function bodies,
-- recompute the column from the counted set). Readers move to the
-- team_active_sandbox_counts view. The triggers alone cannot drift the sum
-- (admit and release share one predicate), but row surgery on sandbox can;
-- the control plane's quota watcher cross-checks the sum against a
-- same-snapshot recount and reports any mismatch, and the repair is
-- re-running this file's seed recount under the same table lock.

BEGIN;

-- Bound the wait for the table lock: while queued behind a long-running
-- sandbox writer, this LOCK would also block every new sandbox write behind
-- it. Better to abort and retry the push than stall creates platform-wide.
SET LOCAL lock_timeout = '5s';

-- Block counted-set transitions so nothing lands between backfill and the
-- trigger-function swap. Reads stay allowed.
LOCK TABLE sandbox IN EXCLUSIVE MODE;

-- fillfactor: every counted transition upserts one of at most 16 rows per
-- team, so pages fill with dead tuples fast; headroom keeps updates HOT so
-- the enforcement SUM scans ~16 live tuples instead of update chains.
CREATE TABLE IF NOT EXISTS team_sandbox_counter (
  team_id uuid     NOT NULL REFERENCES team(id) ON DELETE CASCADE,
  shard   smallint NOT NULL,
  cnt     integer  NOT NULL DEFAULT 0,
  PRIMARY KEY (team_id, shard)
) WITH (fillfactor = 50);

-- Internal table: only the service role and trigger functions touch it.
ALTER TABLE team_sandbox_counter ENABLE ROW LEVEL SECURITY;

-- The margin, tunable at runtime without a deploy (see header). Single row.
CREATE TABLE IF NOT EXISTS sandbox_quota_config (
  single_row boolean PRIMARY KEY DEFAULT true CHECK (single_row),
  margin     integer NOT NULL
);
ALTER TABLE sandbox_quota_config ENABLE ROW LEVEL SECURITY;
-- DO NOTHING deliberately: a re-apply must keep the operator's tuned margin.
INSERT INTO sandbox_quota_config (single_row, margin) VALUES (true, 128)
ON CONFLICT (single_row) DO NOTHING;

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

-- The floor keeps the margin knob one-directional: it can make enforcement
-- more conservative, but can never be set below plausible in-flight
-- concurrency and silently soften the hard limit.
CREATE OR REPLACE FUNCTION sandbox_quota_margin()
RETURNS integer LANGUAGE sql STABLE AS $$
  SELECT GREATEST(COALESCE((SELECT margin FROM sandbox_quota_config), 128), 64)
$$;

-- One team's count, via the view so the sum has exactly one definition.
CREATE OR REPLACE FUNCTION sandbox_quota_total(p_team uuid)
RETURNS integer LANGUAGE sql STABLE AS $$
  SELECT COALESCE(
    (SELECT active_sandbox_count FROM team_active_sandbox_counts WHERE team_id = p_team),
    0)
$$;

-- Seed with an exact recount of the counted set, not the old column — it was
-- clamp-protected rather than provably exact, which is why the previous quota
-- migrations also ended with a recount. Unconditional (delete + insert, not
-- upsert-skip) so a re-apply — roll-forward after the documented rollback, or
-- a table pre-created under older counted-set semantics — can never resume
-- enforcement from stale sums. The table lock makes this race-free: the
-- counter is only ever written from sandbox triggers, which the lock blocks.
DELETE FROM team_sandbox_counter;
INSERT INTO team_sandbox_counter (team_id, shard, cnt)
SELECT team_id, 0, COUNT(*)::int
FROM sandbox
WHERE sandbox_quota_counted(destroyed_at, status)
GROUP BY team_id;

-- Admit one sandbox into the counted set. p_enforce=false records the
-- transition without the cap check (the pause-revert exemption: the VM never
-- stopped, refusing the write would only strand truth).
--
-- The shard is chosen per transaction: a multi-row statement (e.g. a reaper
-- batch) then locks at most one shard row per team, so concurrent batches
-- can't hold-and-wait on each other's shards (random per-row choice
-- deadlocks them), while separate transactions spread uniformly — unlike
-- pg_backend_pid(), whose long-lived pooled backends can cluster mod 16.
CREATE OR REPLACE FUNCTION sandbox_quota_admit(p_team uuid, p_enforce boolean)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
  lim    integer;
  total  integer;
  margin integer;
BEGIN
  -- A missing team fails the FK here on the insert path; the explicit
  -- NOT FOUND guards below cover the conflict-update path, where no RI
  -- check runs (team_id is unchanged by the UPDATE).
  INSERT INTO team_sandbox_counter AS c (team_id, shard, cnt)
  VALUES (p_team, (txid_current() % 16)::smallint, 1)
  ON CONFLICT (team_id, shard) DO UPDATE SET cnt = c.cnt + 1;

  IF NOT p_enforce THEN
    RETURN;
  END IF;

  SELECT max_sandboxes INTO lim FROM team WHERE id = p_team;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'team % does not exist', p_team;
  END IF;

  margin := sandbox_quota_margin();

  -- The fast path only exists for teams whose limit exceeds the margin;
  -- for the rest the check below could never pass, so skip its SUM.
  IF lim > margin THEN
    total := sandbox_quota_total(p_team);
    IF total <= lim - margin THEN
      RETURN; -- fast path: no team-level serialization
    END IF;
  END IF;

  -- Near the limit: serialize this team's admissions and re-check exactly.
  -- xact-scoped (releases on commit/abort, pooler-safe). The two-argument
  -- lock form is a separate keyspace from every single-argument advisory
  -- lock in the schema, so a hash collision with an unrelated lock (team
  -- mutations, per-sandbox locks) cannot block admissions; the class hash
  -- partitions quota from any future two-argument user. The limit is
  -- re-read under the lock: it may have been lowered (abuse response)
  -- while this admission was queued. In practice the team row cannot
  -- vanish mid-admission — a team delete cascades into our locked shard
  -- row and blocks until we commit — but that protection is incidental to
  -- the FK's ON DELETE CASCADE, so the guard stays: an unguarded NULL
  -- limit would make the comparison NULL and silently skip enforcement.
  PERFORM pg_advisory_xact_lock(hashtext('sandbox_quota'), hashtext(p_team::text));
  SELECT max_sandboxes INTO lim FROM team WHERE id = p_team;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'team % does not exist', p_team;
  END IF;
  total := sandbox_quota_total(p_team);
  IF total > lim THEN
    RAISE EXCEPTION 'sandbox quota exceeded (count=%, max=%)', total, lim
      USING ERRCODE = 'SS001';
  END IF;
END;
$$;

-- Release one sandbox from the counted set. Same per-transaction shard
-- choice as admit, for the same batch-deadlock reason.
CREATE OR REPLACE FUNCTION sandbox_quota_release(p_team uuid)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO team_sandbox_counter AS c (team_id, shard, cnt)
  VALUES (p_team, (txid_current() % 16)::smallint, -1)
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

-- The column is frozen, not dropped, so rollback stays one migration; mark
-- it so a future reader (or cross-repo consumer) doesn't trust it live.
COMMENT ON COLUMN team.active_sandbox_count IS
  'Frozen at the sharded-counter migration; read team_active_sandbox_counts instead.';

COMMIT;
