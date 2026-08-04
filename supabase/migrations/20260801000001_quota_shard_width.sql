-- Widen the quota counter from 16 to 64 shards. Concurrent creates for one
-- team queue on shard row locks — each transaction holds its shard's row lock
-- until commit, so burst admissions serialize in chains of burst_size/16.
-- Widening the modulus cuts the expected chain depth 4x. Enforcement is
-- unchanged: it reads SUM over the team's shard rows, which is shard-count
-- agnostic (as are the drift check and the console's view reads). Rows for
-- shards 16-63 appear lazily on first use; a rollback to the narrower modulus
-- leaves them behind, still summed, so totals stay exact in both directions.
--
-- Only the modulus changes; the function bodies are otherwise verbatim from
-- the sharded-counter migration, which also documents why the shard choice
-- must stay per-transaction, not per-row.

BEGIN;

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
  VALUES (p_team, (txid_current() % 64)::smallint, 1)
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

CREATE OR REPLACE FUNCTION sandbox_quota_release(p_team uuid)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO team_sandbox_counter AS c (team_id, shard, cnt)
  VALUES (p_team, (txid_current() % 64)::smallint, -1)
  ON CONFLICT (team_id, shard) DO UPDATE SET cnt = c.cnt - 1;
END;
$$;

COMMIT;
