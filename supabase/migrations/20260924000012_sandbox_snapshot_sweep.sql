-- A capture whose answer was lost, or a delete the host did not confirm, is
-- settled by a sweep that must get past a host that does not answer: each
-- row carries the time it is next due, pushed out on every attempt. The
-- limit on captures a team may have in flight joins the other snapshot
-- limits, counted under the same team lock, so a burst cannot pass it.

BEGIN;

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '10s';

ALTER TABLE sandbox_snapshot
    ADD COLUMN IF NOT EXISTS sweep_after timestamptz NOT NULL DEFAULT now();

COMMENT ON COLUMN sandbox_snapshot.sweep_after IS
  'When the sweep next asks the host about a row still creating or deleting; pushed out on every attempt.';

CREATE INDEX IF NOT EXISTS sandbox_snapshot_sweep
    ON sandbox_snapshot (sweep_after)
    WHERE deleted_at IS NULL AND status IN ('creating', 'deleting');

ALTER TABLE team
    ADD COLUMN IF NOT EXISTS max_snapshots_in_flight int NOT NULL DEFAULT 4;

CREATE OR REPLACE FUNCTION sandbox_snapshot_quota_on_insert() RETURNS trigger
    LANGUAGE plpgsql
AS $$
DECLARE
    team_limit      int;
    sandbox_limit   int;
    in_flight_limit int;
    n               bigint;
BEGIN
    -- NO KEY UPDATE: excludes other snapshot inserts for the team but not the
    -- KEY SHARE locks sandbox create, pause and resume take through their
    -- foreign keys, so an in-flight capture never stalls them.
    SELECT max_snapshots, max_snapshots_per_sandbox, max_snapshots_in_flight
    INTO team_limit, sandbox_limit, in_flight_limit
    FROM team
    WHERE id = NEW.team_id
    FOR NO KEY UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'team % does not exist', NEW.team_id;
    END IF;

    -- An idempotent retry must reach the unique index, not the limits.
    IF NEW.idempotency_key IS NOT NULL AND EXISTS (
        SELECT 1 FROM sandbox_snapshot
        WHERE team_id = NEW.team_id
          AND sandbox_id = NEW.sandbox_id
          AND idempotency_key = NEW.idempotency_key
    ) THEN
        RETURN NEW;
    END IF;

    SELECT count(*) INTO n FROM sandbox_snapshot
    WHERE team_id = NEW.team_id AND deleted_at IS NULL AND status = 'creating';
    IF n >= in_flight_limit THEN
        RAISE EXCEPTION 'snapshots in flight limit reached for team (count=%, max=%)', n, in_flight_limit
            USING ERRCODE = 'SS003';
    END IF;

    SELECT count(*) INTO n FROM sandbox_snapshot
    WHERE team_id = NEW.team_id AND deleted_at IS NULL AND status IN ('creating', 'ready');
    IF n >= team_limit THEN
        RAISE EXCEPTION 'snapshot quota exceeded for team (count=%, max=%)', n, team_limit
            USING ERRCODE = 'SS002';
    END IF;

    SELECT count(*) INTO n FROM sandbox_snapshot
    WHERE sandbox_id = NEW.sandbox_id AND deleted_at IS NULL AND status IN ('creating', 'ready');
    IF n >= sandbox_limit THEN
        RAISE EXCEPTION 'snapshot quota exceeded for sandbox (count=%, max=%)', n, sandbox_limit
            USING ERRCODE = 'SS002';
    END IF;

    RETURN NEW;
END;
$$;

COMMIT;
