-- Customer snapshots: point-in-time captures a new sandbox can be created from.
-- Kept apart from `snapshot`, the resume image overwritten on every pause.
-- Forks are independent copies, so a snapshot can be deleted at any time.
--
-- The sandbox index must be pre-built CONCURRENTLY by hand on a populated
-- database, as with the other sandbox indexes: the runner wraps this file in a
-- transaction, where CONCURRENTLY cannot run, and a plain build blocks sandbox
-- writes for the table scan. Run before merging:
--
--   ALTER TABLE sandbox ADD COLUMN IF NOT EXISTS source_snapshot_id uuid;
--   CREATE INDEX CONCURRENTLY IF NOT EXISTS sandbox_by_source_snapshot
--     ON sandbox (source_snapshot_id) WHERE source_snapshot_id IS NOT NULL;
--   SELECT indisvalid FROM pg_index
--   WHERE indexrelid = 'sandbox_by_source_snapshot'::regclass;
--
-- The column is added bare so the pre-build needs nothing else; the foreign
-- key to sandbox_snapshot is added below, once that table exists.

BEGIN;

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '10s';

CREATE TABLE IF NOT EXISTS sandbox_snapshot (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id         uuid NOT NULL REFERENCES team(id),
    sandbox_id      uuid NOT NULL,
    template_id     uuid REFERENCES template(id),
    kind            text NOT NULL CHECK (kind IN ('fs', 'mem+fs')),
    status          text NOT NULL DEFAULT 'creating'
                    CHECK (status IN ('creating', 'ready', 'failed', 'deleting')),
    name            text CHECK (name IS NULL OR char_length(name) BETWEEN 1 AND 64),
    idempotency_key text CHECK (idempotency_key IS NULL OR char_length(idempotency_key) BETWEEN 1 AND 255),
    host_id         text NOT NULL,
    vcpu_count      int NOT NULL CHECK (vcpu_count > 0),
    memory_mib      int NOT NULL CHECK (memory_mib > 0),
    disk_mib        int NOT NULL CHECK (disk_mib > 0),
    base_path       text NOT NULL,
    base_mem_path   text,
    snapshot_path   text,
    mem_path        text,
    overlay_path    text,
    size_bytes      bigint NOT NULL DEFAULT 0 CHECK (size_bytes >= 0),
    -- Settings a fork inherits, kept here because the source may be gone by then.
    timeout_seconds int,
    network_config  jsonb,
    secret_bindings jsonb NOT NULL DEFAULT '[]'::jsonb,
    -- What the memory image needs to load; a mismatch is refused, not attempted.
    fc_build_sha    text,
    guest_kernel    text,
    snapshot_format text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    ready_at        timestamptz,
    deleted_at      timestamptz,

    -- The source sandbox belongs to the same team, and a fork's pointer can
    -- only name a snapshot of its own team.
    FOREIGN KEY (sandbox_id, team_id) REFERENCES sandbox(id, team_id),
    UNIQUE (id, team_id),

    -- Deletion is the only way out: a deleted row was in deleting first.
    CONSTRAINT sandbox_snapshot_deleted_was_deleting CHECK (
        deleted_at IS NULL OR status = 'deleting'
    ),
    -- A ready row names every artifact its kind needs.
    CONSTRAINT sandbox_snapshot_ready_has_artifacts CHECK (
        status <> 'ready'
        OR (overlay_path IS NOT NULL
            AND (kind = 'fs' OR (snapshot_path IS NOT NULL AND mem_path IS NOT NULL)))
    )
);

ALTER TABLE sandbox_snapshot ENABLE ROW LEVEL SECURITY;

COMMENT ON COLUMN sandbox_snapshot.sandbox_id IS
  'Sandbox the snapshot was captured from. Kept after that sandbox is destroyed.';
COMMENT ON COLUMN sandbox_snapshot.host_id IS
  'Host holding the artifacts; forks run there.';
COMMENT ON COLUMN sandbox_snapshot.base_path IS
  'Template base image the overlay sits on. Pins the template build while the snapshot exists.';
COMMENT ON COLUMN sandbox_snapshot.base_mem_path IS
  'Template memory image the memory diff layers on; NULL for a full image or an fs snapshot.';
COMMENT ON COLUMN sandbox_snapshot.size_bytes IS
  'Bytes the snapshot uniquely holds on disk, for metering; 0 until ready.';
COMMENT ON COLUMN sandbox_snapshot.secret_bindings IS
  'Array of {env_key, secret_id} the source had at capture; a fork re-binds by secret_id with fresh tokens.';
COMMENT ON COLUMN sandbox_snapshot.snapshot_format IS
  'Firecracker snapshot format version the memory image was written with; NULL for an fs snapshot.';

CREATE UNIQUE INDEX IF NOT EXISTS sandbox_snapshot_idempotency
    ON sandbox_snapshot (team_id, sandbox_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

CREATE INDEX IF NOT EXISTS sandbox_snapshot_by_sandbox
    ON sandbox_snapshot (sandbox_id, created_at DESC)
    WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS sandbox_snapshot_by_team
    ON sandbox_snapshot (team_id, created_at DESC)
    WHERE deleted_at IS NULL;

-- The quota counts run under the team lock on every capture; these cover
-- exactly the counted rows so failed captures never widen the scan.
CREATE INDEX IF NOT EXISTS sandbox_snapshot_quota_team
    ON sandbox_snapshot (team_id)
    WHERE deleted_at IS NULL AND status IN ('creating', 'ready');

CREATE INDEX IF NOT EXISTS sandbox_snapshot_quota_sandbox
    ON sandbox_snapshot (sandbox_id)
    WHERE deleted_at IS NULL AND status IN ('creating', 'ready');

-- Every sandbox destroy asks whether its build is still referenced.
CREATE INDEX IF NOT EXISTS sandbox_snapshot_base_path
    ON sandbox_snapshot (base_path)
    WHERE deleted_at IS NULL AND status IN ('creating', 'ready');

ALTER TABLE sandbox
    ADD COLUMN IF NOT EXISTS source_snapshot_id uuid;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'sandbox_source_snapshot_fk') THEN
    ALTER TABLE sandbox
      ADD CONSTRAINT sandbox_source_snapshot_fk
      FOREIGN KEY (source_snapshot_id, team_id) REFERENCES sandbox_snapshot(id, team_id);
  END IF;
END $$;

COMMENT ON COLUMN sandbox.source_snapshot_id IS
  'Snapshot this sandbox was created from; NULL when created from a template.';

-- IF NOT EXISTS matches by name only; an interrupted concurrent pre-build
-- leaves an INVALID index it would silently keep.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_index
    WHERE indexrelid = to_regclass('public.sandbox_by_source_snapshot')
      AND NOT indisvalid
  ) THEN
    RAISE EXCEPTION 'sandbox_by_source_snapshot exists but is INVALID; DROP INDEX it, re-run the concurrent pre-build, then retry';
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS sandbox_by_source_snapshot
    ON sandbox (source_snapshot_id)
    WHERE source_snapshot_id IS NOT NULL;

ALTER TABLE team
    ADD COLUMN IF NOT EXISTS max_snapshots int NOT NULL DEFAULT 100,
    ADD COLUMN IF NOT EXISTS max_snapshots_per_sandbox int NOT NULL DEFAULT 20;

-- Count quota, serialized on the team row like sandbox_quota_on_insert.
-- Only creating and ready rows count: a failed capture never blocks a retry,
-- and a row being deleted has already given its slot back. deleted_at IS NULL
-- is implied by the status but names the partial indexes' predicate.
CREATE OR REPLACE FUNCTION sandbox_snapshot_quota_on_insert() RETURNS trigger
    LANGUAGE plpgsql
AS $$
DECLARE
    team_limit    int;
    sandbox_limit int;
    n             bigint;
BEGIN
    SELECT max_snapshots, max_snapshots_per_sandbox
    INTO team_limit, sandbox_limit
    FROM team
    WHERE id = NEW.team_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'team % does not exist', NEW.team_id;
    END IF;

    -- An idempotent retry must reach the unique index, not the quota.
    IF NEW.idempotency_key IS NOT NULL AND EXISTS (
        SELECT 1 FROM sandbox_snapshot
        WHERE team_id = NEW.team_id
          AND sandbox_id = NEW.sandbox_id
          AND idempotency_key = NEW.idempotency_key
    ) THEN
        RETURN NEW;
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

DROP TRIGGER IF EXISTS trg_sandbox_snapshot_quota ON sandbox_snapshot;
CREATE TRIGGER trg_sandbox_snapshot_quota
    BEFORE INSERT ON sandbox_snapshot
    FOR EACH ROW EXECUTE FUNCTION sandbox_snapshot_quota_on_insert();

-- Failed rows leave the quota count and deletion is terminal, so neither
-- ever comes back: the only way to a live row is an insert through the quota trigger.
CREATE OR REPLACE FUNCTION sandbox_snapshot_no_revive() RETURNS trigger
    LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.status = 'failed' AND NEW.status NOT IN ('failed', 'deleting') THEN
        RAISE EXCEPTION 'snapshot % failed and cannot become %', OLD.id, NEW.status;
    END IF;
    IF OLD.status = 'deleting' AND NEW.status <> 'deleting' THEN
        RAISE EXCEPTION 'snapshot % is being deleted and cannot become %', OLD.id, NEW.status;
    END IF;
    IF OLD.deleted_at IS NOT NULL AND NEW.deleted_at IS NULL THEN
        RAISE EXCEPTION 'snapshot % is deleted and cannot be restored', OLD.id;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_sandbox_snapshot_no_revive ON sandbox_snapshot;
CREATE TRIGGER trg_sandbox_snapshot_no_revive
    BEFORE UPDATE ON sandbox_snapshot
    FOR EACH ROW EXECUTE FUNCTION sandbox_snapshot_no_revive();

COMMIT;
