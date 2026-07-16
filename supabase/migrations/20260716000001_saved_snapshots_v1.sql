-- Immutable, reusable sandbox snapshots. Runtime pause checkpoints continue to
-- use the existing row shape and remain replaceable one-per-sandbox; saved
-- snapshots are versioned rows with independent lifecycle and lineage.

BEGIN;

CREATE TYPE snapshot_kind AS ENUM ('runtime_checkpoint', 'saved');
CREATE TYPE snapshot_status AS ENUM (
    'creating', 'ready', 'unavailable', 'failed', 'deleting'
);

ALTER TABLE snapshot
    ADD COLUMN kind snapshot_kind NOT NULL DEFAULT 'runtime_checkpoint',
    ADD COLUMN status snapshot_status NOT NULL DEFAULT 'ready',
    ADD COLUMN name text,
    ADD COLUMN idempotency_key text,
    ADD COLUMN parent_snapshot_id uuid,
    ADD COLUMN source_status sandbox_status,
    ADD COLUMN template_id uuid REFERENCES template(id),
    ADD COLUMN template_snapshot_path text,
    ADD COLUMN template_mem_path text,
    ADD COLUMN base_path text,
    ADD COLUMN delta_path text,
    ADD COLUMN host_id text,
    ADD COLUMN vcpu_count integer,
    ADD COLUMN memory_mib integer,
    ADD COLUMN disk_mib integer,
    ADD COLUMN manifest_path text,
    ADD COLUMN manifest_digest text,
    ADD COLUMN artifact_metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN logical_size_bytes bigint NOT NULL DEFAULT 0,
    ADD COLUMN exclusive_size_bytes bigint NOT NULL DEFAULT 0,
    ADD COLUMN network_config jsonb,
    ADD COLUMN timeout_seconds integer,
    ADD COLUMN auto_delete_seconds integer,
    ADD COLUMN secret_bindings jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN secret_env_keys jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN failure_reason text,
    ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN finalized_at timestamptz,
    ADD COLUMN deleted_at timestamptz;

ALTER TABLE snapshot
    ADD CONSTRAINT snapshot_id_team_unique UNIQUE (id, team_id),
    ADD CONSTRAINT snapshot_name_valid
        CHECK (name IS NULL OR char_length(name) BETWEEN 1 AND 64),
    ADD CONSTRAINT snapshot_idempotency_key_valid
        CHECK (idempotency_key IS NULL
               OR char_length(idempotency_key) BETWEEN 1 AND 255),
    ADD CONSTRAINT snapshot_vcpu_positive
        CHECK (vcpu_count IS NULL OR vcpu_count > 0),
    ADD CONSTRAINT snapshot_memory_positive
        CHECK (memory_mib IS NULL OR memory_mib > 0),
    ADD CONSTRAINT snapshot_disk_positive
        CHECK (disk_mib IS NULL OR disk_mib > 0),
    ADD CONSTRAINT snapshot_logical_size_non_negative
        CHECK (logical_size_bytes >= 0),
    ADD CONSTRAINT snapshot_exclusive_size_non_negative
        CHECK (exclusive_size_bytes >= 0),
    ADD CONSTRAINT snapshot_artifact_metadata_object
        CHECK (jsonb_typeof(artifact_metadata) = 'object'),
    ADD CONSTRAINT snapshot_secret_bindings_array
        CHECK (jsonb_typeof(secret_bindings) = 'array'),
    ADD CONSTRAINT snapshot_secret_env_keys_array
        CHECK (jsonb_typeof(secret_env_keys) = 'array'
               AND jsonb_array_length(secret_env_keys) <= 256),
    ADD CONSTRAINT snapshot_runtime_shape
        CHECK (kind <> 'runtime_checkpoint'
               OR (status = 'ready'
                   AND parent_snapshot_id IS NULL
                   AND idempotency_key IS NULL
                   AND deleted_at IS NULL)),
    ADD CONSTRAINT snapshot_saved_source_shape
        CHECK (kind <> 'saved'
               OR (source_status IN ('active', 'paused')
                   AND host_id IS NOT NULL
                   AND host_id <> ''
                   AND vcpu_count IS NOT NULL
                   AND memory_mib IS NOT NULL
                   AND disk_mib IS NOT NULL)),
    ADD CONSTRAINT snapshot_ready_artifact_shape
        CHECK (kind <> 'saved' OR status <> 'ready'
               OR (path <> ''
                   AND mem_path IS NOT NULL
                   AND mem_path <> ''
                   AND manifest_path IS NOT NULL
                   AND manifest_path <> ''
                   AND manifest_digest ~ '^[0-9a-f]{64}$')),
    ADD CONSTRAINT snapshot_deleted_state
        CHECK (deleted_at IS NULL OR status = 'deleting'),
    ADD CONSTRAINT snapshot_parent_team_fk
        FOREIGN KEY (parent_snapshot_id, team_id)
        REFERENCES snapshot(id, team_id),
    ADD CONSTRAINT snapshot_source_sandbox_team_fk
        FOREIGN KEY (sandbox_id, team_id)
        REFERENCES sandbox(id, team_id);

DROP INDEX IF EXISTS snapshot_sandbox_unique;

CREATE UNIQUE INDEX snapshot_sandbox_runtime_unique
    ON snapshot (sandbox_id)
    WHERE kind = 'runtime_checkpoint';

CREATE UNIQUE INDEX snapshot_team_source_idempotency_unique
    ON snapshot (team_id, sandbox_id, idempotency_key)
    WHERE kind = 'saved' AND idempotency_key IS NOT NULL;

CREATE INDEX idx_snapshot_team_saved_created
    ON snapshot (team_id, created_at DESC, id DESC)
    WHERE kind = 'saved' AND deleted_at IS NULL;

CREATE INDEX idx_snapshot_source_saved_created
    ON snapshot (sandbox_id, created_at DESC, id DESC)
    WHERE kind = 'saved' AND deleted_at IS NULL;

CREATE INDEX idx_snapshot_parent_saved
    ON snapshot (parent_snapshot_id)
    WHERE kind = 'saved' AND deleted_at IS NULL;

CREATE INDEX idx_snapshot_saved_host
    ON snapshot (host_id, status)
    WHERE kind = 'saved' AND deleted_at IS NULL;

CREATE INDEX idx_snapshot_saved_reconcile
    ON snapshot (status, updated_at, id)
    WHERE kind = 'saved'
      AND deleted_at IS NULL
      AND status IN ('creating', 'deleting');

ALTER TABLE team
    ADD COLUMN max_snapshots integer NOT NULL DEFAULT 100,
    ADD COLUMN max_snapshots_per_sandbox integer NOT NULL DEFAULT 20,
    ADD COLUMN snapshot_storage_quota_bytes bigint,
    ADD COLUMN snapshot_storage_bytes bigint NOT NULL DEFAULT 0;

ALTER TABLE team
    ADD CONSTRAINT team_max_snapshots_positive CHECK (max_snapshots > 0),
    ADD CONSTRAINT team_max_snapshots_per_sandbox_positive
        CHECK (max_snapshots_per_sandbox > 0),
    ADD CONSTRAINT team_snapshot_storage_quota_non_negative
        CHECK (snapshot_storage_quota_bytes IS NULL
               OR snapshot_storage_quota_bytes >= 0),
    ADD CONSTRAINT team_snapshot_storage_non_negative
        CHECK (snapshot_storage_bytes >= 0);

INSERT INTO feature_flag (key, enabled, description)
VALUES (
    'sandbox_snapshots_v1',
    false,
    'Allow a team to capture immutable saved snapshots and create sandboxes from them.'
)
ON CONFLICT (key) DO NOTHING;

ALTER TABLE sandbox
    ADD COLUMN source_snapshot_id uuid,
    ADD COLUMN snapshot_operation_id uuid,
    ADD COLUMN snapshot_operation_started_at timestamptz,
    ADD COLUMN secret_env_keys jsonb NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE sandbox
    ADD CONSTRAINT sandbox_source_snapshot_team_fk
        FOREIGN KEY (source_snapshot_id, team_id)
        REFERENCES snapshot(id, team_id),
    ADD CONSTRAINT sandbox_snapshot_operation_team_fk
        FOREIGN KEY (snapshot_operation_id, team_id)
        REFERENCES snapshot(id, team_id)
        DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT sandbox_snapshot_operation_pair
        CHECK ((snapshot_operation_id IS NULL)
               = (snapshot_operation_started_at IS NULL)),
    ADD CONSTRAINT sandbox_secret_env_keys_array
        CHECK (jsonb_typeof(secret_env_keys) = 'array'
               AND jsonb_array_length(secret_env_keys) <= 256);

-- Seed scrub history for existing sandboxes. Detach operations after this
-- migration retain their key in sandbox.secret_env_keys, allowing a later
-- saved-snapshot fork to erase additive boxd defaults even when the binding is
-- no longer active at capture time.
UPDATE sandbox s
SET secret_env_keys = current_keys.keys
FROM (
    SELECT sandbox_id, jsonb_agg(env_key ORDER BY env_key) AS keys
    FROM sandbox_secret
    GROUP BY sandbox_id
) current_keys
WHERE s.id = current_keys.sandbox_id;

CREATE INDEX idx_sandbox_source_snapshot_pin
    ON sandbox (source_snapshot_id)
    WHERE source_snapshot_id IS NOT NULL;

CREATE INDEX idx_sandbox_destroyed_snapshot_pin
    ON sandbox (destroyed_at, id)
    WHERE source_snapshot_id IS NOT NULL AND destroyed_at IS NOT NULL;

CREATE INDEX idx_sandbox_snapshot_operation
    ON sandbox (snapshot_operation_started_at)
    WHERE snapshot_operation_id IS NOT NULL AND destroyed_at IS NULL;

-- Count admission is serialized on the team row. Creating, ready,
-- unavailable, and deleting rows consume the count until logical deletion;
-- failed captures do not prevent a retry with a new idempotency key.
CREATE OR REPLACE FUNCTION saved_snapshot_quota_on_insert() RETURNS trigger
    LANGUAGE plpgsql
AS $$
DECLARE
    team_count bigint;
    source_count bigint;
    team_limit integer;
    source_limit integer;
    storage_limit bigint;
    storage_usage bigint;
BEGIN
    IF NEW.kind <> 'saved'
       OR NEW.deleted_at IS NOT NULL
       OR NEW.status = 'failed' THEN
        RETURN NEW;
    END IF;

    SELECT max_snapshots, max_snapshots_per_sandbox,
           snapshot_storage_quota_bytes, snapshot_storage_bytes
    INTO team_limit, source_limit, storage_limit, storage_usage
    FROM team
    WHERE id = NEW.team_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'team % does not exist', NEW.team_id;
    END IF;

    -- Let a concurrent idempotent retry reach the unique constraint instead
    -- of being misreported as a quota error. The handler adopts the committed
    -- row after that unique violation.
    IF NEW.idempotency_key IS NOT NULL AND EXISTS (
        SELECT 1 FROM snapshot existing
        WHERE existing.team_id = NEW.team_id
          AND existing.sandbox_id = NEW.sandbox_id
          AND existing.kind = 'saved'
          AND existing.idempotency_key = NEW.idempotency_key
    ) THEN
        RETURN NEW;
    END IF;

    IF storage_limit IS NULL THEN
        RAISE EXCEPTION 'saved snapshot storage quota is not provisioned'
            USING ERRCODE = 'SS004';
    END IF;

    -- Reject before host capture when the team has no remaining byte of
    -- provisioned capacity. Finalization still admits the artifact's actual
    -- exclusive size for teams that have some capacity left.
    IF storage_usage >= storage_limit THEN
        RAISE EXCEPTION 'saved snapshot storage quota exhausted (usage=%, max=%)',
                        storage_usage, storage_limit
            USING ERRCODE = 'SS005';
    END IF;

    SELECT count(*) INTO team_count
    FROM snapshot
    WHERE team_id = NEW.team_id
      AND kind = 'saved'
      AND deleted_at IS NULL
      AND status <> 'failed';

    IF team_count >= team_limit THEN
        RAISE EXCEPTION 'saved snapshot team quota exceeded (count=%, max=%)',
                        team_count, team_limit
            USING ERRCODE = 'SS002';
    END IF;

    SELECT count(*) INTO source_count
    FROM snapshot
    WHERE sandbox_id = NEW.sandbox_id
      AND kind = 'saved'
      AND deleted_at IS NULL
      AND status <> 'failed';

    IF source_count >= source_limit THEN
        RAISE EXCEPTION 'saved snapshot source quota exceeded (count=%, max=%)',
                        source_count, source_limit
            USING ERRCODE = 'SS003';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_saved_snapshot_quota_on_insert
    BEFORE INSERT ON snapshot
    FOR EACH ROW
    EXECUTE FUNCTION saved_snapshot_quota_on_insert();

-- Saved snapshot identity, lineage, captured policy, and committed artifacts
-- are immutable. Only the forward lifecycle and its diagnostic timestamps may
-- change after insert.
CREATE OR REPLACE FUNCTION saved_snapshot_immutable_on_update() RETURNS trigger
    LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.kind IS DISTINCT FROM NEW.kind THEN
        RAISE EXCEPTION 'snapshot kind is immutable' USING ERRCODE = '23514';
    END IF;

    IF OLD.kind <> 'saved' THEN
        RETURN NEW;
    END IF;

    IF OLD.id IS DISTINCT FROM NEW.id
       OR OLD.sandbox_id IS DISTINCT FROM NEW.sandbox_id
       OR OLD.team_id IS DISTINCT FROM NEW.team_id
       OR OLD.name IS DISTINCT FROM NEW.name
       OR OLD.idempotency_key IS DISTINCT FROM NEW.idempotency_key
       OR OLD.parent_snapshot_id IS DISTINCT FROM NEW.parent_snapshot_id
       OR OLD.source_status IS DISTINCT FROM NEW.source_status
       OR OLD.template_id IS DISTINCT FROM NEW.template_id
       OR OLD.template_snapshot_path IS DISTINCT FROM NEW.template_snapshot_path
       OR OLD.template_mem_path IS DISTINCT FROM NEW.template_mem_path
       OR OLD.base_path IS DISTINCT FROM NEW.base_path
       OR OLD.delta_path IS DISTINCT FROM NEW.delta_path
       OR OLD.host_id IS DISTINCT FROM NEW.host_id
       OR OLD.vcpu_count IS DISTINCT FROM NEW.vcpu_count
       OR OLD.memory_mib IS DISTINCT FROM NEW.memory_mib
       OR OLD.disk_mib IS DISTINCT FROM NEW.disk_mib
       OR OLD.network_config IS DISTINCT FROM NEW.network_config
       OR OLD.timeout_seconds IS DISTINCT FROM NEW.timeout_seconds
       OR OLD.auto_delete_seconds IS DISTINCT FROM NEW.auto_delete_seconds
       OR OLD.secret_bindings IS DISTINCT FROM NEW.secret_bindings
       OR OLD.secret_env_keys IS DISTINCT FROM NEW.secret_env_keys
       OR OLD.trigger IS DISTINCT FROM NEW.trigger
       OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
        RAISE EXCEPTION 'saved snapshot captured fields are immutable'
            USING ERRCODE = '23514';
    END IF;

    IF (OLD.path IS DISTINCT FROM NEW.path
        OR OLD.mem_path IS DISTINCT FROM NEW.mem_path
        OR OLD.size_bytes IS DISTINCT FROM NEW.size_bytes
        OR OLD.manifest_path IS DISTINCT FROM NEW.manifest_path
        OR OLD.manifest_digest IS DISTINCT FROM NEW.manifest_digest
        OR OLD.artifact_metadata IS DISTINCT FROM NEW.artifact_metadata
        OR OLD.logical_size_bytes IS DISTINCT FROM NEW.logical_size_bytes
        OR OLD.exclusive_size_bytes IS DISTINCT FROM NEW.exclusive_size_bytes)
       AND NOT (OLD.status = 'creating' AND NEW.status IN ('ready', 'deleting')) THEN
        RAISE EXCEPTION 'saved snapshot artifacts are immutable after commit'
            USING ERRCODE = '23514';
    END IF;

    IF NOT (
        OLD.status = NEW.status
        OR (OLD.status = 'creating' AND NEW.status IN ('ready', 'failed', 'deleting'))
        OR (OLD.status = 'ready' AND NEW.status IN ('unavailable', 'deleting'))
        OR (OLD.status IN ('unavailable', 'failed') AND NEW.status = 'deleting')
    ) THEN
        RAISE EXCEPTION 'invalid saved snapshot status transition: % -> %',
                        OLD.status, NEW.status
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_saved_snapshot_immutable_on_update
    BEFORE UPDATE ON snapshot
    FOR EACH ROW
    EXECUTE FUNCTION saved_snapshot_immutable_on_update();

-- Shadow-only layer ownership and references. This is intentionally separate
-- from invoice/export tables. One layer is charged once to its team while any
-- sandbox or snapshot reference remains; fan-out copies references, not bytes.
CREATE TYPE snapshot_storage_layer_kind AS ENUM (
    'saved_snapshot', 'sandbox_generation', 'sandbox_writable'
);

CREATE TABLE snapshot_storage_layer (
    id bigserial PRIMARY KEY,
    team_id uuid NOT NULL REFERENCES team(id),
    kind snapshot_storage_layer_kind NOT NULL,
    owner_snapshot_id uuid,
    owner_sandbox_id uuid,
    retained_logical_size_bytes bigint NOT NULL DEFAULT 0,
    current_logical_size_bytes bigint NOT NULL DEFAULT 0,
    retained_exclusive_size_bytes bigint NOT NULL DEFAULT 0,
    current_exclusive_size_bytes bigint NOT NULL DEFAULT 0,
    shadow_only boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    ended_at timestamptz,
    CONSTRAINT snapshot_storage_layer_id_team_unique UNIQUE (id, team_id),
    CONSTRAINT snapshot_storage_layer_one_owner CHECK (
        (owner_snapshot_id IS NOT NULL)::integer
        + (owner_sandbox_id IS NOT NULL)::integer = 1
    ),
    CONSTRAINT snapshot_storage_layer_kind_owner CHECK (
        (kind = 'saved_snapshot' AND owner_snapshot_id IS NOT NULL)
        OR (kind IN ('sandbox_generation', 'sandbox_writable')
            AND owner_sandbox_id IS NOT NULL)
    ),
    CONSTRAINT snapshot_storage_layer_sizes_non_negative CHECK (
        retained_logical_size_bytes >= 0
        AND current_logical_size_bytes >= 0
        AND retained_exclusive_size_bytes >= 0
        AND current_exclusive_size_bytes >= 0
    ),
    CONSTRAINT snapshot_storage_layer_snapshot_team_fk
        FOREIGN KEY (owner_snapshot_id, team_id)
        REFERENCES snapshot(id, team_id),
    CONSTRAINT snapshot_storage_layer_sandbox_team_fk
        FOREIGN KEY (owner_sandbox_id, team_id)
        REFERENCES sandbox(id, team_id)
);

CREATE UNIQUE INDEX snapshot_storage_layer_snapshot_owner_unique
    ON snapshot_storage_layer (owner_snapshot_id)
    WHERE owner_snapshot_id IS NOT NULL;
-- A sandbox has exactly one mutable current generation, but may own many
-- immutable sealed generations retained by different snapshots/descendants.
CREATE UNIQUE INDEX snapshot_storage_layer_sandbox_current_owner_unique
    ON snapshot_storage_layer (owner_sandbox_id)
    WHERE owner_sandbox_id IS NOT NULL
      AND kind = 'sandbox_writable'
      AND ended_at IS NULL;
CREATE INDEX snapshot_storage_layer_team_active
    ON snapshot_storage_layer (team_id, id)
    WHERE ended_at IS NULL;

CREATE TABLE snapshot_storage_reference (
    id bigserial PRIMARY KEY,
    layer_id bigint NOT NULL,
    team_id uuid NOT NULL REFERENCES team(id),
    snapshot_id uuid,
    sandbox_id uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    released_at timestamptz,
    CONSTRAINT snapshot_storage_reference_one_resource CHECK (
        (snapshot_id IS NOT NULL)::integer
        + (sandbox_id IS NOT NULL)::integer = 1
    ),
    CONSTRAINT snapshot_storage_reference_layer_team_fk
        FOREIGN KEY (layer_id, team_id)
        REFERENCES snapshot_storage_layer(id, team_id),
    CONSTRAINT snapshot_storage_reference_snapshot_team_fk
        FOREIGN KEY (snapshot_id, team_id)
        REFERENCES snapshot(id, team_id),
    CONSTRAINT snapshot_storage_reference_sandbox_team_fk
        FOREIGN KEY (sandbox_id, team_id)
        REFERENCES sandbox(id, team_id)
);

CREATE UNIQUE INDEX snapshot_storage_reference_snapshot_active_unique
    ON snapshot_storage_reference (layer_id, snapshot_id)
    WHERE snapshot_id IS NOT NULL AND released_at IS NULL;
CREATE UNIQUE INDEX snapshot_storage_reference_sandbox_active_unique
    ON snapshot_storage_reference (layer_id, sandbox_id)
    WHERE sandbox_id IS NOT NULL AND released_at IS NULL;
CREATE INDEX snapshot_storage_reference_layer_active
    ON snapshot_storage_reference (layer_id)
    WHERE released_at IS NULL;

CREATE OR REPLACE FUNCTION snapshot_storage_layer_usage_on_write() RETURNS trigger
    LANGUAGE plpgsql
AS $$
DECLARE
    old_bytes bigint := 0;
    new_bytes bigint := 0;
    delta_bytes bigint;
    total_bytes bigint;
    quota_bytes bigint;
    owner_team_id uuid;
BEGIN
    IF TG_OP <> 'INSERT' AND OLD.ended_at IS NULL THEN
        old_bytes := OLD.retained_exclusive_size_bytes
                     + OLD.current_exclusive_size_bytes;
    END IF;

    IF TG_OP <> 'DELETE' AND NEW.ended_at IS NULL THEN
        new_bytes := NEW.retained_exclusive_size_bytes
                     + NEW.current_exclusive_size_bytes;
    END IF;

    delta_bytes := new_bytes - old_bytes;
    IF delta_bytes = 0 THEN
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
        RETURN NEW;
    END IF;

    owner_team_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.team_id ELSE NEW.team_id END;

    UPDATE team
    SET snapshot_storage_bytes = snapshot_storage_bytes + delta_bytes
    WHERE id = owner_team_id
    RETURNING snapshot_storage_bytes, snapshot_storage_quota_bytes
    INTO total_bytes, quota_bytes;

    -- Sandbox writes already exist by measurement time and cleanup artifacts
    -- may already exist after failed admission, so only a ready saved-snapshot
    -- layer is allowed to reject the transaction on quota.
    IF TG_OP <> 'DELETE'
       AND delta_bytes > 0
       AND NEW.kind = 'saved_snapshot'
       AND EXISTS (
           SELECT 1 FROM snapshot s
           WHERE s.id = NEW.owner_snapshot_id
             AND s.team_id = NEW.team_id
             AND s.status = 'ready'
             AND s.deleted_at IS NULL
       ) THEN
        IF quota_bytes IS NULL THEN
            RAISE EXCEPTION 'saved snapshot storage quota is not provisioned'
                USING ERRCODE = 'SS004';
        END IF;

        IF total_bytes > quota_bytes THEN
            RAISE EXCEPTION 'saved snapshot storage quota exceeded (usage=%, max=%)',
                            total_bytes, quota_bytes
                USING ERRCODE = 'SS005';
        END IF;
    END IF;

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_snapshot_storage_layer_usage_on_write
    BEFORE INSERT OR UPDATE OR DELETE ON snapshot_storage_layer
    FOR EACH ROW
    EXECUTE FUNCTION snapshot_storage_layer_usage_on_write();

-- Fold sealed source generations back into their live owner's mutable row
-- once no snapshot or descendant sandbox references them. Their extents become
-- source-exclusive again when the final external reflink disappears, so a
-- later full-inode FIEMAP measurement must replace this combined current value
-- rather than be added beside the old retained row. Callers may scope by one
-- owner (pause/capture reconciliation), a set of layers whose references were
-- just released (lifecycle triggers), or both. Requiring one scope prevents an
-- accidental team-wide sweep.
CREATE OR REPLACE FUNCTION snapshot_storage_fold_owner_only_generations(
    requested_team_id uuid,
    requested_owner_sandbox_id uuid DEFAULT NULL,
    candidate_layer_ids bigint[] DEFAULT NULL
) RETURNS bigint
    LANGUAGE plpgsql
AS $$
DECLARE
    generation snapshot_storage_layer%ROWTYPE;
    current_layer_id bigint;
    active_ref_count bigint;
    owner_ref_count bigint;
    affected_count bigint;
    folded_count bigint := 0;
BEGIN
    IF requested_owner_sandbox_id IS NULL
       AND candidate_layer_ids IS NULL THEN
        RETURN 0;
    END IF;
    IF candidate_layer_ids IS NOT NULL
       AND cardinality(candidate_layer_ids) = 0 THEN
        RETURN 0;
    END IF;

    -- Capture finalization takes the same sandbox row lock before sealing its
    -- writable generation. Lock every candidate owner in a stable order so a
    -- capture either publishes its new reference first or observes the fully
    -- folded current row; it can never observe a half-folded generation.
    PERFORM owner.id
    FROM sandbox owner
    WHERE owner.team_id = requested_team_id
      AND owner.destroyed_at IS NULL
      AND (requested_owner_sandbox_id IS NULL
           OR owner.id = requested_owner_sandbox_id)
      AND EXISTS (
          SELECT 1
          FROM snapshot_storage_layer layer
          WHERE layer.team_id = requested_team_id
            AND layer.owner_sandbox_id = owner.id
            AND layer.kind = 'sandbox_generation'
            AND layer.ended_at IS NULL
            AND (candidate_layer_ids IS NULL
                 OR layer.id = ANY(candidate_layer_ids))
      )
    ORDER BY owner.id
    FOR UPDATE;

    -- Lock candidate layers by ID. The active-reference predicate is checked
    -- again after their reference rows are locked; missing live owners/current
    -- rows are deliberately left retained (fail closed) rather than dropped.
    FOR generation IN
        SELECT layer.*
        FROM snapshot_storage_layer layer
        JOIN sandbox owner
          ON owner.id = layer.owner_sandbox_id
         AND owner.team_id = layer.team_id
        WHERE layer.team_id = requested_team_id
          AND layer.kind = 'sandbox_generation'
          AND layer.ended_at IS NULL
          AND owner.destroyed_at IS NULL
          AND (requested_owner_sandbox_id IS NULL
               OR layer.owner_sandbox_id = requested_owner_sandbox_id)
          AND (candidate_layer_ids IS NULL
               OR layer.id = ANY(candidate_layer_ids))
        ORDER BY layer.id
        FOR UPDATE OF layer
    LOOP
        SELECT current.id
        INTO current_layer_id
        FROM snapshot_storage_layer current
        WHERE current.team_id = requested_team_id
          AND current.owner_sandbox_id = generation.owner_sandbox_id
          AND current.kind = 'sandbox_writable'
          AND current.ended_at IS NULL
        FOR UPDATE;
        IF current_layer_id IS NULL THEN
            CONTINUE;
        END IF;

        PERFORM ref.id
        FROM snapshot_storage_reference ref
        WHERE ref.layer_id = generation.id
          AND ref.team_id = requested_team_id
          AND ref.released_at IS NULL
        ORDER BY ref.id
        FOR UPDATE;

        SELECT count(*),
               count(*) FILTER (
                   WHERE ref.snapshot_id IS NULL
                     AND ref.sandbox_id = generation.owner_sandbox_id
               )
        INTO active_ref_count, owner_ref_count
        FROM snapshot_storage_reference ref
        WHERE ref.layer_id = generation.id
          AND ref.team_id = requested_team_id
          AND ref.released_at IS NULL;
        IF active_ref_count <> 1 OR owner_ref_count <> 1 THEN
            CONTINUE;
        END IF;

        UPDATE snapshot_storage_layer current
        SET current_logical_size_bytes =
                current.current_logical_size_bytes
                + generation.retained_logical_size_bytes
                + generation.current_logical_size_bytes,
            current_exclusive_size_bytes =
                current.current_exclusive_size_bytes
                + generation.retained_exclusive_size_bytes
                + generation.current_exclusive_size_bytes,
            updated_at = now()
        WHERE current.id = current_layer_id
          AND current.team_id = requested_team_id
          AND current.kind = 'sandbox_writable'
          AND current.ended_at IS NULL;
        GET DIAGNOSTICS affected_count = ROW_COUNT;
        IF affected_count <> 1 THEN
            RAISE EXCEPTION 'owner-only generation has no live writable layer'
                USING ERRCODE = '23514';
        END IF;

        UPDATE snapshot_storage_reference ref
        SET released_at = now()
        WHERE ref.layer_id = generation.id
          AND ref.team_id = requested_team_id
          AND ref.snapshot_id IS NULL
          AND ref.sandbox_id = generation.owner_sandbox_id
          AND ref.released_at IS NULL;
        GET DIAGNOSTICS affected_count = ROW_COUNT;
        IF affected_count <> 1 THEN
            RAISE EXCEPTION 'owner-only generation reference changed during fold'
                USING ERRCODE = '23514';
        END IF;

        UPDATE snapshot_storage_layer layer
        SET ended_at = now(), updated_at = now()
        WHERE layer.id = generation.id
          AND layer.team_id = requested_team_id
          AND layer.kind = 'sandbox_generation'
          AND layer.ended_at IS NULL
          AND NOT EXISTS (
              SELECT 1
              FROM snapshot_storage_reference ref
              WHERE ref.layer_id = layer.id
                AND ref.team_id = layer.team_id
                AND ref.released_at IS NULL
          );
        GET DIAGNOSTICS affected_count = ROW_COUNT;
        IF affected_count <> 1 THEN
            RAISE EXCEPTION 'owner-only generation gained a reference during fold'
                USING ERRCODE = '23514';
        END IF;

        folded_count := folded_count + 1;
    END LOOP;
    RETURN folded_count;
END;
$$;

-- Reconcile a stable VMD full-inode measurement in one database transaction.
-- PL/pgSQL sequencing is intentional: an owner-only fold updates the current
-- row before the authoritative replacement, which PostgreSQL does not allow a
-- data-modifying CTE and its outer UPDATE to do to the same tuple.
CREATE OR REPLACE FUNCTION snapshot_storage_reconcile_writable_usage(
    requested_team_id uuid,
    requested_sandbox_id uuid,
    measured_logical_size_bytes bigint,
    measured_exclusive_size_bytes bigint
) RETURNS bigint
    LANGUAGE plpgsql
AS $$
DECLARE
    affected_count bigint;
BEGIN
    IF measured_logical_size_bytes < 0
       OR measured_exclusive_size_bytes < 0 THEN
        RAISE EXCEPTION 'writable-layer measurements must be non-negative'
            USING ERRCODE = '23514';
    END IF;

    PERFORM sandbox.id
    FROM sandbox
    WHERE sandbox.id = requested_sandbox_id
      AND sandbox.team_id = requested_team_id
      AND sandbox.destroyed_at IS NULL
    FOR UPDATE;
    IF NOT FOUND THEN
        RETURN 0;
    END IF;

    PERFORM snapshot_storage_fold_owner_only_generations(
        requested_team_id, requested_sandbox_id, NULL
    );

    UPDATE snapshot_storage_layer layer
    SET current_logical_size_bytes = measured_logical_size_bytes,
        current_exclusive_size_bytes = measured_exclusive_size_bytes,
        updated_at = now()
    WHERE layer.owner_sandbox_id = requested_sandbox_id
      AND layer.team_id = requested_team_id
      AND layer.kind = 'sandbox_writable'
      AND layer.ended_at IS NULL;
    GET DIAGNOSTICS affected_count = ROW_COUNT;
    RETURN affected_count;
END;
$$;

CREATE OR REPLACE FUNCTION snapshot_storage_snapshot_lifecycle() RETURNS trigger
    LANGUAGE plpgsql
AS $$
DECLARE
    source_layer_id bigint;
    snapshot_layer_id bigint;
    source_logical bigint;
    source_exclusive bigint;
    source_current_logical bigint := 0;
    source_current_exclusive bigint := 0;
    source_remaining_logical bigint := 0;
    source_remaining_exclusive bigint := 0;
    team_usage bigint;
    team_quota bigint;
    released_layer_ids bigint[];
BEGIN
    IF OLD.status = 'creating'
       AND NEW.status IN ('ready', 'deleting')
       AND NEW.finalized_at IS NOT NULL THEN
        source_logical := COALESCE(
            (NEW.artifact_metadata ->> 'source_logical_size_bytes')::bigint,
            0
        );
        source_exclusive := COALESCE(
            (NEW.artifact_metadata ->> 'source_exclusive_size_bytes')::bigint,
            0
        );

        -- A ready branch seals the source's current writable generation into
        -- its own immutable row. Snapshot references must never point at the
        -- replacement mutable row: otherwise later source writes would be
        -- charged and retained by an older snapshot that cannot reference
        -- those bytes. Cleanup-only artifacts never retain source generations
        -- because their reflinks are about to be discarded.
        IF NEW.status = 'ready' THEN
            -- Defensive repair for a final-reference release performed by an
            -- older writer: fold any owner-only generations before sealing the
            -- current row. The source lock held by finalization serializes this
            -- with lifecycle folding.
            PERFORM snapshot_storage_fold_owner_only_generations(
                NEW.team_id, NEW.sandbox_id, NULL
            );

            SELECT layer.id,
                   layer.current_logical_size_bytes,
                   layer.current_exclusive_size_bytes
            INTO source_layer_id,
                 source_current_logical,
                 source_current_exclusive
            FROM snapshot_storage_layer layer
            WHERE layer.owner_sandbox_id = NEW.sandbox_id
              AND layer.team_id = NEW.team_id
              AND layer.kind = 'sandbox_writable'
              AND layer.ended_at IS NULL
            FOR UPDATE;

            IF source_layer_id IS NULL THEN
                INSERT INTO snapshot_storage_layer (
                    team_id, kind, owner_sandbox_id,
                    retained_logical_size_bytes,
                    retained_exclusive_size_bytes
                ) VALUES (
                    NEW.team_id, 'sandbox_generation', NEW.sandbox_id,
                    source_logical, source_exclusive
                )
                RETURNING id INTO source_layer_id;
            ELSE
                -- The VMD source fields describe only bytes that this capture
                -- actually retained through reflink sharing. A prior writable
                -- measurement may also include source-only vmstate, sidecars,
                -- or copied-delta bytes. Carry that non-retained remainder into
                -- the replacement current generation instead of making it
                -- disappear until the next pause measurement.
                source_remaining_logical := GREATEST(
                    source_current_logical - source_logical, 0
                );
                source_remaining_exclusive := GREATEST(
                    source_current_exclusive - source_exclusive, 0
                );
                UPDATE snapshot_storage_layer
                SET kind = 'sandbox_generation',
                    retained_logical_size_bytes = source_logical,
                    retained_exclusive_size_bytes = source_exclusive,
                    current_logical_size_bytes = 0,
                    current_exclusive_size_bytes = 0,
                    updated_at = now()
                WHERE id = source_layer_id;
            END IF;

            INSERT INTO snapshot_storage_reference (
                layer_id, team_id, sandbox_id
            ) VALUES (source_layer_id, NEW.team_id, NEW.sandbox_id)
            ON CONFLICT (layer_id, sandbox_id)
                WHERE sandbox_id IS NOT NULL AND released_at IS NULL
            DO NOTHING;
        END IF;

        INSERT INTO snapshot_storage_layer (
            team_id, kind, owner_snapshot_id,
            retained_logical_size_bytes,
            retained_exclusive_size_bytes
        ) VALUES (
            NEW.team_id, 'saved_snapshot', NEW.id,
            NEW.logical_size_bytes, NEW.exclusive_size_bytes
        )
        ON CONFLICT (owner_snapshot_id)
            WHERE owner_snapshot_id IS NOT NULL
        DO UPDATE SET
            retained_logical_size_bytes = EXCLUDED.retained_logical_size_bytes,
            retained_exclusive_size_bytes = EXCLUDED.retained_exclusive_size_bytes,
            ended_at = NULL,
            updated_at = now()
        RETURNING id INTO snapshot_layer_id;

        INSERT INTO snapshot_storage_reference (
            layer_id, team_id, snapshot_id
        ) VALUES (snapshot_layer_id, NEW.team_id, NEW.id)
        ON CONFLICT (layer_id, snapshot_id)
            WHERE snapshot_id IS NOT NULL AND released_at IS NULL
        DO NOTHING;

        IF NEW.status = 'ready' THEN
            -- The source sandbox already references every immutable ancestor
            -- it needs. Copy that reference set to the new snapshot, including
            -- the source writable generation retained above.
            INSERT INTO snapshot_storage_reference (
                layer_id, team_id, snapshot_id
            )
            SELECT ref.layer_id, NEW.team_id, NEW.id
            FROM snapshot_storage_reference ref
            WHERE ref.sandbox_id = NEW.sandbox_id
              AND ref.team_id = NEW.team_id
              AND ref.released_at IS NULL
            ON CONFLICT (layer_id, snapshot_id)
                WHERE snapshot_id IS NOT NULL AND released_at IS NULL
            DO NOTHING;

            -- Start a new mutable generation only after copying the source's
            -- sealed/ancestor reference set to the snapshot. This row is
            -- referenced by the source sandbox alone until the next capture
            -- seals it.
            INSERT INTO snapshot_storage_layer (
                team_id, kind, owner_sandbox_id,
                current_logical_size_bytes,
                current_exclusive_size_bytes
            ) VALUES (
                NEW.team_id, 'sandbox_writable', NEW.sandbox_id,
                source_remaining_logical, source_remaining_exclusive
            )
            RETURNING id INTO source_layer_id;

            INSERT INTO snapshot_storage_reference (
                layer_id, team_id, sandbox_id
            ) VALUES (source_layer_id, NEW.team_id, NEW.sandbox_id);

            SELECT snapshot_storage_bytes, snapshot_storage_quota_bytes
            INTO team_usage, team_quota
            FROM team
            WHERE id = NEW.team_id
            FOR UPDATE;
            IF team_quota IS NULL THEN
                RAISE EXCEPTION 'saved snapshot storage quota is not provisioned'
                    USING ERRCODE = 'SS004';
            END IF;
            IF team_usage > team_quota THEN
                RAISE EXCEPTION 'saved snapshot storage quota exceeded (usage=%, max=%)',
                                team_usage, team_quota
                    USING ERRCODE = 'SS005';
            END IF;
        END IF;
    END IF;

    IF OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL THEN
        SELECT array_agg(DISTINCT ref.layer_id ORDER BY ref.layer_id)
        INTO released_layer_ids
        FROM snapshot_storage_reference ref
        WHERE ref.snapshot_id = NEW.id
          AND ref.team_id = NEW.team_id
          AND ref.released_at IS NULL;

        -- Acquire owner -> generation -> reference locks before releasing the
        -- target refs. Calling the fold once while those refs are still active
        -- normally makes no change, but establishes the same lock order used by
        -- concurrent capture finalization and prevents a source/ref deadlock.
        PERFORM snapshot_storage_fold_owner_only_generations(
            NEW.team_id, NULL, released_layer_ids
        );

        UPDATE snapshot_storage_reference
        SET released_at = now()
        WHERE snapshot_id = NEW.id
          AND team_id = NEW.team_id
          AND released_at IS NULL;

        PERFORM snapshot_storage_fold_owner_only_generations(
            NEW.team_id, NULL, released_layer_ids
        );

        UPDATE snapshot_storage_layer layer
        SET ended_at = now(), updated_at = now()
        WHERE layer.team_id = NEW.team_id
          AND layer.ended_at IS NULL
          AND NOT EXISTS (
              SELECT 1 FROM snapshot_storage_reference ref
              WHERE ref.layer_id = layer.id AND ref.released_at IS NULL
          );
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_snapshot_storage_snapshot_lifecycle
    AFTER UPDATE ON snapshot
    FOR EACH ROW
    WHEN (OLD.kind = 'saved')
    EXECUTE FUNCTION snapshot_storage_snapshot_lifecycle();

CREATE OR REPLACE FUNCTION snapshot_storage_sandbox_lifecycle() RETURNS trigger
    LANGUAGE plpgsql
AS $$
DECLARE
    writable_layer_id bigint;
    released_layer_ids bigint[];
BEGIN
    -- A fork's lineage is part of its immutable restore identity. The only
    -- supported mutation is releasing the pin after host teardown has made
    -- the sandbox terminal; otherwise the reference ledger could diverge
    -- from source_snapshot_id.
    IF TG_OP = 'UPDATE'
       AND OLD.source_snapshot_id IS DISTINCT FROM NEW.source_snapshot_id
       AND NOT (
           OLD.source_snapshot_id IS NOT NULL
           AND NEW.source_snapshot_id IS NULL
           AND NEW.destroyed_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'sandbox source snapshot is immutable while live'
            USING ERRCODE = '23514';
    END IF;

    IF TG_OP = 'INSERT' AND NEW.source_snapshot_id IS NOT NULL THEN
        INSERT INTO snapshot_storage_layer (
            team_id, kind, owner_sandbox_id
        ) VALUES (
            NEW.team_id, 'sandbox_writable', NEW.id
        )
        RETURNING id INTO writable_layer_id;

        INSERT INTO snapshot_storage_reference (
            layer_id, team_id, sandbox_id
        ) VALUES (writable_layer_id, NEW.team_id, NEW.id)
        ON CONFLICT (layer_id, sandbox_id)
            WHERE sandbox_id IS NOT NULL AND released_at IS NULL
        DO NOTHING;

        INSERT INTO snapshot_storage_reference (
            layer_id, team_id, sandbox_id
        )
        SELECT ref.layer_id, NEW.team_id, NEW.id
        FROM snapshot_storage_reference ref
        WHERE ref.snapshot_id = NEW.source_snapshot_id
          AND ref.team_id = NEW.team_id
          AND ref.released_at IS NULL
        ON CONFLICT (layer_id, sandbox_id)
            WHERE sandbox_id IS NOT NULL AND released_at IS NULL
        DO NOTHING;
    END IF;

    IF TG_OP = 'UPDATE' AND (
        (OLD.destroyed_at IS NULL AND NEW.destroyed_at IS NOT NULL
         AND NEW.source_snapshot_id IS NULL)
        OR (OLD.source_snapshot_id IS NOT NULL
            AND NEW.source_snapshot_id IS NULL
            AND NEW.destroyed_at IS NOT NULL)
    ) THEN
        SELECT array_agg(DISTINCT ref.layer_id ORDER BY ref.layer_id)
        INTO released_layer_ids
        FROM snapshot_storage_reference ref
        WHERE ref.sandbox_id = NEW.id
          AND ref.team_id = NEW.team_id
          AND ref.released_at IS NULL;

        -- Establish source-first locking before reference release; see the
        -- equivalent saved-snapshot lifecycle path above.
        PERFORM snapshot_storage_fold_owner_only_generations(
            NEW.team_id, NULL, released_layer_ids
        );

        UPDATE snapshot_storage_reference
        SET released_at = now()
        WHERE sandbox_id = NEW.id
          AND team_id = NEW.team_id
          AND released_at IS NULL;

        PERFORM snapshot_storage_fold_owner_only_generations(
            NEW.team_id, NULL, released_layer_ids
        );

        UPDATE snapshot_storage_layer layer
        SET ended_at = now(), updated_at = now()
        WHERE layer.team_id = NEW.team_id
          AND layer.ended_at IS NULL
          AND NOT EXISTS (
              SELECT 1 FROM snapshot_storage_reference ref
              WHERE ref.layer_id = layer.id AND ref.released_at IS NULL
          );
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_snapshot_storage_sandbox_insert
    AFTER INSERT ON sandbox
    FOR EACH ROW
    EXECUTE FUNCTION snapshot_storage_sandbox_lifecycle();

-- PostgreSQL runs same-kind triggers in name order. This storage trigger must
-- acquire any ancestor-owner sandbox locks before trg_sandbox_quota_on_update
-- acquires the team row; capture finalization uses the same sandbox -> team
-- order. The numeric prefix makes that lock order explicit and deadlock-free.
CREATE TRIGGER trg_00_snapshot_storage_sandbox_update
    AFTER UPDATE ON sandbox
    FOR EACH ROW
    EXECUTE FUNCTION snapshot_storage_sandbox_lifecycle();

-- Saved-snapshot forks are pinned to the artifact host. Serialize their
-- admission on that host row and account for both active and starting VMs so
-- a concurrent fan-out cannot overcommit stale capacity. This intentionally
-- guards the V1 host-local fork path; the general scheduler may adopt the same
-- resource-weighted admission in a later migration.
CREATE OR REPLACE FUNCTION admit_saved_snapshot_host(
    requested_host_id text,
    requested_vcpus integer,
    requested_memory_mib integer
) RETURNS boolean
    LANGUAGE plpgsql
AS $$
DECLARE
    max_vcpus bigint;
    max_memory_mib bigint;
    used_vcpus bigint;
    used_memory_mib bigint;
BEGIN
    SELECT capacity_vcpus, capacity_memory_mib
    INTO max_vcpus, max_memory_mib
    FROM host
    WHERE id = requested_host_id
      AND status = 'active'
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'saved snapshot host % is unavailable', requested_host_id
            USING ERRCODE = 'SS006';
    END IF;

    SELECT COALESCE(sum(vcpu_count), 0), COALESCE(sum(memory_mib), 0)
    INTO used_vcpus, used_memory_mib
    FROM sandbox
    WHERE host_id = requested_host_id
      -- Starting/restoring and resuming admissions are serialized on the host
      -- row. Pausing remains physically resident until VMD confirms the pause,
      -- so it cannot free capacity early.
      -- A live failed row may represent an ambiguous teardown whose host
      -- process could not be proven dead. Count it until destroyed_at is set
      -- so saved-snapshot admission cannot overcommit an orphaned VM.
      AND status IN ('active', 'starting', 'resuming', 'pausing', 'failed')
      AND destroyed_at IS NULL;

    IF used_vcpus + requested_vcpus > max_vcpus
       OR used_memory_mib + requested_memory_mib > max_memory_mib THEN
        RAISE EXCEPTION
            'saved snapshot host capacity exhausted (vcpus=%+%/%, memory_mib=%+%/%)',
            used_vcpus, requested_vcpus, max_vcpus,
            used_memory_mib, requested_memory_mib, max_memory_mib
            USING ERRCODE = 'SS006';
    END IF;

    RETURN true;
END;
$$;

COMMIT;
