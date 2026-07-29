-- Expand the snapshot row shape in a short metadata-only transaction.
-- PostgreSQL 16 stores constant defaults in the catalog, so existing rows are
-- not rewritten while the ACCESS EXCLUSIVE lock is held.

BEGIN;

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

-- Old control planes finalize pause checkpoints with ON CONFLICT (sandbox_id).
-- Refuse to expand a drifted database unless the exact legacy conflict target
-- remains available for those writers.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_index i
        JOIN pg_class idx ON idx.oid = i.indexrelid
        JOIN pg_namespace ns ON ns.oid = idx.relnamespace
        WHERE ns.nspname = 'public'
          AND idx.relname = 'snapshot_sandbox_unique'
          AND i.indrelid = 'public.snapshot'::regclass
          AND i.indisunique
          AND i.indisvalid
          AND i.indisready
          AND i.indimmediate
          AND i.indpred IS NULL
          AND i.indnkeyatts = 1
          AND pg_get_indexdef(i.indexrelid, 1, true) = 'sandbox_id'
    ) THEN
        RAISE EXCEPTION
            'expand requires the legacy non-partial snapshot_sandbox_unique index';
    END IF;
END;
$$;

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
    ADD COLUMN template_id uuid,
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

COMMIT;
