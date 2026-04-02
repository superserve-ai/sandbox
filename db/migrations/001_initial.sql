-- 001_initial.sql
-- Full schema for AgentBox platform

-- =============================================================================
-- Enums
-- =============================================================================

CREATE TYPE vm_status AS ENUM ('creating', 'running', 'sleeping', 'dead');
CREATE TYPE checkpoint_type AS ENUM ('auto', 'manual', 'named');

-- =============================================================================
-- Extensions
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- =============================================================================
-- Tables
-- =============================================================================

CREATE TABLE vms (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name            text NOT NULL,
    status          vm_status NOT NULL DEFAULT 'creating',
    vcpu_count      int NOT NULL,
    mem_size_mib    int NOT NULL,
    ip_address      inet,
    host_id         text,
    parent_vm_id    uuid REFERENCES vms(id),
    forked_from_checkpoint_id uuid,  -- FK added after checkpoints table
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    deleted_at      timestamptz,
    metadata        jsonb DEFAULT '{}',

    CONSTRAINT vms_vcpu_positive CHECK (vcpu_count > 0),
    CONSTRAINT vms_mem_positive CHECK (mem_size_mib > 0)
);

CREATE TABLE checkpoints (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    vm_id           uuid NOT NULL REFERENCES vms(id),
    name            text,
    type            checkpoint_type NOT NULL DEFAULT 'auto',
    size_bytes      bigint NOT NULL DEFAULT 0,
    delta_size_bytes bigint NOT NULL DEFAULT 0,
    storage_path    text NOT NULL,
    pinned          boolean NOT NULL DEFAULT false,
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz,

    CONSTRAINT checkpoints_size_non_negative CHECK (size_bytes >= 0),
    CONSTRAINT checkpoints_delta_size_non_negative CHECK (delta_size_bytes >= 0),
    CONSTRAINT checkpoints_unique_name_per_vm UNIQUE (vm_id, name)
);

-- Now add the deferred FK from vms to checkpoints
ALTER TABLE vms
    ADD CONSTRAINT fk_vms_forked_from_checkpoint
    FOREIGN KEY (forked_from_checkpoint_id) REFERENCES checkpoints(id);

CREATE TABLE forks (
    id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    source_vm_id         uuid NOT NULL REFERENCES vms(id),
    target_vm_id         uuid NOT NULL REFERENCES vms(id),
    source_checkpoint_id uuid NOT NULL REFERENCES checkpoints(id),
    created_at           timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT forks_source_ne_target CHECK (source_vm_id <> target_vm_id)
);

CREATE TABLE rollback_log (
    id                        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    vm_id                     uuid NOT NULL REFERENCES vms(id),
    from_checkpoint_id        uuid NOT NULL REFERENCES checkpoints(id),
    to_checkpoint_id          uuid NOT NULL REFERENCES checkpoints(id),
    pre_rollback_checkpoint_id uuid NOT NULL REFERENCES checkpoints(id),
    triggered_by              text,
    created_at                timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE exec_log (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    vm_id        uuid NOT NULL REFERENCES vms(id),
    command      text NOT NULL,
    exit_code    int,
    started_at   timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz
);

CREATE TABLE api_keys (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    key_hash   text NOT NULL UNIQUE,
    name       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz,
    revoked    boolean NOT NULL DEFAULT false
);

-- =============================================================================
-- Indexes
-- =============================================================================

-- VM lookups
CREATE INDEX idx_vms_status ON vms(status) WHERE deleted_at IS NULL;
CREATE INDEX idx_vms_parent_vm_id ON vms(parent_vm_id) WHERE parent_vm_id IS NOT NULL;
CREATE INDEX idx_vms_host_id ON vms(host_id) WHERE host_id IS NOT NULL;
CREATE INDEX idx_vms_deleted_at ON vms(deleted_at) WHERE deleted_at IS NOT NULL;

-- Checkpoint lookups
CREATE INDEX idx_checkpoints_vm_id_created_at ON checkpoints(vm_id, created_at DESC);
CREATE INDEX idx_checkpoints_expires_at ON checkpoints(expires_at) WHERE expires_at IS NOT NULL AND pinned = false;

-- Fork tree queries
CREATE INDEX idx_forks_source_vm_id ON forks(source_vm_id);
CREATE INDEX idx_forks_target_vm_id ON forks(target_vm_id);
CREATE INDEX idx_forks_source_checkpoint_id ON forks(source_checkpoint_id);

-- Rollback log
CREATE INDEX idx_rollback_log_vm_id ON rollback_log(vm_id, created_at DESC);

-- Exec log
CREATE INDEX idx_exec_log_vm_id ON exec_log(vm_id, started_at DESC);

-- API keys
CREATE INDEX idx_api_keys_key_hash ON api_keys(key_hash) WHERE revoked = false;
