-- Templates: reusable Firecracker rootfs+snapshot bundles. A template row
-- represents the user-facing artifact; the actual rootfs.ext4 + snapshot
-- live on the vmd host's local disk, paths recorded here. Sandboxes are
-- created from a template by restoring its snapshot (instead of the baked-in
-- default template).

-- Curated templates (python-3.11, node-22, etc.) are owned by a designated
-- "system team". Every user's list query unions their own team's templates
-- with the system team's — no separate visibility flag needed. The system
-- team is identified by SYSTEM_TEAM_ID in controlplane config; must point
-- to a real team row.

CREATE TYPE template_status AS ENUM ('pending', 'building', 'ready', 'failed');

CREATE TABLE template (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id         uuid NOT NULL REFERENCES team(id) ON DELETE CASCADE,
    alias           text NOT NULL,
    status          template_status NOT NULL DEFAULT 'pending',
    build_spec      jsonb NOT NULL,
    vcpu            int NOT NULL DEFAULT 1,
    memory_mib      int NOT NULL DEFAULT 1024,
    disk_mib        int NOT NULL DEFAULT 4096,
    rootfs_path     text,
    snapshot_path   text,
    mem_path        text,
    size_bytes      bigint,
    error_message   text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    built_at        timestamptz,
    deleted_at      timestamptz,

    CONSTRAINT template_alias_unique_per_team UNIQUE (team_id, alias),
    CONSTRAINT template_vcpu_range CHECK (vcpu BETWEEN 1 AND 4),
    CONSTRAINT template_memory_range CHECK (memory_mib BETWEEN 256 AND 4096),
    CONSTRAINT template_disk_range CHECK (disk_mib BETWEEN 1024 AND 8192),
    CONSTRAINT template_size_non_negative CHECK (size_bytes IS NULL OR size_bytes >= 0)
);

CREATE INDEX idx_template_team ON template(team_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_template_team_status ON template(team_id, status) WHERE deleted_at IS NULL;

ALTER TABLE sandbox ADD COLUMN template_id uuid REFERENCES template(id);
CREATE INDEX idx_sandbox_template ON sandbox(template_id) WHERE template_id IS NOT NULL;

ALTER TABLE template ENABLE ROW LEVEL SECURITY;
