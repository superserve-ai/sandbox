-- Backup coverage reported by hosts: one row per verified generation in
-- a cell's backup bucket. The uploader's durable notification outbox
-- delivers reports at least once, so writes are idempotent inserts keyed
-- by (owner, bucket, generation); redeliveries and out-of-order arrivals
-- change nothing. Coverage questions ("is this sandbox backed up, as of
-- when") become queries over completed_at instead of SSH sessions.
--
-- generation is the uploader's content-addressed key (sha256 hex), not
-- the snapshot table's per-sandbox counter: it names the object prefix
-- in the bucket, which is what restore tooling fetches.
--
-- files carries the generation's full manifest (name, size, sha256,
-- base dependency per file) as reported after upload verification, so
-- restore and GC can reason about a generation without listing the
-- bucket (hosts cannot list it, and the control plane should not need
-- to).

CREATE TABLE backup_generation (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    sandbox_id uuid REFERENCES sandbox(id) ON DELETE CASCADE,
    template_id uuid REFERENCES template(id) ON DELETE CASCADE,
    build_id text,
    generation text NOT NULL CHECK (generation ~ '^[0-9a-f]{64}$'),
    bucket text NOT NULL,
    completed_at timestamptz NOT NULL,
    reported_at timestamptz NOT NULL DEFAULT now(),
    files jsonb NOT NULL,
    CHECK (num_nonnulls(sandbox_id, template_id) = 1),
    CHECK (template_id IS NULL OR build_id IS NOT NULL)
);

CREATE UNIQUE INDEX backup_generation_sandbox_unique
    ON backup_generation (sandbox_id, bucket, generation)
    WHERE sandbox_id IS NOT NULL;

CREATE UNIQUE INDEX backup_generation_template_unique
    ON backup_generation (template_id, build_id, bucket, generation)
    WHERE template_id IS NOT NULL;

-- Latest-coverage lookups (alerting, backfill targeting) scan per
-- sandbox by recency.
CREATE INDEX backup_generation_sandbox_completed
    ON backup_generation (sandbox_id, completed_at DESC)
    WHERE sandbox_id IS NOT NULL;

-- Internal table (only the control plane touches it, over the direct DB
-- connection): RLS on with no policies, so the anon/authenticated roles
-- get no access. Same pattern as artifact_manifest.
ALTER TABLE backup_generation ENABLE ROW LEVEL SECURITY;
