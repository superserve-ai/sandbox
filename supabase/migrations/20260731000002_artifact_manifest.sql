-- Per-file integrity manifest for durable sandbox artifacts.
--
-- One row per artifact file per snapshot, keyed on snapshot_id so history
-- keys stay correct when snapshots become per-generation rows (today the
-- FinalizePause upsert reuses one snapshot row per sandbox; manifest rows
-- for that row are replaced on each pause). Template artifact manifests
-- reuse this table later via a nullable template reference; the CHECK
-- keeps every row attached to exactly one parent kind.
--
-- base_path records an overlay's restore dependency (e.g. a sandbox rootfs
-- overlay over its template base.ext4): backup verification and GC must
-- treat the pair as a unit.

CREATE TABLE artifact_manifest (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    snapshot_id uuid REFERENCES snapshot(id) ON DELETE CASCADE,
    template_id uuid REFERENCES template(id) ON DELETE CASCADE,
    file_name text NOT NULL,
    path text NOT NULL,
    size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
    sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    base_path text,
    guest_kernel text,
    vmd_version text,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (num_nonnulls(snapshot_id, template_id) = 1)
);

CREATE UNIQUE INDEX artifact_manifest_snapshot_file
    ON artifact_manifest (snapshot_id, file_name)
    WHERE snapshot_id IS NOT NULL;

CREATE UNIQUE INDEX artifact_manifest_template_file
    ON artifact_manifest (template_id, file_name)
    WHERE template_id IS NOT NULL;

-- Internal table (only the control plane touches it, over the direct DB
-- connection): RLS on with no policies, so the anon/authenticated roles get
-- no access. Same pattern as quota_alert_state.
ALTER TABLE artifact_manifest ENABLE ROW LEVEL SECURITY;
