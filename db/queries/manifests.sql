-- name: ReplaceSnapshotManifestEntry :exec
-- Upsert one manifest row for a snapshot. The pause path replaces the whole
-- set for a snapshot (same file names each pause), so per-file upsert keyed
-- on (snapshot_id, file_name) converges without a separate delete pass.
INSERT INTO artifact_manifest (snapshot_id, file_name, path, size_bytes, sha256, base_path)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (snapshot_id, file_name) WHERE snapshot_id IS NOT NULL
DO UPDATE SET
    path = EXCLUDED.path,
    size_bytes = EXCLUDED.size_bytes,
    sha256 = EXCLUDED.sha256,
    base_path = EXCLUDED.base_path,
    created_at = now();

-- name: ListSnapshotManifest :many
SELECT * FROM artifact_manifest
WHERE snapshot_id = $1
ORDER BY file_name;

-- name: DeleteSnapshotManifest :exec
DELETE FROM artifact_manifest WHERE snapshot_id = $1;
