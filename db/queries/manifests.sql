-- name: ReplaceSnapshotManifest :exec
-- Atomically replace a snapshot's entire manifest set. Upsert the fresh
-- entries, then delete any row the fresh set no longer contains: a re-pause
-- that hashes fewer files than the previous pause (e.g. one hash failed)
-- must not leave the old row behind looking current, because the artifact
-- content it describes changed with the new pause. Single statement, so
-- there is no window with a half-replaced set. An empty fresh set clears
-- the snapshot's manifest entirely.
WITH fresh AS (
    SELECT unnest(@file_names::text[])  AS file_name,
           unnest(@paths::text[])       AS path,
           unnest(@sizes::bigint[])     AS size_bytes,
           unnest(@digests::text[])     AS sha256,
           unnest(@base_paths::text[])  AS base_path
),
kept AS (
    INSERT INTO artifact_manifest (snapshot_id, file_name, path, size_bytes, sha256, base_path)
    SELECT @snapshot_id::uuid, f.file_name, f.path, f.size_bytes, f.sha256, NULLIF(f.base_path, '')
    FROM fresh f
    ON CONFLICT (snapshot_id, file_name) WHERE snapshot_id IS NOT NULL
    DO UPDATE SET
        path = EXCLUDED.path,
        size_bytes = EXCLUDED.size_bytes,
        sha256 = EXCLUDED.sha256,
        base_path = EXCLUDED.base_path,
        created_at = now()
    RETURNING id
)
DELETE FROM artifact_manifest
WHERE snapshot_id = @snapshot_id::uuid
  AND id NOT IN (SELECT id FROM kept);

-- name: ListSnapshotManifest :many
SELECT * FROM artifact_manifest
WHERE snapshot_id = $1
ORDER BY file_name;

-- name: DeleteSnapshotManifest :exec
DELETE FROM artifact_manifest WHERE snapshot_id = $1;
