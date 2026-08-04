-- name: ListSnapshotManifest :many
SELECT * FROM artifact_manifest
WHERE snapshot_id = $1
ORDER BY file_name;

-- name: DeleteSnapshotManifest :exec
DELETE FROM artifact_manifest WHERE snapshot_id = $1;
