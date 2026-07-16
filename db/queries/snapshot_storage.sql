-- Shadow-only saved-snapshot/fork layer accounting. These records never feed
-- invoice/export tables; they are reconciled against VMD FIEMAP measurements.

-- name: RecordSandboxWritableLayerUsage :execrows
-- VMD reports a full-inode measurement. Once the last snapshot/descendant
-- reference to one of this sandbox's sealed generations is gone, its surviving
-- source extents become exclusive again and are included in that measurement.
-- Collapse every such owner-only generation before replacing the mutable row,
-- otherwise the same extents would be counted in both rows. The source lock is
-- the same lock taken by saved-snapshot finalization, so a capture cannot seal
-- the writable row while this reconciliation is changing generation ownership.
-- A measurement racing retryable artifact deletion may remain conservative;
-- the next stable pause runs this replacement again and converges exactly.
SELECT snapshot_storage_reconcile_writable_usage(
    sqlc.arg(team_id),
    sqlc.arg(sandbox_id),
    sqlc.arg(logical_size_bytes),
    sqlc.arg(exclusive_size_bytes)
);

-- name: GetTeamSnapshotLayerUsage :one
SELECT
    COALESCE(sum(retained_logical_size_bytes + current_logical_size_bytes), 0)::bigint
        AS logical_size_bytes,
    COALESCE(sum(retained_exclusive_size_bytes + current_exclusive_size_bytes), 0)::bigint
        AS exclusive_size_bytes,
    count(*)::bigint AS active_layer_count
FROM snapshot_storage_layer
WHERE team_id = sqlc.arg(team_id)
  AND ended_at IS NULL;

-- name: GetSnapshotStorageReferenceCounts :one
SELECT
    count(*) FILTER (WHERE snapshot_id IS NOT NULL)::bigint AS snapshot_reference_count,
    count(*) FILTER (WHERE sandbox_id IS NOT NULL)::bigint AS sandbox_reference_count
FROM snapshot_storage_reference
WHERE layer_id = sqlc.arg(layer_id)
  AND team_id = sqlc.arg(team_id)
  AND released_at IS NULL;

-- name: ListSnapshotStorageLayersForTeam :many
SELECT *
FROM snapshot_storage_layer
WHERE team_id = sqlc.arg(team_id)
ORDER BY id ASC;
