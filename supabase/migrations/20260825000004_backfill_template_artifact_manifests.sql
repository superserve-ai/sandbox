-- Seed manifests for templates that were already ready before template
-- manifests were written during FinalizeBuild. The database cannot stat paths
-- on a VMD host, so leave the historical allocation at zero until the artifact
-- is rebuilt and measured by the host.
INSERT INTO artifact_manifest (
    template_id, file_name, path, size_bytes, allocated_bytes, sha256
)
SELECT t.id,
       'rootfs.ext4',
       t.rootfs_path,
       COALESCE(t.size_bytes, 0),
       0,
       repeat('0', 64)
FROM template AS t
WHERE t.status = 'ready'
  AND t.deleted_at IS NULL
  AND t.base_path IS NULL
  AND t.delta_path IS NULL
  AND t.rootfs_path IS NOT NULL
ON CONFLICT (template_id, path) WHERE template_id IS NOT NULL DO NOTHING;

-- Overlay-mode paths are independently retained artifacts. Their historical
-- allocation is unavailable to the control-plane database and is therefore
-- left at zero until a host-side build measurement records it.
INSERT INTO artifact_manifest (
    template_id, file_name, path, size_bytes, allocated_bytes, sha256
)
SELECT t.id,
       CASE WHEN p.path = t.base_path THEN 'base.ext4' ELSE 'delta.ext4' END,
       p.path,
       0,
       0,
       repeat('0', 64)
FROM template AS t
CROSS JOIN LATERAL (
    VALUES (t.base_path), (t.delta_path)
) AS p(path)
WHERE t.status = 'ready'
  AND t.deleted_at IS NULL
  AND p.path IS NOT NULL
ON CONFLICT (template_id, path) WHERE template_id IS NOT NULL DO NOTHING;
