-- Upgrade existing installations without turning a known full-copy template
-- into an unresolved post-cutover history segment.  The host receipt remains
-- authoritative: this row is only a prospective bridge and is closed by the
-- first retained receipt (the unresolved-obligation wrapper keeps the gap
-- unbillable until that receipt is accepted).
INSERT INTO sandbox_storage_baseline (
  sandbox_id,team_id,host_id,path,generation,allocated_bytes,observed_at,
  effective_at,receipt_id,started_at,ended_at
)
SELECT DISTINCT ON (i.sandbox_id,i.host_id)
  i.sandbox_id,s.team_id,i.host_id,t.rootfs_path,
  encode(digest(s.template_id::text || ':' || t.rootfs_path,'sha256'),'hex'),
  am.allocated_bytes,now(),i.started_at,
  '00000000-0000-0000-0000-000000000000'::uuid,i.started_at,NULL
FROM sandbox_storage_interval i
JOIN sandbox s ON s.id=i.sandbox_id
JOIN template t ON t.id=s.template_id
JOIN retained_storage_cutover c ON c.team_id=i.team_id AND c.host_id=i.host_id
JOIN artifact_manifest am ON am.template_id=s.template_id AND am.path=t.rootfs_path
WHERE s.base_path IS NULL
  AND t.rootfs_path IS NOT NULL
  AND am.allocated_bytes>0
  AND i.started_at>=c.started_at
  AND (i.ended_at IS NULL OR i.ended_at>i.started_at)
  AND NOT EXISTS (
    SELECT 1 FROM sandbox_storage_baseline b
    WHERE b.sandbox_id=i.sandbox_id AND b.host_id=i.host_id
      AND b.effective_at<=i.started_at
      AND (b.ended_at IS NULL OR b.ended_at>i.started_at)
  )
ORDER BY i.sandbox_id,i.host_id,i.started_at
ON CONFLICT (sandbox_id,host_id,effective_at,receipt_id) DO NOTHING;
