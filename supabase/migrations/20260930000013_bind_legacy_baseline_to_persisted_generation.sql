-- Bind legacy baseline suppression to the build-specific paths persisted on
-- each owner.  template.rootfs_path and template.id describe the current
-- template row, not the generation retained by an older interval; consulting
-- either one would let a rebuild rewrite historical allocation identity.
-- If an old owner has no persisted baseline path, its shared identity is
-- unknown and must not be invented from mutable template metadata.
CREATE OR REPLACE FUNCTION storage_mib_seconds(p_team uuid,p_start timestamptz,p_end timestamptz,p_floor_legacy_artifacts boolean DEFAULT true)
RETURNS numeric LANGUAGE sql STABLE AS $$
WITH team_cutovers AS MATERIALIZED (
  SELECT team_id,MIN(started_at) started_at
  FROM retained_storage_cutover
  WHERE team_id=p_team
  GROUP BY team_id
), legacy_intervals AS MATERIALIZED (
  SELECT i.sandbox_id,i.team_id,i.host_id,i.disk_mib,i.started_at,
   LEAST(i.ended_at,b.started_at) ended_at,
   LEAST(s.destroyed_at,b.started_at,
    MIN(i.ended_at) FILTER (WHERE i.end_reason='reassigned') OVER (
     PARTITION BY i.sandbox_id,i.team_id,i.host_id ORDER BY i.started_at
     ROWS BETWEEN CURRENT ROW AND UNBOUNDED FOLLOWING)) artifact_retention_end
  FROM sandbox_storage_interval i
  JOIN sandbox s ON s.id=i.sandbox_id
  LEFT JOIN retained_storage_cutover c ON c.host_id=i.host_id AND c.team_id=i.team_id
  CROSS JOIN LATERAL (
    SELECT CASE WHEN i.started_at<c.started_at THEN c.started_at
      ELSE (SELECT MIN(r.started_at) FROM retained_storage_interval r
        WHERE r.host_id=i.host_id AND r.team_id=i.team_id
          AND r.owner_kind='sandbox' AND r.owner_id=i.sandbox_id
          AND r.started_at>=i.started_at) END started_at
  ) b
  WHERE i.team_id=p_team AND p_start<LEAST(p_end,billing_request_now())
), artifact_bounds AS (
  SELECT s.*,i.host_id interval_host_id,i.started_at billing_started_at,
   i.artifact_retention_end retention_end,tc.started_at team_cutover,
   CASE
     WHEN s.base_path IS NOT NULL THEN s.base_path
     -- A delta without its persisted base has no authoritative shared
     -- baseline. Do not fall back to the mutable template row.
     WHEN s.delta_path IS NOT NULL THEN NULL
     -- Full-copy owners retain the template snapshot path at creation. The
     -- sibling rootfs is the build-specific baseline only when that pin is
     -- present; old rows without it remain unknown.
     WHEN s.snapshot_path ~ '/vmstate[.]snap$'
       THEN regexp_replace(s.snapshot_path, '/[^/]+$', '/rootfs.ext4')
   END baseline_path
  FROM sandbox s JOIN legacy_intervals i ON i.sandbox_id=s.id
  LEFT JOIN team_cutovers tc ON tc.team_id=i.team_id
  WHERE s.team_id=p_team AND i.started_at<LEAST(billing_request_now(),p_end)
    AND COALESCE(i.artifact_retention_end,billing_request_now())>p_start
), artifact_refs AS (
  SELECT s.interval_host_id,s.team_cutover,p.path,s.baseline_path,
   CASE WHEN s.baseline_path IS NOT NULL AND p.path=s.baseline_path
     THEN 'baseline:'||s.baseline_path
     ELSE 'private:'||s.id::text||':'||p.path
   END allocation_identity,
   MAX(COALESCE(am.allocated_bytes,0))::numeric/1048576.0 artifact_mib,
   GREATEST(s.billing_started_at,p_start) range_start,
   LEAST(COALESCE(s.retention_end,billing_request_now()),p_end) range_end
  FROM artifact_bounds s
  CROSS JOIN LATERAL unnest(ARRAY[
    s.base_path,
    s.delta_path,
    CASE WHEN s.baseline_path IS NOT NULL THEN s.baseline_path END
  ]) p(path)
  LEFT JOIN artifact_manifest am
    ON (am.snapshot_id=s.snapshot_id OR am.template_id=s.template_id)
   AND am.path=p.path
  WHERE p.path IS NOT NULL
  GROUP BY s.interval_host_id,s.team_cutover,p.path,s.baseline_path,
   CASE WHEN s.baseline_path IS NOT NULL AND p.path=s.baseline_path
     THEN 'baseline:'||s.baseline_path
     ELSE 'private:'||s.id::text||':'||p.path
   END,s.billing_started_at,s.retention_end
), pre_ranges AS (
  SELECT path,MAX(artifact_mib) artifact_mib,
   range_agg(tstzrange(range_start,LEAST(range_end,COALESCE(team_cutover,range_end)),'[)')) retained_ranges
  FROM artifact_refs
  WHERE range_end>range_start AND (team_cutover IS NULL OR range_start<team_cutover)
  GROUP BY path
), retained_baselines AS (
  SELECT r.host_id,r.team_id,b.baseline_path,
   'baseline:'||b.baseline_path allocation_identity,
   r.started_at,r.ended_at
  FROM retained_storage_interval r
  JOIN sandbox s ON s.id=r.owner_id AND r.owner_kind='sandbox'
  CROSS JOIN LATERAL (
    SELECT CASE
      WHEN s.base_path IS NOT NULL THEN s.base_path
      WHEN s.delta_path IS NOT NULL THEN NULL
      WHEN s.snapshot_path ~ '/vmstate[.]snap$'
        THEN regexp_replace(s.snapshot_path, '/[^/]+$', '/rootfs.ext4')
    END baseline_path
  ) b
  WHERE r.team_id=p_team AND b.baseline_path IS NOT NULL
  UNION ALL
  SELECT r.host_id,r.team_id,ss.base_path,
   'baseline:'||ss.base_path,
   r.started_at,r.ended_at
  FROM retained_storage_interval r
  JOIN sandbox_snapshot ss ON ss.id=r.owner_id AND r.owner_kind='snapshot'
  WHERE r.team_id=p_team AND ss.base_path IS NOT NULL
), post_ranges AS (
  SELECT seg.interval_host_id,seg.path,seg.allocation_identity,
   MAX(seg.artifact_mib) artifact_mib,
   range_agg(tstzrange(seg.boundary,seg.next_boundary,'[)')) retained_ranges
  FROM (
    SELECT ar.interval_host_id,ar.path,ar.allocation_identity,ar.artifact_mib,
     ar.range_start,ar.range_end,ar.team_cutover,b.boundary,
     lead(b.boundary) OVER (
       PARTITION BY ar.interval_host_id,ar.path,ar.allocation_identity,ar.range_start,ar.range_end
       ORDER BY b.boundary) next_boundary
    FROM artifact_refs ar
    CROSS JOIN LATERAL (
      SELECT ar.range_start boundary
      UNION SELECT ar.range_end
      UNION SELECT GREATEST(rb.started_at,ar.range_start)
      FROM retained_baselines rb
      WHERE rb.host_id=ar.interval_host_id AND rb.team_id=p_team
        AND rb.baseline_path=ar.path
        AND rb.allocation_identity=ar.allocation_identity
        AND rb.started_at<ar.range_end
        AND COALESCE(rb.ended_at,billing_request_now())>ar.range_start
      UNION SELECT LEAST(COALESCE(rb.ended_at,billing_request_now()),ar.range_end)
      FROM retained_baselines rb
      WHERE rb.host_id=ar.interval_host_id AND rb.team_id=p_team
        AND rb.baseline_path=ar.path
        AND rb.allocation_identity=ar.allocation_identity
        AND rb.started_at<ar.range_end
        AND COALESCE(rb.ended_at,billing_request_now())>ar.range_start
    ) b
    WHERE ar.team_cutover IS NOT NULL
      AND ar.range_end>GREATEST(ar.range_start,ar.team_cutover)
      AND b.boundary>=GREATEST(ar.range_start,ar.team_cutover)
      AND b.boundary<=ar.range_end
  ) seg
  WHERE seg.next_boundary>seg.boundary
    AND NOT EXISTS (
      SELECT 1 FROM retained_baselines rb
      WHERE rb.host_id=seg.interval_host_id AND rb.team_id=p_team
        AND rb.baseline_path=seg.path
        AND rb.allocation_identity=seg.allocation_identity
        AND rb.started_at<=seg.boundary
        AND COALESCE(rb.ended_at,billing_request_now())>seg.boundary
    )
  GROUP BY seg.interval_host_id,seg.path,seg.allocation_identity
), artifact_ranges AS (
  SELECT path,artifact_mib,retained_ranges FROM pre_ranges
  UNION ALL
  SELECT path,artifact_mib,retained_ranges FROM post_ranges
), artifacts AS (
  SELECT COALESCE(sum(artifact_mib*EXTRACT(epoch FROM(upper(r)-lower(r)))),0) amount
  FROM artifact_ranges CROSS JOIN LATERAL unnest(retained_ranges) ranges(r)
), overlays AS (
  SELECT COALESCE(sum(EXTRACT(epoch FROM(LEAST(COALESCE(ended_at,billing_request_now()),p_end)-GREATEST(started_at,p_start)))*disk_mib),0) amount
  FROM legacy_intervals WHERE GREATEST(started_at,p_start)<LEAST(COALESCE(ended_at,billing_request_now()),p_end)
) SELECT CASE WHEN p_start>=LEAST(p_end,billing_request_now()) THEN 0 ELSE
  (CASE WHEN p_floor_legacy_artifacts THEN FLOOR(artifacts.amount) ELSE artifacts.amount END)
  +overlays.amount+retained_storage_mib_seconds(p_team,p_start,p_end) END
 FROM artifacts,overlays
$$;
