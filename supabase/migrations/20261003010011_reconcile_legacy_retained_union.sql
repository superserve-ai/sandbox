-- Keep the retained physical union as the authority for a shared baseline
-- while rollback-created owners still have legacy artifact rows.
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
  SELECT s.*,i.host_id interval_host_id,i.started_at billing_started_at,i.artifact_retention_end retention_end,
   tc.started_at team_cutover
  FROM sandbox s JOIN legacy_intervals i ON i.sandbox_id=s.id
  LEFT JOIN team_cutovers tc ON tc.team_id=i.team_id
  WHERE s.team_id=p_team AND i.started_at<LEAST(billing_request_now(),p_end)
    AND COALESCE(i.artifact_retention_end,billing_request_now())>p_start
), artifact_refs AS (
  SELECT s.interval_host_id,s.team_cutover,p.path,
   CASE WHEN s.base_path IS NULL AND s.delta_path IS NULL THEN t.rootfs_path ELSE s.base_path END baseline_path,
   CASE
     WHEN p.path=CASE WHEN s.base_path IS NULL AND s.delta_path IS NULL THEN t.rootfs_path ELSE s.base_path END
       THEN CASE WHEN t.id IS NOT NULL THEN 'template:'||t.id::text
                 WHEN s.snapshot_id IS NOT NULL THEN 'snapshot:'||s.snapshot_id::text END
     ELSE 'private:'||s.id::text||':'||p.path
   END allocation_identity,
   MAX(COALESCE(am.allocated_bytes,0))::numeric/1048576.0 artifact_mib,
   GREATEST(s.billing_started_at,p_start) range_start,
   LEAST(COALESCE(s.retention_end,billing_request_now()),p_end) range_end
  FROM artifact_bounds s LEFT JOIN template t ON t.id=s.template_id
  CROSS JOIN LATERAL unnest(ARRAY[s.base_path,s.delta_path,CASE WHEN s.base_path IS NULL AND s.delta_path IS NULL THEN t.rootfs_path END]) p(path)
  LEFT JOIN artifact_manifest am ON (am.snapshot_id=s.snapshot_id OR am.template_id=t.id) AND am.path=p.path
  WHERE p.path IS NOT NULL
  GROUP BY s.interval_host_id,s.team_cutover,p.path,
   CASE WHEN s.base_path IS NULL AND s.delta_path IS NULL THEN t.rootfs_path ELSE s.base_path END,
   CASE
     WHEN p.path=CASE WHEN s.base_path IS NULL AND s.delta_path IS NULL THEN t.rootfs_path ELSE s.base_path END
       THEN CASE WHEN t.id IS NOT NULL THEN 'template:'||t.id::text
                 WHEN s.snapshot_id IS NOT NULL THEN 'snapshot:'||s.snapshot_id::text END
     ELSE 'private:'||s.id::text||':'||p.path
   END,
   s.billing_started_at,s.retention_end
), pre_ranges AS (
  SELECT path,MAX(artifact_mib) artifact_mib,
   range_agg(tstzrange(range_start,LEAST(range_end,COALESCE(team_cutover,range_end)),'[)')) retained_ranges
  FROM artifact_refs
  WHERE range_end>range_start AND (team_cutover IS NULL OR range_start<team_cutover)
  GROUP BY path
), retained_baselines AS (
  -- A retained interval suppresses a legacy artifact only when its baseline
  -- identity is established by the same template/snapshot generation. Host
  -- and time remain part of the match; an unrelated retained owner must not
  -- erase a legacy baseline merely because it shares a machine.
  SELECT r.host_id,r.team_id,
   CASE WHEN s.base_path IS NULL AND s.delta_path IS NULL THEN t.rootfs_path ELSE s.base_path END baseline_path,
   CASE WHEN t.id IS NOT NULL THEN 'template:'||t.id::text
        WHEN s.snapshot_id IS NOT NULL THEN 'snapshot:'||s.snapshot_id::text END allocation_identity,
   r.started_at,r.ended_at
  FROM retained_storage_interval r
  JOIN sandbox s ON s.id=r.owner_id AND r.owner_kind='sandbox'
  LEFT JOIN template t ON t.id=s.template_id
  WHERE r.team_id=p_team
  UNION ALL
  SELECT r.host_id,r.team_id,ss.base_path,
   CASE WHEN ss.template_id IS NOT NULL THEN 'template:'||ss.template_id::text END,
   r.started_at,r.ended_at
  FROM retained_storage_interval r
  JOIN sandbox_snapshot ss ON ss.id=r.owner_id AND r.owner_kind='snapshot'
  WHERE r.team_id=p_team
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
        AND rb.allocation_identity IS NOT NULL
        AND rb.allocation_identity=ar.allocation_identity
        AND rb.started_at<ar.range_end
        AND COALESCE(rb.ended_at,billing_request_now())>ar.range_start
      UNION SELECT LEAST(COALESCE(rb.ended_at,billing_request_now()),ar.range_end)
      FROM retained_baselines rb
      WHERE rb.host_id=ar.interval_host_id AND rb.team_id=p_team
        AND rb.baseline_path=ar.path
        AND rb.allocation_identity IS NOT NULL
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
        AND rb.allocation_identity IS NOT NULL
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
