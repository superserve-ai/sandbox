-- Host-scoped legacy artifact identity is a prospective behavior. Before the
-- first retained-storage cutover for a team, preserve the path-only union that
-- produced already-finalized quantities. Once a cutover exists, split the
-- legacy ranges at that boundary and scope only the post-boundary ranges by
-- their interval host.
CREATE OR REPLACE FUNCTION storage_mib_seconds(p_team uuid,p_start timestamptz,p_end timestamptz,p_floor_legacy_artifacts boolean DEFAULT true)
RETURNS numeric LANGUAGE sql STABLE AS $$
WITH team_cutovers AS MATERIALIZED (
  SELECT team_id,MIN(started_at) started_at
  FROM retained_storage_cutover
  WHERE team_id=p_team
  GROUP BY team_id
), legacy_intervals AS MATERIALIZED (
  SELECT i.sandbox_id,i.team_id,i.host_id,i.disk_mib,i.started_at,
   LEAST(i.ended_at,c.started_at) ended_at,
   LEAST(s.destroyed_at,c.started_at,
    MIN(i.ended_at) FILTER (WHERE i.end_reason='reassigned') OVER (
     PARTITION BY i.sandbox_id,i.team_id,i.host_id ORDER BY i.started_at
     ROWS BETWEEN CURRENT ROW AND UNBOUNDED FOLLOWING)) artifact_retention_end
  FROM sandbox_storage_interval i
  JOIN sandbox s ON s.id=i.sandbox_id
  LEFT JOIN retained_storage_cutover c ON c.host_id=i.host_id AND c.team_id=i.team_id
  WHERE i.team_id=p_team AND p_start<LEAST(p_end,billing_request_now())
    AND (
      i.started_at<COALESCE(c.started_at,'infinity')
      -- During a producer rollback, a sandbox created or reassigned after
      -- cutover has no retained interval yet. Keep its valid legacy samples
      -- billable instead of treating the permanent cutover as a blanket
      -- exclusion for every future owner.
      OR c.started_at IS NULL
      OR NOT EXISTS (
        SELECT 1 FROM retained_storage_interval r
        WHERE r.team_id=i.team_id AND r.owner_kind='sandbox'
          AND r.owner_id=i.sandbox_id AND r.started_at>=c.started_at
      )
    )
), artifact_bounds AS (
  SELECT s.*,i.host_id interval_host_id,i.started_at billing_started_at,i.artifact_retention_end retention_end,
   tc.started_at team_cutover
  FROM sandbox s JOIN legacy_intervals i ON i.sandbox_id=s.id
  LEFT JOIN team_cutovers tc ON tc.team_id=i.team_id
  WHERE s.team_id=p_team AND i.started_at<LEAST(billing_request_now(),p_end)
    AND COALESCE(i.artifact_retention_end,billing_request_now())>p_start
), artifact_refs AS (
  SELECT s.interval_host_id,s.team_cutover,p.path,
   MAX(COALESCE(am.allocated_bytes,0))::numeric/1048576.0 artifact_mib,
   GREATEST(s.billing_started_at,p_start) range_start,
   LEAST(COALESCE(s.retention_end,billing_request_now()),p_end) range_end
  FROM artifact_bounds s LEFT JOIN template t ON t.id=s.template_id
  CROSS JOIN LATERAL unnest(ARRAY[s.base_path,s.delta_path,CASE WHEN s.base_path IS NULL AND s.delta_path IS NULL THEN t.rootfs_path END]) p(path)
  LEFT JOIN artifact_manifest am ON (am.snapshot_id=s.snapshot_id OR am.template_id=t.id) AND am.path=p.path
  WHERE p.path IS NOT NULL
  GROUP BY s.interval_host_id,s.team_cutover,p.path,s.billing_started_at,s.retention_end
), pre_ranges AS (
  SELECT path,MAX(artifact_mib) artifact_mib,
   range_agg(tstzrange(range_start,LEAST(range_end,COALESCE(team_cutover,range_end)),'[)')) retained_ranges
  FROM artifact_refs
  WHERE range_end>range_start AND (team_cutover IS NULL OR range_start<team_cutover)
  GROUP BY path
), post_ranges AS (
  SELECT interval_host_id,path,MAX(artifact_mib) artifact_mib,
   range_agg(tstzrange(GREATEST(range_start,team_cutover),range_end,'[)')) retained_ranges
  FROM artifact_refs
  WHERE team_cutover IS NOT NULL AND range_end>GREATEST(range_start,team_cutover)
  GROUP BY interval_host_id,path
), artifact_ranges AS (
  SELECT path,artifact_mib,retained_ranges FROM pre_ranges
  UNION ALL
  SELECT path,artifact_mib,retained_ranges FROM post_ranges
), artifacts AS (
  SELECT COALESCE(sum(artifact_mib*EXTRACT(epoch FROM(upper(r)-lower(r)))),0) amount
  FROM artifact_ranges CROSS JOIN LATERAL unnest(retained_ranges) ranges(r)
), overlays AS (
  SELECT COALESCE(sum(EXTRACT(epoch FROM(LEAST(COALESCE(ended_at,billing_request_now()),p_end)-GREATEST(started_at,p_start)))*disk_mib),0) amount
  FROM legacy_intervals WHERE started_at<LEAST(billing_request_now(),p_end) AND COALESCE(ended_at,billing_request_now())>p_start
) SELECT CASE WHEN p_start>=LEAST(p_end,billing_request_now()) THEN 0 ELSE
  (CASE WHEN p_floor_legacy_artifacts THEN FLOOR(artifacts.amount) ELSE artifacts.amount END)
  +overlays.amount+retained_storage_mib_seconds(p_team,p_start,p_end) END
 FROM artifacts,overlays
$$;
