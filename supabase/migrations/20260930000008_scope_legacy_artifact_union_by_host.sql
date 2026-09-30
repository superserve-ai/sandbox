-- The same path on different hosts represents separate physical allocations.
-- Use the interval host because the sandbox may have been reassigned since.
CREATE OR REPLACE FUNCTION storage_mib_seconds(p_team uuid,p_start timestamptz,p_end timestamptz,p_floor_legacy_artifacts boolean DEFAULT true)
RETURNS numeric LANGUAGE sql STABLE AS $$
WITH legacy_intervals AS MATERIALIZED (
  SELECT i.sandbox_id,i.team_id,i.host_id,i.disk_mib,i.started_at,
   LEAST(i.ended_at,c.started_at) ended_at,
   -- Measurement changes do not release artifacts, but the next handoff
   -- ends this owner's entire legacy reference, including earlier samples.
   LEAST(s.destroyed_at,c.started_at,
    MIN(i.ended_at) FILTER (WHERE i.end_reason='reassigned') OVER (
     PARTITION BY i.sandbox_id,i.team_id,i.host_id ORDER BY i.started_at
     ROWS BETWEEN CURRENT ROW AND UNBOUNDED FOLLOWING)) artifact_retention_end
  FROM sandbox_storage_interval i
  JOIN sandbox s ON s.id=i.sandbox_id
  LEFT JOIN retained_storage_cutover c ON c.host_id=i.host_id AND c.team_id=i.team_id
  WHERE i.team_id=p_team AND p_start<LEAST(p_end,billing_request_now()) AND i.started_at<COALESCE(c.started_at,'infinity')
), artifact_bounds AS (
  -- Keep each host/reference range separate until the host/path union. A
  -- sandbox transfer must not bridge two hosts and reopen a prior cutover.
  SELECT s.*,i.host_id interval_host_id,i.started_at billing_started_at,i.artifact_retention_end retention_end
  FROM sandbox s JOIN legacy_intervals i ON i.sandbox_id=s.id
  WHERE s.team_id=p_team AND i.started_at<LEAST(billing_request_now(),p_end)
    AND COALESCE(i.artifact_retention_end,billing_request_now())>p_start
), artifact_ranges AS (
  SELECT s.interval_host_id,p.path,MAX(COALESCE(am.allocated_bytes,0))::numeric/1048576.0 artifact_mib,
   range_agg(tstzrange(GREATEST(s.billing_started_at,p_start),LEAST(COALESCE(s.retention_end,billing_request_now()),p_end),'[)')) retained_ranges
  FROM artifact_bounds s LEFT JOIN template t ON t.id=s.template_id
  CROSS JOIN LATERAL unnest(ARRAY[s.base_path,s.delta_path,CASE WHEN s.base_path IS NULL AND s.delta_path IS NULL THEN t.rootfs_path END]) p(path)
  LEFT JOIN artifact_manifest am ON (am.snapshot_id=s.snapshot_id OR am.template_id=t.id) AND am.path=p.path
  WHERE p.path IS NOT NULL
  GROUP BY s.interval_host_id,p.path
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
