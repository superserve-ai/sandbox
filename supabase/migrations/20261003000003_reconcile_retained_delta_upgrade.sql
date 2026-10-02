-- Existing installations already have storage_mib_seconds_segmented from the
-- retained cutover migration. Keep that implementation as the compatibility
-- body, then remove the one legacy artifact class that it cannot distinguish
-- from retained extents: a template delta referenced by multiple sandboxes.
ALTER FUNCTION storage_mib_seconds_segmented(uuid,timestamptz,timestamptz,boolean)
  RENAME TO storage_mib_seconds_segmented_before_delta_reconciliation;

CREATE FUNCTION retained_template_delta_mib_seconds(
  p_team uuid, p_start timestamptz, p_end timestamptz
) RETURNS numeric LANGUAGE sql STABLE AS $$
WITH bounds AS (
  SELECT LEAST(p_end,billing_request_now()) period_end
), refs AS MATERIALIZED (
  SELECT i.host_id,s.template_id,s.delta_path,
         MAX(am.allocated_bytes)::numeric/1048576.0 artifact_mib,
         range_agg(tstzrange(
           GREATEST(i.started_at,c.started_at,p_start),
           LEAST(COALESCE(i.ended_at,b.period_end),
                 COALESCE(s.destroyed_at,b.period_end),p_end),'[)'
         )) retained_ranges
  FROM sandbox_storage_interval i
  JOIN sandbox s ON s.id=i.sandbox_id AND s.team_id=p_team
  JOIN retained_storage_cutover c ON c.team_id=i.team_id AND c.host_id=i.host_id
  CROSS JOIN bounds b
  JOIN artifact_manifest am ON am.template_id=s.template_id AND am.path=s.delta_path
  WHERE s.template_id IS NOT NULL AND s.delta_path IS NOT NULL
    AND i.started_at<b.period_end
    AND COALESCE(i.ended_at,b.period_end)>p_start
    AND GREATEST(i.started_at,c.started_at,p_start)
        < LEAST(COALESCE(i.ended_at,b.period_end),COALESCE(s.destroyed_at,b.period_end),p_end)
  GROUP BY i.host_id,s.template_id,s.delta_path
), ranges AS (
  SELECT artifact_mib,unnest(retained_ranges) r FROM refs
)
SELECT COALESCE(sum(artifact_mib*EXTRACT(epoch FROM (upper(r)-lower(r)))),0)
FROM ranges
$$;

CREATE OR REPLACE FUNCTION storage_mib_seconds_segmented(
  p_team uuid,p_start timestamptz,p_end timestamptz,
  p_floor_legacy_artifacts boolean DEFAULT true
) RETURNS numeric LANGUAGE sql STABLE AS $$
SELECT CASE
  WHEN base IS NULL THEN NULL::numeric
  ELSE base - retained_template_delta_mib_seconds(p_team,p_start,p_end)
END
FROM (
  SELECT storage_mib_seconds_segmented_before_delta_reconciliation(
    p_team,p_start,p_end,p_floor_legacy_artifacts
  ) base
) q
$$;

-- Rebind the public wrapper created by the initial retained-obligation
-- migration. Its unknown/obligation behavior remains authoritative; only the
-- corrected segmented quantity changes.
CREATE OR REPLACE FUNCTION storage_mib_seconds(
  p_team uuid,p_start timestamptz,p_end timestamptz,
  p_floor_legacy_artifacts boolean DEFAULT true
) RETURNS numeric LANGUAGE sql STABLE AS $$
SELECT CASE WHEN EXISTS (
  SELECT 1 FROM retained_storage_measurement_obligation o
  WHERE o.team_id=p_team AND o.effective_at<LEAST(p_end,billing_request_now())
    AND COALESCE(o.resolved_at,o.ended_at,billing_request_now())>p_start
) THEN NULL::numeric
ELSE storage_mib_seconds_segmented(p_team,p_start,p_end,p_floor_legacy_artifacts)
END
$$;
