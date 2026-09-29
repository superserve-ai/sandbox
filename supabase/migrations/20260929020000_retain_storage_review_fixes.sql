SET LOCAL lock_timeout = '250ms';

-- A retained report can be the first authoritative observation on a new host
-- after reassignment. End the old host's legacy interval at that receipt
-- boundary without pretending the sandbox was destroyed.
ALTER TABLE sandbox_storage_interval
  DROP CONSTRAINT IF EXISTS sandbox_storage_interval_reason_valid;
ALTER TABLE sandbox_storage_interval
  ADD CONSTRAINT sandbox_storage_interval_reason_valid
  CHECK (end_reason IS NULL OR end_reason IN ('deleted','measurement','reassigned'));

-- Preserve the legacy path-union calculation for all pre-cutover history.
-- Host reassignment is handled prospectively by closing the old legacy
-- interval when the destination host is first observed.
CREATE OR REPLACE FUNCTION storage_mib_seconds(p_team uuid,p_start timestamptz,p_end timestamptz,p_floor_legacy_artifacts boolean DEFAULT true)
RETURNS numeric LANGUAGE sql STABLE AS $$
WITH legacy_intervals AS MATERIALIZED (
  SELECT i.sandbox_id,i.team_id,i.host_id,i.disk_mib,i.started_at,
   LEAST(i.ended_at,c.started_at) ended_at,
   LEAST(s.destroyed_at,c.started_at) artifact_retention_end
  FROM sandbox_storage_interval i
  JOIN sandbox s ON s.id=i.sandbox_id
  LEFT JOIN retained_storage_cutover c ON c.host_id=i.host_id AND c.team_id=i.team_id
  WHERE i.team_id=p_team AND p_start<LEAST(p_end,billing_request_now()) AND i.started_at<COALESCE(c.started_at,'infinity')
), artifact_bounds AS (
  -- Keep each host/reference range separate until the final path union. A
  -- sandbox transfer must not bridge two hosts and reopen a prior cutover.
  SELECT s.*,i.host_id interval_host_id,i.started_at billing_started_at,i.artifact_retention_end retention_end
  FROM sandbox s JOIN legacy_intervals i ON i.sandbox_id=s.id
  WHERE s.team_id=p_team AND i.started_at<LEAST(billing_request_now(),p_end)
    AND COALESCE(i.artifact_retention_end,billing_request_now())>p_start
), artifact_ranges AS (
  SELECT p.path,MAX(COALESCE(am.allocated_bytes,0))::numeric/1048576.0 artifact_mib,
   range_agg(tstzrange(GREATEST(s.billing_started_at,p_start),LEAST(COALESCE(s.retention_end,billing_request_now()),p_end),'[)')) retained_ranges
  FROM artifact_bounds s LEFT JOIN template t ON t.id=s.template_id
  CROSS JOIN LATERAL unnest(ARRAY[s.base_path,s.delta_path,CASE WHEN s.base_path IS NULL AND s.delta_path IS NULL THEN t.rootfs_path END]) p(path)
  LEFT JOIN artifact_manifest am ON (am.snapshot_id=s.snapshot_id OR am.template_id=t.id) AND am.path=p.path
  WHERE p.path IS NOT NULL
  -- Keep the legacy path-only union. Host reassignment is cut at the
  -- prospective handoff in the receiver, so splitting this historical
  -- calculation by host would change finalized quantities at deployment.
  GROUP BY p.path
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

-- Owner creation must never wait behind a fleet-sized retained inventory
-- transaction. If the exclusive report fence is busy, clock_timestamp keeps
-- this owner after that report's receipt boundary so the retry can include it.
CREATE OR REPLACE FUNCTION fence_retained_storage_owner_creation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM pg_try_advisory_xact_lock_shared(hashtextextended('retained-storage-owner:' || NEW.host_id, 0));
 IF NEW.created_at IS NULL THEN
  NEW.created_at := clock_timestamp();
 END IF;
 RETURN NEW;
END;
$$;
