-- A post-cutover activation has no trusted provisioned quantity.  Keep a
-- quantity-free durable fence until a compatible retained receipt resolves it.
CREATE TABLE retained_storage_measurement_obligation (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  team_id uuid NOT NULL REFERENCES team(id),
  owner_kind text NOT NULL CHECK (owner_kind IN ('sandbox','snapshot')),
  owner_id uuid NOT NULL,
  host_id text NOT NULL,
  effective_at timestamptz NOT NULL CHECK (isfinite(effective_at)),
  ended_at timestamptz,
  resolved_at timestamptz,
  resolution_report_id uuid,
  CHECK (ended_at IS NULL OR ended_at >= effective_at),
  CHECK (resolved_at IS NULL OR resolved_at >= effective_at),
  CHECK (ended_at IS NULL OR resolved_at IS NULL OR resolved_at <= ended_at)
);
CREATE UNIQUE INDEX retained_storage_measurement_obligation_active
  ON retained_storage_measurement_obligation(owner_kind,owner_id)
  WHERE resolved_at IS NULL AND ended_at IS NULL;
CREATE INDEX retained_storage_measurement_obligation_window
  ON retained_storage_measurement_obligation(team_id,host_id,effective_at,ended_at,resolved_at);
ALTER TABLE retained_storage_measurement_obligation ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION close_retained_storage_measurement_obligation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.destroyed_at IS NOT NULL THEN
    UPDATE retained_storage_measurement_obligation
    SET ended_at=GREATEST(effective_at,NEW.destroyed_at)
    WHERE owner_kind='sandbox' AND owner_id=NEW.id AND ended_at IS NULL;
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER close_retained_storage_measurement_obligation
AFTER UPDATE OF destroyed_at ON sandbox
FOR EACH ROW WHEN (OLD.destroyed_at IS NULL AND NEW.destroyed_at IS NOT NULL)
EXECUTE FUNCTION close_retained_storage_measurement_obligation();

-- Persisted baseline observations are piecewise temporal evidence.  The
-- original legacy stay remains the accounting envelope, while effective_at is
-- the immutable receipt boundary at which this evidence becomes authoritative.
ALTER TABLE sandbox_storage_baseline
  ADD COLUMN effective_at timestamptz,
  ADD COLUMN receipt_id uuid;
UPDATE sandbox_storage_baseline
SET effective_at=COALESCE(effective_at,observed_at), receipt_id=COALESCE(receipt_id,'00000000-0000-0000-0000-000000000000'::uuid);
ALTER TABLE sandbox_storage_baseline
  ALTER COLUMN effective_at SET NOT NULL,
  ALTER COLUMN receipt_id SET DEFAULT '00000000-0000-0000-0000-000000000000'::uuid,
  ALTER COLUMN receipt_id SET NOT NULL;
ALTER TABLE sandbox_storage_baseline
  DROP CONSTRAINT IF EXISTS sandbox_storage_baseline_sandbox_id_host_id_path_generation_started_at_key;
ALTER TABLE sandbox_storage_baseline
  ADD CONSTRAINT sandbox_storage_baseline_effective_order_unique
  UNIQUE (sandbox_id,host_id,effective_at,receipt_id);
CREATE INDEX sandbox_storage_baseline_effective_lookup
  ON sandbox_storage_baseline(team_id,host_id,sandbox_id,effective_at,ended_at);

-- Replace the latest-observation lookup with an immutable segment-aware
-- implementation.  The old implementation is retained under an internal
-- name so deployed callers can be replaced atomically below.
ALTER FUNCTION storage_mib_seconds(uuid,timestamptz,timestamptz,boolean)
  RENAME TO storage_mib_seconds_without_obligations;

CREATE FUNCTION storage_mib_seconds_segmented(p_team uuid,p_start timestamptz,p_end timestamptz,p_floor_legacy_artifacts boolean DEFAULT true)
RETURNS numeric LANGUAGE sql STABLE AS $$
WITH bounds AS MATERIALIZED (
 SELECT LEAST(p_end,billing_request_now()) period_end,billing_request_now() request_now
), legacy_source AS MATERIALIZED (
 SELECT i.sandbox_id,i.team_id,i.host_id,i.disk_mib,i.started_at,i.ended_at,i.end_reason,
  s.destroyed_at,c.started_at team_cutover,b.period_end,b.request_now
 FROM sandbox_storage_interval i JOIN sandbox s ON s.id=i.sandbox_id
 CROSS JOIN bounds b LEFT JOIN retained_storage_cutover c ON c.host_id=i.host_id AND c.team_id=i.team_id
 WHERE i.team_id=p_team AND p_start<b.period_end AND i.started_at<b.period_end
   AND COALESCE(i.ended_at,b.period_end)>p_start
), legacy_intervals AS MATERIALIZED (
 SELECT i.sandbox_id,i.team_id,i.host_id,i.disk_mib,i.started_at,
  LEAST(COALESCE(i.ended_at,i.period_end),boundary.started_at) ended_at,
  LEAST(i.destroyed_at,i.period_end,boundary.started_at,MIN(i.ended_at) FILTER (WHERE i.end_reason='reassigned') OVER (
    PARTITION BY i.sandbox_id,i.team_id,i.host_id ORDER BY i.started_at
    ROWS BETWEEN CURRENT ROW AND UNBOUNDED FOLLOWING)) artifact_retention_end,
  i.team_cutover,i.request_now
 FROM legacy_source i
 CROSS JOIN LATERAL (SELECT COALESCE(
   CASE WHEN i.started_at<i.team_cutover THEN i.team_cutover END,
   (SELECT MIN(r.started_at) FROM retained_storage_interval r
    WHERE r.host_id=i.host_id AND r.team_id=i.team_id AND r.owner_kind='sandbox'
      AND r.owner_id=i.sandbox_id AND r.started_at>=i.started_at),
   i.period_end) started_at) boundary
 WHERE i.started_at<boundary.started_at
), legacy_segments AS MATERIALIZED (
 SELECT s.id,s.template_id,s.snapshot_id,s.base_path,s.delta_path,
  i.host_id interval_host_id,
  GREATEST(i.started_at,x.effective_at) billing_started_at,
  LEAST(COALESCE(i.artifact_retention_end,i.request_now),COALESCE(x.ended_at,i.request_now)) retention_end,
  i.team_cutover,i.request_now,x.path baseline_path,x.generation baseline_generation,
  x.allocated_bytes baseline_allocated_bytes,
  false unresolved_baseline
 FROM sandbox s JOIN legacy_intervals i ON i.sandbox_id=s.id
 JOIN sandbox_storage_baseline x ON x.sandbox_id=s.id AND x.team_id=p_team AND x.host_id=i.host_id
  AND x.effective_at<COALESCE(i.artifact_retention_end,i.request_now)
  AND COALESCE(x.ended_at,i.request_now)>i.started_at
 WHERE s.team_id=p_team
), legacy_prefix AS MATERIALIZED (
 SELECT s.id,s.template_id,s.snapshot_id,s.base_path,s.delta_path,
  i.host_id interval_host_id,i.started_at billing_started_at,
  LEAST(COALESCE(i.artifact_retention_end,i.request_now),COALESCE(first_segment.first_effective,i.request_now)) retention_end,
  i.team_cutover,i.request_now,NULL::text baseline_path,NULL::text baseline_generation,NULL::bigint baseline_allocated_bytes,
  ((s.template_id IS NOT NULL AND s.base_path IS NULL)
   OR (i.team_cutover IS NOT NULL AND s.base_path IS NOT NULL)) unresolved_baseline
 FROM sandbox s JOIN legacy_intervals i ON i.sandbox_id=s.id
 LEFT JOIN LATERAL (
   SELECT MIN(x.effective_at) first_effective FROM sandbox_storage_baseline x
   WHERE x.sandbox_id=s.id AND x.team_id=p_team AND x.host_id=i.host_id
     AND x.effective_at<COALESCE(i.artifact_retention_end,i.request_now)
 ) first_segment ON true
 WHERE s.team_id=p_team AND i.started_at<COALESCE(first_segment.first_effective,i.request_now)
), artifact_bounds AS MATERIALIZED (
 SELECT * FROM legacy_segments UNION ALL SELECT * FROM legacy_prefix
), artifact_refs AS MATERIALIZED (
 SELECT a.interval_host_id,a.team_cutover,p.path,
  CASE WHEN p.path=a.baseline_path THEN
    CASE WHEN a.baseline_generation IS NULL THEN NULL ELSE 'baseline:'||a.baseline_path||':'||a.baseline_generation END
   ELSE 'private:'||a.id::text||':'||p.path END allocation_identity,
  CASE WHEN p.path=a.baseline_path THEN COALESCE(a.baseline_allocated_bytes,am_snapshot.allocated_bytes,am_template.allocated_bytes)
   ELSE COALESCE(am_snapshot.allocated_bytes,am_template.allocated_bytes) END artifact_bytes,
  GREATEST(a.billing_started_at,p_start) range_start,
  LEAST(COALESCE(a.retention_end,a.request_now),p_end) range_end,
  a.unresolved_baseline,a.template_id,a.base_path,a.baseline_path
 FROM artifact_bounds a
 CROSS JOIN LATERAL unnest(ARRAY[a.base_path,a.delta_path,
   CASE WHEN a.baseline_path IN (a.base_path,a.delta_path) THEN NULL ELSE a.baseline_path END]) p(path)
 LEFT JOIN artifact_manifest am_snapshot ON am_snapshot.snapshot_id=a.snapshot_id AND am_snapshot.path=p.path
 LEFT JOIN artifact_manifest am_template ON am_template.snapshot_id IS NULL AND am_template.template_id=a.template_id AND am_template.path=p.path
 WHERE p.path IS NOT NULL
), pre_ranges AS (
 SELECT path,allocation_identity,artifact_bytes::numeric/1048576.0 artifact_mib,
 range_agg(tstzrange(range_start,LEAST(range_end,COALESCE(team_cutover,range_end)),'[)')) retained_ranges
 FROM artifact_refs
 WHERE artifact_bytes IS NOT NULL AND range_end>range_start
   AND (team_cutover IS NULL OR range_start<team_cutover)
 GROUP BY path,allocation_identity,artifact_bytes
), retained_baselines AS MATERIALIZED (
 SELECT r.host_id,r.team_id,r.baseline_path,'baseline:'||r.baseline_path||':'||COALESCE(r.baseline_generation,'') allocation_identity,
  r.started_at,r.ended_at FROM retained_storage_interval r
 WHERE r.team_id=p_team AND r.baseline_path IS NOT NULL
), retained_coverage AS MATERIALIZED (
 SELECT host_id,team_id,baseline_path,allocation_identity,
  range_agg(tstzrange(started_at,COALESCE(ended_at,(SELECT request_now FROM bounds)),'[)')) covered
 FROM retained_baselines GROUP BY host_id,team_id,baseline_path,allocation_identity
), post_ranges AS (
 SELECT ar.interval_host_id,ar.path,ar.allocation_identity,ar.artifact_bytes::numeric/1048576.0 artifact_mib,
  range_agg(tstzrange(GREATEST(ar.range_start,ar.team_cutover),ar.range_end,'[)'))
    -COALESCE(rc.covered,'{}'::tstzmultirange) retained_ranges
 FROM artifact_refs ar LEFT JOIN retained_coverage rc ON rc.host_id=ar.interval_host_id AND rc.team_id=p_team
  AND rc.baseline_path=ar.path AND rc.allocation_identity=ar.allocation_identity
 WHERE ar.team_cutover IS NOT NULL AND ar.range_end>GREATEST(ar.range_start,ar.team_cutover)
   AND ar.artifact_bytes IS NOT NULL
 GROUP BY ar.interval_host_id,ar.path,ar.allocation_identity,ar.artifact_bytes,rc.covered
), artifact_ranges AS (
 SELECT path,artifact_mib,retained_ranges FROM pre_ranges
 UNION ALL SELECT path,artifact_mib,retained_ranges FROM post_ranges
), artifacts AS (
 SELECT COALESCE(sum(artifact_mib*EXTRACT(epoch FROM (upper(r)-lower(r)))),0) amount
 FROM artifact_ranges CROSS JOIN LATERAL unnest(retained_ranges) ranges(r)
), overlays AS (
 SELECT COALESCE(sum(EXTRACT(epoch FROM (LEAST(COALESCE(ended_at,(SELECT request_now FROM bounds)),p_end)-GREATEST(started_at,p_start)))*disk_mib),0) amount
 FROM legacy_intervals WHERE GREATEST(started_at,p_start)<LEAST(COALESCE(ended_at,(SELECT request_now FROM bounds)),p_end)
), final_value AS (
 SELECT CASE WHEN EXISTS(SELECT 1 FROM artifact_refs WHERE range_end>range_start AND artifact_bytes IS NULL)
   OR EXISTS(SELECT 1 FROM artifact_refs a WHERE a.unresolved_baseline AND a.team_cutover IS NOT NULL
       AND a.range_end>GREATEST(a.range_start,a.team_cutover))
   OR EXISTS(SELECT 1 FROM artifact_bounds a WHERE a.template_id IS NOT NULL AND a.base_path IS NULL
       AND a.baseline_path IS NULL AND a.retention_end>a.billing_started_at)
  THEN NULL::numeric
  ELSE (CASE WHEN p_floor_legacy_artifacts THEN FLOOR(artifacts.amount) ELSE artifacts.amount END)
    +overlays.amount+retained_storage_mib_seconds(p_team,p_start,p_end) END amount
 FROM artifacts,overlays
)
SELECT CASE WHEN p_start>=(SELECT period_end FROM bounds) THEN 0::numeric ELSE amount END FROM final_value
$$;

CREATE FUNCTION storage_mib_seconds(p_team uuid,p_start timestamptz,p_end timestamptz,p_floor_legacy_artifacts boolean DEFAULT true)
RETURNS numeric LANGUAGE sql STABLE AS $$
 SELECT CASE WHEN EXISTS (
   SELECT 1 FROM retained_storage_measurement_obligation o
   WHERE o.team_id=p_team AND o.effective_at<LEAST(p_end,billing_request_now())
     AND COALESCE(o.resolved_at,o.ended_at,billing_request_now())>p_start
 ) THEN NULL::numeric
 ELSE storage_mib_seconds_segmented(p_team,p_start,p_end,p_floor_legacy_artifacts) END
$$;

-- Rebind the payable function's dependency to the obligation-aware wrapper.
CREATE OR REPLACE FUNCTION billable_storage_mib_seconds(p_team_id uuid, p_start timestamptz, p_end timestamptz)
RETURNS numeric LANGUAGE plpgsql STABLE AS $$
DECLARE
  v_start timestamptz;
  v_end timestamptz := LEAST(p_end, now());
BEGIN
  SELECT GREATEST(p_start, effective_at) INTO v_start
  FROM team_storage_billing_activation WHERE team_id=p_team_id;
  IF v_start IS NULL OR v_start >= v_end THEN RETURN 0; END IF;
  RETURN storage_mib_seconds(p_team_id, v_start, v_end, false);
END;
$$;

CREATE OR REPLACE FUNCTION storage_reports_complete_through(
  p_team_id uuid, p_boundary timestamptz
) RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT NOT EXISTS (
    SELECT 1 FROM retained_storage_measurement_obligation o
    WHERE o.team_id=p_team_id AND o.effective_at<p_boundary
      AND COALESCE(o.resolved_at,o.ended_at,billing_request_now())>p_boundary
  ) AND NOT EXISTS (
    SELECT 1 FROM host_storage_report r
    WHERE r.received_at<p_boundary
      AND (r.state IN ('pending','processing','retry_exhausted') OR
        (r.state='processed' AND r.payload IS NOT NULL AND
          (jsonb_typeof(r.payload)<>'array' OR r.next_measurement_index<>CASE
            WHEN jsonb_typeof(r.payload)='array' THEN jsonb_array_length(r.payload) ELSE -1 END)))
      AND EXISTS (
        SELECT 1 FROM sandbox s
        WHERE s.team_id=p_team_id AND s.host_id=r.host_id AND s.created_at<=r.received_at
          AND (s.destroyed_at IS NULL OR s.destroyed_at>r.received_at)
        UNION ALL SELECT 1 FROM sandbox_snapshot s
        WHERE s.team_id=p_team_id AND s.host_id=r.host_id AND s.created_at<=r.received_at
          AND (s.status IN ('ready','creating','deleting') OR s.retention_ended_at>r.received_at)
          AND (LEAST(s.deleted_at,s.retention_ended_at) IS NULL OR LEAST(s.deleted_at,s.retention_ended_at)>r.received_at))
    UNION ALL
    SELECT 1 FROM legacy_host_storage_report legacy
    WHERE legacy.received_at<p_boundary AND EXISTS (
      SELECT 1 FROM sandbox s
      WHERE s.team_id=p_team_id AND s.host_id=legacy.host_id AND s.created_at<=legacy.received_at
        AND (s.destroyed_at IS NULL OR s.destroyed_at>legacy.received_at)
      UNION ALL SELECT 1 FROM sandbox_snapshot s
      WHERE s.team_id=p_team_id AND s.host_id=legacy.host_id AND s.created_at<=legacy.received_at
        AND (s.status IN ('ready','creating','deleting') OR s.retention_ended_at>legacy.received_at)
        AND (LEAST(s.deleted_at,s.retention_ended_at) IS NULL OR LEAST(s.deleted_at,s.retention_ended_at)>legacy.received_at))
  )
$$;

-- A host/lifetime access path bounds receiver candidate discovery before any
-- owner-history probes.  This is additive to the separate pending host-id
-- backfill/index decision.
CREATE INDEX sandbox_retained_receiver_host_lifetime
  ON sandbox(host_id,created_at,destroyed_at,id);
CREATE INDEX sandbox_snapshot_retained_receiver_host_lifetime
  ON sandbox_snapshot(host_id,created_at,deleted_at,retention_ended_at,id);

DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN
  GRANT SELECT,INSERT,UPDATE ON retained_storage_measurement_obligation TO service_role;
  GRANT USAGE,SELECT ON SEQUENCE retained_storage_measurement_obligation_id_seq TO service_role;
 END IF;
END $$;
