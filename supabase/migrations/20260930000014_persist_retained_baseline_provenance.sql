-- Persist the allocation identity that the host actually measured.  The
-- control-plane template row is mutable and snapshot_path does not imply a
-- sibling rootfs location, so accounting must never reconstruct this value.
ALTER TABLE retained_storage_interval
  ADD COLUMN baseline_path text,
  ADD COLUMN baseline_generation text,
  ADD COLUMN baseline_allocated_bytes bigint;
ALTER TABLE retained_storage_interval
  ADD CONSTRAINT retained_storage_baseline_bytes_nonnegative
  CHECK (baseline_allocated_bytes IS NULL OR baseline_allocated_bytes >= 0);
ALTER TABLE retained_storage_interval
  ADD CONSTRAINT retained_storage_baseline_identity_valid
  CHECK (baseline_path IS NULL OR (baseline_path LIKE '/%' AND length(baseline_path) <= 4096
    AND baseline_generation IS NOT NULL AND length(baseline_generation)=64
    AND baseline_generation ~ '^[0-9a-f]{64}$'));
CREATE INDEX retained_storage_baseline_identity
  ON retained_storage_interval(team_id,host_id,baseline_path,baseline_generation,started_at,ended_at)
  WHERE baseline_path IS NOT NULL;

-- Legacy intervals predate retained reports.  A receipt copies verified
-- baseline evidence here, bound to the exact legacy stay and host.  Rows are
-- immutable history; a later build or path reuse gets a new generation row.
CREATE TABLE sandbox_storage_baseline (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  sandbox_id uuid NOT NULL,
  team_id uuid NOT NULL REFERENCES team(id),
  host_id text NOT NULL,
  path text NOT NULL,
  generation text NOT NULL,
  allocated_bytes bigint NOT NULL CHECK (allocated_bytes >= 0),
  CHECK (path LIKE '/%' AND length(path) <= 4096),
  CHECK (length(generation)=64 AND generation ~ '^[0-9a-f]{64}$'),
  observed_at timestamptz NOT NULL DEFAULT now(),
  started_at timestamptz NOT NULL,
  ended_at timestamptz,
  CHECK (ended_at IS NULL OR ended_at >= started_at),
  UNIQUE (sandbox_id,host_id,path,generation,started_at)
);
CREATE INDEX sandbox_storage_baseline_lookup
  ON sandbox_storage_baseline(team_id,host_id,sandbox_id,started_at,ended_at);
ALTER TABLE sandbox_storage_baseline ENABLE ROW LEVEL SECURITY;

-- The previous migration supplied a compatibility function.  This forward
-- definition is the effective accounting contract after provenance storage is
-- present; it uses exact persisted identities and set-based coverage.
CREATE OR REPLACE FUNCTION storage_mib_seconds(p_team uuid,p_start timestamptz,p_end timestamptz,p_floor_legacy_artifacts boolean DEFAULT true)
RETURNS numeric LANGUAGE sql STABLE AS $$
WITH bounds AS MATERIALIZED (
  SELECT LEAST(p_end,clock.request_now) period_end,clock.request_now
  FROM (SELECT billing_request_now() request_now) clock
), legacy_source AS MATERIALIZED (
  SELECT i.sandbox_id,i.team_id,i.host_id,i.disk_mib,i.started_at,i.ended_at,i.end_reason,
   s.destroyed_at,c.started_at team_cutover,b.period_end,b.request_now
  FROM sandbox_storage_interval i
  JOIN sandbox s ON s.id=i.sandbox_id
  CROSS JOIN bounds b
  LEFT JOIN retained_storage_cutover c ON c.host_id=i.host_id AND c.team_id=i.team_id
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
), artifact_bounds AS MATERIALIZED (
  SELECT s.id,s.template_id,s.snapshot_id,s.base_path,s.delta_path,
   i.host_id interval_host_id,i.started_at billing_started_at,
   i.artifact_retention_end retention_end,i.team_cutover,i.request_now,
   b.path baseline_path,b.generation baseline_generation,
   b.allocated_bytes baseline_allocated_bytes,
   (s.template_id IS NOT NULL AND s.base_path IS NULL AND b.path IS NULL) unresolved_baseline
  FROM sandbox s
  JOIN legacy_intervals i ON i.sandbox_id=s.id
  LEFT JOIN LATERAL (
    SELECT x.path,x.generation,x.allocated_bytes
    FROM sandbox_storage_baseline x
    WHERE x.sandbox_id=s.id AND x.team_id=p_team AND x.host_id=i.host_id
      AND x.started_at<=i.started_at
      AND COALESCE(x.ended_at,i.request_now)>i.started_at
    ORDER BY x.observed_at DESC,x.id DESC
    LIMIT 1
  ) b ON true
  WHERE s.team_id=p_team AND i.started_at<LEAST(i.request_now,p_end)
    AND COALESCE(i.artifact_retention_end,i.request_now)>p_start
), artifact_refs AS MATERIALIZED (
  SELECT a.interval_host_id,a.team_cutover,p.path,
   CASE WHEN p.path=a.baseline_path THEN 'baseline:'||a.baseline_path||':'||COALESCE(a.baseline_generation,'')
        ELSE 'private:'||a.id::text||':'||p.path END allocation_identity,
   CASE WHEN p.path=a.baseline_path THEN COALESCE(a.baseline_allocated_bytes,am_snapshot.allocated_bytes,am_template.allocated_bytes)
        ELSE COALESCE(am_snapshot.allocated_bytes,am_template.allocated_bytes) END artifact_bytes,
   GREATEST(a.billing_started_at,p_start) range_start,
   LEAST(COALESCE(a.retention_end,a.request_now),p_end) range_end
  FROM artifact_bounds a
  CROSS JOIN LATERAL unnest(ARRAY[a.base_path,a.delta_path,
    CASE WHEN a.baseline_path IN (a.base_path,a.delta_path) THEN NULL ELSE a.baseline_path END]) p(path)
  LEFT JOIN artifact_manifest am_snapshot
    ON am_snapshot.snapshot_id=a.snapshot_id AND am_snapshot.path=p.path
  LEFT JOIN artifact_manifest am_template
    ON am_template.snapshot_id IS NULL AND am_template.template_id=a.template_id AND am_template.path=p.path
  WHERE p.path IS NOT NULL
), pre_ranges AS (
  SELECT path,allocation_identity,
   MAX(artifact_bytes)::numeric/1048576.0 artifact_mib,
   range_agg(tstzrange(range_start,LEAST(range_end,COALESCE(team_cutover,range_end)),'[)')) retained_ranges
  FROM artifact_refs
  WHERE artifact_bytes IS NOT NULL AND range_end>range_start
    AND (team_cutover IS NULL OR range_start<team_cutover)
  GROUP BY path,allocation_identity
), retained_baselines AS MATERIALIZED (
  SELECT r.host_id,r.team_id,r.baseline_path,
   'baseline:'||r.baseline_path||':'||COALESCE(r.baseline_generation,'') allocation_identity,
   r.started_at,r.ended_at
  FROM retained_storage_interval r
  WHERE r.team_id=p_team AND r.baseline_path IS NOT NULL
), retained_coverage AS MATERIALIZED (
  SELECT host_id,team_id,baseline_path,allocation_identity,
   range_agg(tstzrange(started_at,COALESCE(ended_at,(SELECT request_now FROM bounds)),'[)')) covered
  FROM retained_baselines
  GROUP BY host_id,team_id,baseline_path,allocation_identity
), post_ranges AS (
  SELECT ar.interval_host_id,ar.path,ar.allocation_identity,
   MAX(ar.artifact_bytes)::numeric/1048576.0 artifact_mib,
   range_agg(tstzrange(GREATEST(ar.range_start,ar.team_cutover),ar.range_end,'[)'))
     - COALESCE(rc.covered,'{}'::tstzmultirange) retained_ranges
  FROM artifact_refs ar
  LEFT JOIN retained_coverage rc ON rc.host_id=ar.interval_host_id AND rc.team_id=p_team
    AND rc.baseline_path=ar.path AND rc.allocation_identity=ar.allocation_identity
  WHERE ar.team_cutover IS NOT NULL AND ar.range_end>GREATEST(ar.range_start,ar.team_cutover)
    AND ar.artifact_bytes IS NOT NULL
  GROUP BY ar.interval_host_id,ar.path,ar.allocation_identity,rc.covered
), artifact_ranges AS (
  SELECT path,artifact_mib,retained_ranges FROM pre_ranges
  UNION ALL
  SELECT path,artifact_mib,retained_ranges FROM post_ranges
), artifacts AS (
  SELECT COALESCE(sum(artifact_mib*EXTRACT(epoch FROM (upper(r)-lower(r)))),0) amount
  FROM artifact_ranges CROSS JOIN LATERAL unnest(retained_ranges) ranges(r)
), overlays AS (
  SELECT COALESCE(sum(EXTRACT(epoch FROM (LEAST(COALESCE(ended_at,(SELECT request_now FROM bounds)),p_end)-GREATEST(started_at,p_start)))*disk_mib),0) amount
  FROM legacy_intervals
  WHERE GREATEST(started_at,p_start)<LEAST(COALESCE(ended_at,(SELECT request_now FROM bounds)),p_end)
), final_value AS (
  SELECT CASE WHEN EXISTS (
      SELECT 1 FROM artifact_refs WHERE range_end>range_start AND artifact_bytes IS NULL
    ) OR EXISTS (SELECT 1 FROM artifact_bounds WHERE unresolved_baseline) THEN NULL::numeric
    ELSE (CASE WHEN p_floor_legacy_artifacts THEN FLOOR(artifacts.amount) ELSE artifacts.amount END)
      +overlays.amount+retained_storage_mib_seconds(p_team,p_start,p_end) END amount
  FROM artifacts,overlays
)
SELECT CASE WHEN p_start>=(SELECT period_end FROM bounds) THEN 0::numeric ELSE amount END FROM final_value
$$;
