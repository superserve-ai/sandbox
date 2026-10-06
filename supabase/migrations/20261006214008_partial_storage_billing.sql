-- Capture legacy references lazily; never scan or rewrite the sandbox fleet.
ALTER TABLE template ADD COLUMN legacy_storage_rootfs_ref jsonb;
ALTER TABLE sandbox ADD COLUMN legacy_storage_refs jsonb;

CREATE FUNCTION legacy_storage_reference(p_template uuid,p_base text,p_delta text,p_capture jsonb,p_snapshot text DEFAULT NULL,p_mem text DEFAULT NULL)
RETURNS jsonb LANGUAGE sql STABLE AS $$
 SELECT COALESCE(p_capture,jsonb_build_object('base',p_base,'delta',p_delta,
   'rootfs_fallback',CASE WHEN p_base IS NULL AND p_delta IS NULL THEN
     (SELECT ref->>'path' FROM template t
      CROSS JOIN LATERAL (SELECT COALESCE(t.legacy_storage_rootfs_ref,
        jsonb_build_object('path',t.rootfs_path,'snapshot',t.snapshot_path,'mem',t.mem_path)) ref) capture
      WHERE t.id=p_template AND NULLIF(p_snapshot,'') IS NOT NULL AND NULLIF(p_mem,'') IS NOT NULL
        AND ref->>'snapshot'=p_snapshot AND ref->>'mem'=p_mem) END))
$$;

CREATE FUNCTION capture_legacy_template_reference() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.legacy_storage_rootfs_ref IS NOT NULL THEN
   NEW.legacy_storage_rootfs_ref:=OLD.legacy_storage_rootfs_ref;
 ELSIF NEW.legacy_storage_rootfs_ref IS NULL AND ROW(NEW.rootfs_path,NEW.snapshot_path,NEW.mem_path) IS DISTINCT FROM ROW(OLD.rootfs_path,OLD.snapshot_path,OLD.mem_path) THEN
   NEW.legacy_storage_rootfs_ref:=jsonb_build_object('path',OLD.rootfs_path,'snapshot',OLD.snapshot_path,'mem',OLD.mem_path);
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER capture_legacy_template_reference BEFORE UPDATE OF rootfs_path,snapshot_path,mem_path,legacy_storage_rootfs_ref
ON template FOR EACH ROW EXECUTE FUNCTION capture_legacy_template_reference();

CREATE FUNCTION capture_legacy_sandbox_reference() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='UPDATE' AND ROW(NEW.template_id,NEW.base_path,NEW.delta_path) IS DISTINCT FROM ROW(OLD.template_id,OLD.base_path,OLD.delta_path) THEN
   RAISE EXCEPTION 'sandbox storage reference identity is immutable';
 END IF;
 IF TG_OP='INSERT' THEN
   IF NEW.legacy_storage_refs IS NULL THEN
     NEW.legacy_storage_refs:=jsonb_build_object('base',NEW.base_path,'delta',NEW.delta_path,
       'rootfs_fallback',CASE WHEN NEW.base_path IS NULL AND NEW.delta_path IS NULL THEN
         (SELECT rootfs_path FROM template WHERE id=NEW.template_id
          AND NULLIF(NEW.snapshot_path,'') IS NOT NULL AND NULLIF(NEW.mem_path,'') IS NOT NULL
          AND snapshot_path=NEW.snapshot_path AND mem_path=NEW.mem_path) END);
   END IF;
 ELSIF OLD.legacy_storage_refs IS NOT NULL THEN
   NEW.legacy_storage_refs:=OLD.legacy_storage_refs;
 ELSIF ROW(NEW.snapshot_path,NEW.mem_path) IS DISTINCT FROM ROW(OLD.snapshot_path,OLD.mem_path) THEN
   NEW.legacy_storage_refs:=legacy_storage_reference(OLD.template_id,OLD.base_path,OLD.delta_path,
     NULL,OLD.snapshot_path,OLD.mem_path);
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER capture_legacy_sandbox_reference BEFORE INSERT OR UPDATE OF template_id,base_path,delta_path,snapshot_path,mem_path,legacy_storage_refs
ON sandbox FOR EACH ROW EXECUTE FUNCTION capture_legacy_sandbox_reference();

ALTER TABLE team_billing_usage_hourly
 ALTER COLUMN storage_mib_seconds DROP NOT NULL,
 ADD COLUMN known_storage_mib_seconds numeric,
 ADD COLUMN storage_complete boolean;
ALTER TABLE billing_export_measurement_queue
 ADD COLUMN known_storage_mib_seconds numeric,
 ADD COLUMN storage_complete boolean;
ALTER TABLE billing_export_measurement ADD COLUMN storage_complete boolean;
ALTER TABLE billing_export_usage ADD COLUMN storage_complete boolean;
ALTER TABLE team_billing_usage ADD COLUMN storage_complete boolean;

CREATE FUNCTION storage_usage_detail(p_team uuid,p_start timestamptz,p_end timestamptz,p_floor_legacy_artifacts boolean DEFAULT true)
RETURNS TABLE(known_mib_seconds numeric,complete boolean,blocked boolean) LANGUAGE sql STABLE AS $$
WITH sandbox_refs AS MATERIALIZED (
 SELECT s.id,s.team_id,s.template_id,s.snapshot_id,s.destroyed_at,
  refs->>'base' base_path,refs->>'delta' delta_path,refs->>'rootfs_fallback' rootfs_ref
 FROM sandbox s CROSS JOIN LATERAL (SELECT legacy_storage_reference(s.template_id,s.base_path,s.delta_path,s.legacy_storage_refs,s.snapshot_path,s.mem_path) refs) capture
 WHERE s.team_id=p_team
), bounds AS MATERIALIZED (
 SELECT LEAST(p_end,billing_request_now()) period_end,billing_request_now() request_now
), legacy_source AS MATERIALIZED (
 SELECT i.sandbox_id,i.team_id,i.host_id,i.disk_mib,i.started_at,i.ended_at,i.end_reason,
  s.destroyed_at,c.started_at team_cutover,b.period_end,b.request_now
 FROM sandbox_storage_interval i JOIN sandbox_refs s ON s.id=i.sandbox_id
 CROSS JOIN bounds b
 LEFT JOIN LATERAL (
   SELECT CASE WHEN i.host_id IS NULL THEN MIN(c.started_at)
               ELSE MIN(c.started_at) FILTER (WHERE c.host_id=i.host_id) END started_at
   FROM retained_storage_cutover c
   WHERE c.team_id=i.team_id AND (i.host_id IS NULL OR c.host_id=i.host_id)
 ) c ON true
 WHERE i.team_id=p_team AND p_start<b.period_end AND i.started_at<b.period_end
   -- An overlay interval can close while its referenced artifacts remain
   -- retained. Keep that reference until the sandbox's retention ends.
   AND (COALESCE(i.ended_at,b.period_end)>p_start
        OR COALESCE(s.destroyed_at,b.period_end)>p_start)
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
 SELECT s.id,s.template_id,s.snapshot_id,s.base_path,s.delta_path,s.rootfs_ref,
  i.host_id interval_host_id,
  GREATEST(i.started_at,x.effective_at) billing_started_at,
  LEAST(COALESCE(i.artifact_retention_end,i.request_now),COALESCE(x.ended_at,i.request_now)) retention_end,
  i.team_cutover,i.request_now,x.path baseline_path,x.generation baseline_generation,
  x.allocated_bytes baseline_allocated_bytes,
  false unresolved_baseline
 FROM sandbox_refs s JOIN legacy_intervals i ON i.sandbox_id=s.id
 JOIN sandbox_storage_baseline x ON x.sandbox_id=s.id AND x.team_id=p_team AND x.host_id=i.host_id
  AND x.effective_at<COALESCE(i.artifact_retention_end,i.request_now)
  AND COALESCE(x.ended_at,i.request_now)>i.started_at
 WHERE s.team_id=p_team
), legacy_prefix AS MATERIALIZED (
 SELECT s.id,s.template_id,s.snapshot_id,s.base_path,s.delta_path,s.rootfs_ref,
  i.host_id interval_host_id,i.started_at billing_started_at,
  LEAST(COALESCE(i.artifact_retention_end,i.request_now),COALESCE(first_segment.first_effective,i.request_now)) retention_end,
  i.team_cutover,i.request_now,
  -- Before the retained cutover, legacy artifact accounting is still
  -- path-based. Preserve that union even when no retained provenance row has
  -- arrived yet; after cutover the same absence is an unknown contribution.
  CASE WHEN i.team_cutover IS NULL OR i.started_at<i.team_cutover
       THEN s.base_path
       -- Before retained provenance existed, a full-copy sandbox could have
       -- no persisted base_path even though its immutable template manifest
       -- was already measured. Carry that known path forward prospectively;
       -- mutable template metadata is only used when the manifest proves the
       -- allocation exists.
       WHEN s.template_id IS NOT NULL AND s.base_path IS NULL
            AND s.rootfs_ref IS NOT NULL
            AND EXISTS (
              SELECT 1 FROM artifact_manifest am
              WHERE am.template_id=s.template_id AND am.path=s.rootfs_ref
                AND am.allocation_eligible_at IS NOT NULL
            )
       THEN s.rootfs_ref
  END baseline_path,
  NULL::text baseline_generation,NULL::bigint baseline_allocated_bytes,
  ((s.template_id IS NOT NULL AND s.base_path IS NULL
       AND s.rootfs_ref IS NULL
       AND i.team_cutover IS NOT NULL AND i.started_at>=i.team_cutover)
   OR (i.team_cutover IS NOT NULL AND s.base_path IS NOT NULL
       AND i.started_at>=i.team_cutover)) unresolved_baseline
 FROM sandbox_refs s JOIN legacy_intervals i ON i.sandbox_id=s.id
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
    'baseline:'||a.baseline_path||':'||COALESCE(a.baseline_generation,'')
   WHEN p.path=a.delta_path AND a.template_id IS NOT NULL
     THEN 'template-delta:'||a.template_id::text||':'||p.path
   ELSE 'private:'||a.id::text||':'||p.path END allocation_identity,
  CASE WHEN p.path=a.baseline_path THEN COALESCE(a.baseline_allocated_bytes,am_snapshot.allocated_bytes,CASE WHEN am_template.allocation_eligible_at IS NOT NULL THEN am_template.allocated_bytes END)
   ELSE COALESCE(am_snapshot.allocated_bytes,CASE WHEN am_template.allocation_eligible_at IS NOT NULL THEN am_template.allocated_bytes END) END artifact_bytes,
  GREATEST(a.billing_started_at,p_start) range_start,
  GREATEST(a.billing_started_at,p_start,CASE
    WHEN (p.path=a.baseline_path AND a.baseline_allocated_bytes IS NOT NULL) OR am_snapshot.allocated_bytes IS NOT NULL
      THEN '-infinity'::timestamptz ELSE am_template.allocation_eligible_at END) known_start,
  CASE WHEN (p.path=a.baseline_path AND a.baseline_allocated_bytes IS NOT NULL) OR am_snapshot.allocated_bytes IS NOT NULL
    THEN '-infinity'::timestamptz ELSE am_template.allocation_eligible_at END measurement_eligible_at,
  LEAST(COALESCE(a.retention_end,a.request_now),p_end) range_end,
  a.unresolved_baseline,a.template_id,a.snapshot_id,a.base_path,a.baseline_path,a.baseline_generation
 FROM artifact_bounds a
  CROSS JOIN LATERAL unnest(ARRAY[a.base_path,a.delta_path,
   CASE WHEN a.baseline_path IN (a.base_path,a.delta_path) THEN NULL
        WHEN a.baseline_path IS NOT NULL THEN a.baseline_path
        WHEN a.base_path IS NULL AND a.delta_path IS NULL THEN a.rootfs_ref
        ELSE NULL END]) p(path)
 LEFT JOIN artifact_manifest am_snapshot ON am_snapshot.snapshot_id=a.snapshot_id AND am_snapshot.path=p.path
 LEFT JOIN artifact_manifest am_template ON am_template.snapshot_id IS NULL AND am_template.template_id=a.template_id AND am_template.path=p.path
 WHERE p.path IS NOT NULL
), pre_sources AS MATERIALIZED (
 SELECT * FROM artifact_refs WHERE artifact_bytes IS NOT NULL AND range_end>known_start
   AND (team_cutover IS NULL OR known_start<team_cutover)
), pre_boundaries AS (
 SELECT path,p_start boundary FROM pre_sources
 UNION SELECT path,p_end FROM pre_sources
 UNION SELECT path,measurement_eligible_at FROM pre_sources
   WHERE measurement_eligible_at>p_start AND measurement_eligible_at<p_end
), pre_slices AS (
 SELECT path,boundary slice_start,lead(boundary) OVER(PARTITION BY path ORDER BY boundary) slice_end
 FROM pre_boundaries
), pre_ranges AS (
 -- Preserve the path-union maximum within each evidence epoch. A later,
 -- larger measurement must not raise the maximum in an earlier epoch.
 SELECT p.path,MAX(a.artifact_bytes)::numeric/1048576.0 artifact_mib,
 range_agg(tstzrange(GREATEST(a.range_start,p.slice_start),
    LEAST(a.range_end,COALESCE(a.team_cutover,a.range_end),p.slice_end),'[)'))
 FILTER(WHERE GREATEST(a.range_start,p.slice_start)<LEAST(a.range_end,COALESCE(a.team_cutover,a.range_end),p.slice_end)) retained_ranges
 FROM pre_slices p JOIN pre_sources a ON a.path=p.path AND a.measurement_eligible_at<=p.slice_start
 WHERE p.slice_end IS NOT NULL
 GROUP BY p.path,p.slice_start,p.slice_end
), retained_baselines AS MATERIALIZED (
 SELECT r.host_id,r.team_id,r.baseline_path,'baseline:'||r.baseline_path||':'||COALESCE(r.baseline_generation,'') allocation_identity,
  r.started_at,r.ended_at FROM retained_storage_interval r
 WHERE r.team_id=p_team AND r.baseline_path IS NOT NULL
), retained_coverage AS MATERIALIZED (
 SELECT host_id,team_id,baseline_path,allocation_identity,
  range_agg(tstzrange(started_at,COALESCE(ended_at,(SELECT request_now FROM bounds)),'[)')) covered
 FROM retained_baselines GROUP BY host_id,team_id,baseline_path,allocation_identity
), retained_deltas AS MATERIALIZED (
 SELECT r.host_id,r.team_id,
  'template-delta:'||s.template_id::text||':'||s.delta_path allocation_identity,
  range_agg(tstzrange(r.started_at,COALESCE(r.ended_at,(SELECT request_now FROM bounds)),'[)')) covered
 FROM retained_storage_interval r JOIN sandbox s ON r.owner_kind='sandbox' AND r.owner_id=s.id
 WHERE r.team_id=p_team AND s.team_id=p_team
   AND s.template_id IS NOT NULL AND s.delta_path IS NOT NULL
 GROUP BY r.host_id,r.team_id,s.template_id,s.delta_path
), post_ranges AS (
 SELECT ar.interval_host_id,ar.path,ar.allocation_identity,ar.artifact_bytes::numeric/1048576.0 artifact_mib,
 range_agg(tstzrange(GREATEST(ar.known_start,ar.team_cutover),ar.range_end,'[)'))
    -COALESCE(rc.covered,'{}'::tstzmultirange)
    -COALESCE(rd.covered,'{}'::tstzmultirange) retained_ranges
 FROM artifact_refs ar LEFT JOIN retained_coverage rc ON rc.host_id=ar.interval_host_id AND rc.team_id=p_team
  AND rc.baseline_path=ar.path
  AND (rc.allocation_identity=ar.allocation_identity
       OR ar.baseline_generation IS NULL)
 -- Remove a shared delta only from the artifact ranges being added here,
 -- and only while a retained owner on this host already represents it.
 LEFT JOIN retained_deltas rd ON rd.host_id=ar.interval_host_id AND rd.team_id=p_team
  AND rd.allocation_identity=ar.allocation_identity
 WHERE ar.team_cutover IS NOT NULL AND ar.range_end>GREATEST(ar.known_start,ar.team_cutover)
   AND ar.artifact_bytes IS NOT NULL
 GROUP BY ar.interval_host_id,ar.path,ar.allocation_identity,ar.artifact_bytes,rc.covered,rd.covered
), artifact_ranges AS (
 SELECT path,artifact_mib,retained_ranges FROM pre_ranges
 UNION ALL SELECT path,artifact_mib,retained_ranges FROM post_ranges
), artifacts AS (
 SELECT COALESCE(sum(artifact_mib*EXTRACT(epoch FROM (upper(r)-lower(r)))),0) amount
 FROM artifact_ranges CROSS JOIN LATERAL unnest(retained_ranges) ranges(r)
), overlays AS (
 SELECT COALESCE(sum(EXTRACT(epoch FROM (LEAST(COALESCE(ended_at,(SELECT request_now FROM bounds)),p_end)-GREATEST(started_at,p_start)))*disk_mib),0) amount
 FROM legacy_intervals WHERE GREATEST(started_at,p_start)<LEAST(COALESCE(ended_at,(SELECT request_now FROM bounds)),p_end)
), outcome AS (
 SELECT
  (CASE WHEN p_floor_legacy_artifacts THEN FLOOR(artifacts.amount) ELSE artifacts.amount END)
     +overlays.amount+COALESCE(retained.amount,0) known_mib_seconds,
  NOT (EXISTS(SELECT 1 FROM artifact_refs WHERE range_end>range_start AND (artifact_bytes IS NULL OR known_start>range_start))
    OR EXISTS(SELECT 1 FROM artifact_bounds a WHERE a.template_id IS NOT NULL
       AND a.base_path IS NULL AND a.delta_path IS NULL AND a.baseline_path IS NULL AND a.rootfs_ref IS NULL
       AND GREATEST(a.billing_started_at,p_start)<LEAST(COALESCE(a.retention_end,a.request_now),p_end))) complete,
  retained.amount IS NULL
   OR EXISTS(SELECT 1 FROM artifact_refs a WHERE a.template_id IS NULL
      AND a.artifact_bytes IS NULL AND a.range_end>a.range_start)
   OR EXISTS(SELECT 1 FROM retained_storage_measurement_obligation o
      WHERE o.team_id=p_team AND o.effective_at<LEAST(p_end,billing_request_now())
        AND o.resolved_at IS NULL AND o.ended_at IS NULL AND billing_request_now()>p_start)
   OR EXISTS(SELECT 1 FROM artifact_refs a WHERE a.unresolved_baseline AND a.team_cutover IS NOT NULL
       AND a.range_end>GREATEST(a.range_start,a.team_cutover))
   OR EXISTS(SELECT 1 FROM artifact_refs a WHERE a.team_cutover IS NOT NULL
       AND a.range_end>GREATEST(a.range_start,a.team_cutover)
       AND (a.artifact_bytes IS NULL OR a.known_start>GREATEST(a.range_start,a.team_cutover)))
   OR EXISTS(SELECT 1 FROM artifact_bounds a WHERE a.interval_host_id IS NULL
       AND a.team_cutover IS NOT NULL
       AND LEAST(COALESCE(a.retention_end,a.request_now),p_end)>a.team_cutover
       AND GREATEST(a.billing_started_at,p_start)<LEAST(COALESCE(a.retention_end,a.request_now),p_end))
   OR EXISTS(SELECT 1 FROM artifact_bounds a WHERE a.template_id IS NOT NULL AND a.base_path IS NULL
       AND a.team_cutover IS NOT NULL AND a.billing_started_at>=a.team_cutover AND a.baseline_path IS NULL
       AND GREATEST(a.billing_started_at,p_start)<LEAST(COALESCE(a.retention_end,a.request_now),p_end)) blocked
 FROM artifacts,overlays,LATERAL (SELECT retained_storage_mib_seconds(p_team,p_start,p_end) amount) retained
)
SELECT CASE WHEN p_start>=(SELECT period_end FROM bounds) THEN 0::numeric ELSE known_mib_seconds END,
 CASE WHEN p_start>=(SELECT period_end FROM bounds) THEN true ELSE complete END,
 CASE WHEN p_start>=(SELECT period_end FROM bounds) THEN false ELSE blocked END FROM outcome
$$;

CREATE OR REPLACE FUNCTION storage_mib_seconds_segmented(p_team uuid,p_start timestamptz,p_end timestamptz,p_floor_legacy_artifacts boolean DEFAULT true)
RETURNS numeric LANGUAGE sql STABLE AS $$
 SELECT CASE WHEN complete AND NOT blocked THEN known_mib_seconds END
 FROM storage_usage_detail(p_team,p_start,p_end,p_floor_legacy_artifacts)
$$;

CREATE FUNCTION billable_storage_usage_detail(p_team uuid,p_start timestamptz,p_end timestamptz)
RETURNS TABLE(known_mib_seconds numeric,complete boolean,blocked boolean) LANGUAGE sql STABLE AS $$
 WITH activation AS (SELECT GREATEST(p_start,effective_at) at FROM team_storage_billing_activation
   WHERE team_id=p_team AND effective_at<LEAST(p_end,billing_request_now()))
 SELECT d.known_mib_seconds,d.complete,d.blocked FROM activation a
 CROSS JOIN LATERAL storage_usage_detail(p_team,a.at,p_end,false) d
 UNION ALL SELECT 0::numeric,true,false WHERE NOT EXISTS(SELECT 1 FROM activation)
$$;

CREATE OR REPLACE FUNCTION billable_storage_mib_seconds(p_team_id uuid,p_start timestamptz,p_end timestamptz)
RETURNS numeric LANGUAGE sql STABLE AS $$
 SELECT CASE WHEN NOT blocked THEN known_mib_seconds END FROM billable_storage_usage_detail(p_team_id,p_start,p_end)
$$;

CREATE OR REPLACE FUNCTION clip_storage_export_cache() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE d record;
BEGIN
 IF TG_TABLE_NAME='billing_export_measurement' THEN
   SELECT * INTO d FROM billable_storage_usage_detail(NEW.team_id,GREATEST(NEW.hour_start,NEW.period_start),LEAST(NEW.hour_start+interval '1 hour',NEW.period_end));
   IF d.blocked THEN RAISE EXCEPTION 'storage measurement unavailable for export cache' USING ERRCODE='55000'; END IF;
   NEW.storage_mib_seconds:=d.known_mib_seconds;
   NEW.storage_complete:=d.complete;
 ELSE
   SELECT COALESCE(SUM(m.storage_mib_seconds),0),
     CASE WHEN count(*) FILTER(WHERE m.storage_complete=false)>0 THEN false
          WHEN count(*) FILTER(WHERE m.storage_complete IS NULL)>0 THEN NULL ELSE true END
   INTO NEW.storage_mib_seconds,NEW.storage_complete
   FROM billing_export_measurement m WHERE m.team_id=NEW.team_id AND m.period_start=NEW.period_start AND m.period_end=NEW.period_end;
 END IF;
 RETURN NEW;
END;
$$;

-- Old API close writers omit the additive completeness column. The database
-- owns both its payable quantity and status in the same measurement snapshot.
CREATE FUNCTION classify_team_storage_close() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE d record;
BEGIN
 IF TG_OP='INSERT' AND (NEW.finalized_at IS NOT NULL OR NEW.exported_at IS NOT NULL
    OR EXISTS(SELECT 1 FROM team_billing_period p WHERE p.team_id=NEW.team_id
      AND p.period_start=NEW.period_start AND p.period_end=NEW.period_end
      AND (p.finalized_at IS NOT NULL OR p.exported_at IS NOT NULL OR p.status IN ('exporting','exported','finalized')))) THEN
   RETURN NEW;
 END IF;
 IF TG_OP='UPDATE' AND (OLD.finalized_at IS NOT NULL OR OLD.exported_at IS NOT NULL
    OR EXISTS(SELECT 1 FROM team_billing_period p WHERE p.team_id=NEW.team_id
      AND p.period_start=NEW.period_start AND p.period_end=NEW.period_end
      AND (p.finalized_at IS NOT NULL OR p.exported_at IS NOT NULL OR p.status IN ('exporting','exported','finalized')))) THEN
   NEW.storage_mib_seconds:=OLD.storage_mib_seconds;
   NEW.storage_complete:=OLD.storage_complete;
   RETURN NEW;
 END IF;
 SELECT * INTO d FROM billable_storage_usage_detail(NEW.team_id,NEW.period_start,NEW.period_end);
 IF d.blocked THEN RAISE EXCEPTION 'storage measurement unavailable for period close' USING ERRCODE='55000'; END IF;
 NEW.storage_mib_seconds:=d.known_mib_seconds;
 NEW.storage_complete:=d.complete;
 RETURN NEW;
END;
$$;
CREATE TRIGGER classify_team_storage_close BEFORE INSERT OR UPDATE OF storage_mib_seconds,storage_complete
ON team_billing_usage FOR EACH ROW EXECUTE FUNCTION classify_team_storage_close();
