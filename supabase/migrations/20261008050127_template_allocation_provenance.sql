-- Allocation hashes do not prove that stat succeeded: older producers used
-- the same zero hash for measured files and unavailable legacy artifacts.
ALTER TABLE artifact_manifest
    ADD COLUMN allocation_measured_at timestamptz,
    ADD COLUMN allocation_eligible_at timestamptz,
    ADD COLUMN allocation_build_id uuid,
    ADD COLUMN allocation_attempt_id uuid;

-- Preserve established positive history. There is no trustworthy historical
-- evidence for zero in the old wire format; do not infer it from file hashes.
UPDATE artifact_manifest SET allocation_eligible_at='-infinity'
WHERE template_id IS NOT NULL AND allocated_bytes>0;

CREATE FUNCTION guard_template_allocation_provenance() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE fresh_assertion boolean; unchanged boolean := false;
BEGIN
    IF NEW.template_id IS NULL THEN
        NEW.allocation_measured_at:=NULL;
        NEW.allocation_eligible_at:=NULL;
        NEW.allocation_build_id:=NULL;
        NEW.allocation_attempt_id:=NULL;
        RETURN NEW;
    END IF;
    fresh_assertion:=NEW.allocation_measured_at IS NOT NULL
        AND NEW.allocation_build_id IS NOT NULL;
    IF TG_OP='UPDATE' THEN
        -- UPDATE OF also catches old writers assigning the same zero/path.
        fresh_assertion:=fresh_assertion
            AND NEW.allocation_measured_at IS DISTINCT FROM OLD.allocation_measured_at;
        unchanged:=NEW.template_id IS NOT DISTINCT FROM OLD.template_id
            AND NEW.snapshot_id IS NOT DISTINCT FROM OLD.snapshot_id
            AND NEW.path IS NOT DISTINCT FROM OLD.path
            AND NEW.allocated_bytes IS NOT DISTINCT FROM OLD.allocated_bytes
            -- Attaching generation proof does not revoke already-known positive
            -- path-based history. Zero still requires the same source identity.
            AND (OLD.allocated_bytes>0 OR (
                NEW.allocation_build_id IS NOT DISTINCT FROM OLD.allocation_build_id
                AND NEW.allocation_attempt_id IS NOT DISTINCT FROM OLD.allocation_attempt_id));
    END IF;
    IF fresh_assertion THEN
        IF NOT EXISTS (SELECT 1 FROM template_build b WHERE b.id=NEW.allocation_build_id
            AND b.template_id=NEW.template_id)
            OR (NEW.allocation_attempt_id IS NOT NULL AND NOT EXISTS (
                SELECT 1 FROM template_build_attempt a WHERE a.id=NEW.allocation_attempt_id
                    AND a.build_id=NEW.allocation_build_id)) THEN
            RAISE EXCEPTION 'allocation evidence does not match the template build';
        END IF;
        NEW.allocation_measured_at:=clock_timestamp();
    ELSE
        NEW.allocation_measured_at:=NULL;
        NEW.allocation_build_id:=NULL;
        NEW.allocation_attempt_id:=NULL;
    END IF;
    IF NEW.allocated_bytes<0 OR (NEW.allocated_bytes=0 AND NOT fresh_assertion) THEN
        NEW.allocation_eligible_at:=NULL;
    ELSIF unchanged AND OLD.allocation_eligible_at IS NOT NULL THEN
        NEW.allocation_eligible_at:=OLD.allocation_eligible_at;
    ELSE
        -- New evidence must never fill a historical billing gap, including
        -- quantity changes on a reused path. Caller timestamps are not trusted.
        NEW.allocation_eligible_at:=clock_timestamp();
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER template_allocation_provenance
BEFORE INSERT OR UPDATE OF template_id,snapshot_id,path,allocated_bytes,
    allocation_measured_at,allocation_eligible_at,allocation_build_id,allocation_attempt_id
ON artifact_manifest FOR EACH ROW EXECUTE FUNCTION guard_template_allocation_provenance();

CREATE FUNCTION template_allocation_bytes(p_bytes bigint,p_eligible timestamptz,p_at timestamptz)
RETURNS bigint LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE WHEN p_eligible IS NOT NULL AND p_at>=p_eligible THEN p_bytes END
$$;

CREATE OR REPLACE FUNCTION accept_template_publication(p_build uuid,p_attempt uuid)
RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE b template_build; p template_build_publication; r jsonb;
BEGIN
    PERFORM 1 FROM template WHERE id=(SELECT template_id FROM template_build WHERE id=p_build) FOR UPDATE;
    SELECT * INTO b FROM template_build WHERE id=p_build FOR UPDATE;
    IF b.status NOT IN ('building','snapshotting','ready') OR NOT EXISTS (SELECT 1 FROM template_build_execution
        WHERE build_id=b.id AND current_attempt=p_attempt)
    THEN RETURN false; END IF;
    SELECT * INTO p FROM template_build_publication WHERE build_id=b.id AND attempt_id=p_attempt;
    IF NOT FOUND OR p.accepted_at IS NOT NULL THEN RETURN false; END IF;
    PERFORM 1 FROM template WHERE id=b.template_id AND deleted_at IS NULL FOR UPDATE;
    IF NOT FOUND THEN RETURN false; END IF;
    IF template_revision_superseded(b.template_id,p.revision) THEN
        PERFORM transition_template_attempt(b.id,p_attempt,'fail','superseded by a newer version');
        RETURN false;
    END IF;
    r:=p.runtime;
    UPDATE template_build_publication SET accepted_at=now() WHERE build_id=b.id;
    IF b.status<>'ready' THEN
        UPDATE template_build_attempt SET state='ready',cleanup_pending=false WHERE id=p_attempt;
        UPDATE template_build SET status='ready',finalized_at=now(),updated_at=now(),error_message=NULL WHERE id=b.id;
        UPDATE template SET status='ready',rootfs_path=r->>'rootfs_path',snapshot_path=r->>'snapshot_path',
            mem_path=r->>'mem_path',
            vcpu=(SELECT vcpu FROM template_build_input WHERE build_id=b.id),
            memory_mib=(SELECT memory_mib FROM template_build_input WHERE build_id=b.id),
            disk_mib=(SELECT disk_mib FROM template_build_input WHERE build_id=b.id),
            base_path=NULLIF(r->>'base_path',''),delta_path=NULLIF(r->>'delta_path',''),
            size_bytes=(r->>'size_bytes')::bigint,built_at=now(),updated_at=now(),error_message=NULL
            WHERE id=b.template_id;
    END IF;
    UPDATE template_build_execution SET reason='ready; durable publication accepted' WHERE build_id=b.id;
    INSERT INTO artifact_manifest(template_id,file_name,path,size_bytes,allocated_bytes,sha256,
        allocation_measured_at,allocation_build_id,allocation_attempt_id)
    SELECT DISTINCT ON (f->>'runtime_path') b.template_id,f->>'name',f->>'runtime_path',(f->>'size_bytes')::bigint,
        GREATEST(COALESCE((f->>'allocated_bytes')::bigint,0),0),f->>'sha256',
        CASE WHEN (f->>'allocated_bytes')::bigint>0 THEN clock_timestamp() END,b.id,p_attempt
    FROM jsonb_array_elements(p.files) f
    WHERE NULLIF(f->>'runtime_path','') IS NOT NULL
    ORDER BY f->>'runtime_path'
    ON CONFLICT (template_id,path) WHERE template_id IS NOT NULL DO UPDATE
    SET file_name=EXCLUDED.file_name,size_bytes=EXCLUDED.size_bytes,
        -- An old publication may synthesize zero. It can preserve the producer's
        -- measured value only for this exact fenced generation and path.
        allocated_bytes=CASE WHEN EXCLUDED.allocated_bytes=0 AND artifact_manifest.allocation_measured_at IS NOT NULL
            AND artifact_manifest.allocation_build_id=b.id
            AND artifact_manifest.allocation_attempt_id=p_attempt
            THEN artifact_manifest.allocated_bytes ELSE EXCLUDED.allocated_bytes END,
        sha256=EXCLUDED.sha256,
        allocation_measured_at=CASE WHEN EXCLUDED.allocated_bytes>0 OR (artifact_manifest.allocation_measured_at IS NOT NULL
            AND artifact_manifest.allocation_build_id=b.id
            AND artifact_manifest.allocation_attempt_id=p_attempt)
            THEN clock_timestamp() END,
        allocation_build_id=b.id,allocation_attempt_id=p_attempt;
    RETURN true;
END;
$$;

DROP FUNCTION finalize_template_build(uuid,uuid,jsonb,bigint,bigint,bigint);
CREATE OR REPLACE FUNCTION finalize_template_build(p_build uuid,p_attempt uuid,p_runtime jsonb,
    p_rootfs_allocated bigint,p_base_allocated bigint,p_delta_allocated bigint,p_allocations_verified boolean DEFAULT false)
RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE b template_build;
BEGIN
    PERFORM 1 FROM template WHERE id=(SELECT template_id FROM template_build WHERE id=p_build) FOR UPDATE;
    SELECT * INTO b FROM template_build WHERE id=p_build FOR UPDATE;
    IF b.status NOT IN ('building','snapshotting') OR NOT EXISTS (SELECT 1 FROM template_build_execution
        WHERE build_id=b.id AND current_attempt=p_attempt)
    THEN RETURN false; END IF;
    PERFORM 1 FROM template WHERE id=b.template_id AND deleted_at IS NULL FOR UPDATE;
    IF NOT FOUND THEN RETURN false; END IF;
    IF template_revision_superseded(b.template_id,
        (SELECT revision FROM template_build_execution WHERE build_id=b.id)) THEN
        PERFORM transition_template_attempt(b.id,p_attempt,'fail','superseded by a newer version');
        RETURN false;
    END IF;
    UPDATE template_build_attempt SET state='ready',cleanup_pending=false WHERE id=p_attempt;
    UPDATE template_build SET status='ready',finalized_at=now(),updated_at=now(),error_message=NULL WHERE id=b.id;
    UPDATE template_build_execution SET reason='ready; durable publication pending' WHERE build_id=b.id;
    UPDATE template SET status='ready',rootfs_path=p_runtime->>'rootfs_path',snapshot_path=p_runtime->>'snapshot_path',
        mem_path=p_runtime->>'mem_path',
        vcpu=(SELECT vcpu FROM template_build_input WHERE build_id=b.id),
        memory_mib=(SELECT memory_mib FROM template_build_input WHERE build_id=b.id),
        disk_mib=(SELECT disk_mib FROM template_build_input WHERE build_id=b.id),
        base_path=NULLIF(p_runtime->>'base_path',''),delta_path=NULLIF(p_runtime->>'delta_path',''),
        size_bytes=(p_runtime->>'size_bytes')::bigint,built_at=now(),updated_at=now(),error_message=NULL
        WHERE id=b.template_id;
    INSERT INTO artifact_manifest(template_id,file_name,path,size_bytes,allocated_bytes,sha256,
        allocation_measured_at,allocation_build_id,allocation_attempt_id)
    SELECT DISTINCT ON (a.path) b.template_id,a.file_name,a.path,a.size_bytes,
        GREATEST(COALESCE(a.allocated_bytes,0),0),repeat('0',64),
        CASE WHEN p_allocations_verified AND a.allocated_bytes>=0 THEN clock_timestamp() END,b.id,p_attempt
    FROM (VALUES
        ('rootfs.ext4',p_runtime->>'rootfs_path',COALESCE((p_runtime->>'size_bytes')::bigint,0),p_rootfs_allocated),
        ('base.ext4',NULLIF(p_runtime->>'base_path',''),0::bigint,p_base_allocated),
        ('delta.ext4',NULLIF(p_runtime->>'delta_path',''),0::bigint,p_delta_allocated)
    ) AS a(file_name,path,size_bytes,allocated_bytes)
    WHERE a.path IS NOT NULL
    ORDER BY a.path,(a.file_name='rootfs.ext4') DESC
    ON CONFLICT (template_id,path) WHERE template_id IS NOT NULL DO UPDATE
    SET size_bytes=EXCLUDED.size_bytes,allocated_bytes=EXCLUDED.allocated_bytes,
        allocation_measured_at=EXCLUDED.allocation_measured_at,
        allocation_build_id=EXCLUDED.allocation_build_id,allocation_attempt_id=EXCLUDED.allocation_attempt_id;
    PERFORM accept_template_publication(b.id,p_attempt);
    RETURN true;
END;
$$;

-- Reconcile template deltas inside the segmented artifact union, using the
-- same clipped ranges as legacy accounting before adding physical usage.
CREATE OR REPLACE FUNCTION storage_mib_seconds_segmented(p_team uuid,p_start timestamptz,p_end timestamptz,p_floor_legacy_artifacts boolean DEFAULT true)
RETURNS numeric LANGUAGE sql STABLE AS $$
WITH bounds AS MATERIALIZED (
 SELECT LEAST(p_end,billing_request_now()) period_end,billing_request_now() request_now
), legacy_source AS MATERIALIZED (
 SELECT i.sandbox_id,i.team_id,i.host_id,i.disk_mib,i.started_at,i.ended_at,i.end_reason,
  s.destroyed_at,c.started_at team_cutover,b.period_end,b.request_now
 FROM sandbox_storage_interval i JOIN sandbox s ON s.id=i.sandbox_id
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
            AND t.rootfs_path IS NOT NULL
            AND EXISTS (
              SELECT 1 FROM artifact_manifest am
              WHERE am.template_id=s.template_id AND am.path=t.rootfs_path
                AND template_allocation_bytes(am.allocated_bytes,am.allocation_eligible_at,GREATEST(i.started_at,p_start)) IS NOT NULL
            )
       THEN t.rootfs_path
  END baseline_path,
  NULL::text baseline_generation,NULL::bigint baseline_allocated_bytes,
  ((s.template_id IS NOT NULL AND s.base_path IS NULL
       AND t.rootfs_path IS NULL
       AND i.team_cutover IS NOT NULL AND i.started_at>=i.team_cutover)
   OR (i.team_cutover IS NOT NULL AND s.base_path IS NOT NULL
       AND i.started_at>=i.team_cutover)) unresolved_baseline
 FROM sandbox s JOIN legacy_intervals i ON i.sandbox_id=s.id
 LEFT JOIN template t ON t.id=s.template_id
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
  CASE WHEN p.path=a.baseline_path THEN COALESCE(a.baseline_allocated_bytes,am_snapshot.allocated_bytes,template_allocation_bytes(am_template.allocated_bytes,am_template.allocation_eligible_at,GREATEST(a.billing_started_at,p_start)))
   ELSE COALESCE(am_snapshot.allocated_bytes,template_allocation_bytes(am_template.allocated_bytes,am_template.allocation_eligible_at,GREATEST(a.billing_started_at,p_start))) END artifact_bytes,
  GREATEST(a.billing_started_at,p_start) range_start,
  LEAST(COALESCE(a.retention_end,a.request_now),p_end) range_end,
  a.unresolved_baseline,a.template_id,a.base_path,a.baseline_path,a.baseline_generation
 FROM artifact_bounds a
 LEFT JOIN template t ON t.id=a.template_id
 CROSS JOIN LATERAL unnest(ARRAY[a.base_path,a.delta_path,
   CASE WHEN a.baseline_path IN (a.base_path,a.delta_path) THEN NULL
        WHEN a.baseline_path IS NOT NULL THEN a.baseline_path
        WHEN a.base_path IS NULL AND a.delta_path IS NULL THEN t.rootfs_path
        ELSE NULL END]) p(path)
 LEFT JOIN artifact_manifest am_snapshot ON am_snapshot.snapshot_id=a.snapshot_id AND am_snapshot.path=p.path
 LEFT JOIN artifact_manifest am_template ON am_template.snapshot_id IS NULL AND am_template.template_id=a.template_id AND am_template.path=p.path
 WHERE p.path IS NOT NULL
), pre_ranges AS (
 -- Pre-cutover history retains the legacy path-union semantics: references
 -- sharing a path are one allocation, and the largest observed allocation
 -- applies over the complete reference-lifetime union.  Retained generation
 -- identities are intentionally introduced only at the prospective cutover.
 SELECT path,MAX(artifact_bytes)::numeric/1048576.0 artifact_mib,
 range_agg(tstzrange(range_start,LEAST(range_end,COALESCE(team_cutover,range_end)),'[)')) retained_ranges
 FROM artifact_refs
 WHERE artifact_bytes IS NOT NULL AND range_end>range_start
   AND (team_cutover IS NULL OR range_start<team_cutover)
 GROUP BY path
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
 range_agg(tstzrange(GREATEST(ar.range_start,ar.team_cutover),ar.range_end,'[)'))
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
 WHERE ar.team_cutover IS NOT NULL AND ar.range_end>GREATEST(ar.range_start,ar.team_cutover)
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
), final_value AS (
 SELECT CASE WHEN EXISTS(SELECT 1 FROM artifact_refs WHERE range_end>range_start AND artifact_bytes IS NULL)
   OR EXISTS(SELECT 1 FROM artifact_refs a WHERE a.unresolved_baseline AND a.team_cutover IS NOT NULL
       AND a.range_end>GREATEST(a.range_start,a.team_cutover))
   OR EXISTS(SELECT 1 FROM artifact_bounds a WHERE a.interval_host_id IS NULL
       AND a.team_cutover IS NOT NULL
       AND LEAST(COALESCE(a.retention_end,a.request_now),p_end)>a.team_cutover
       AND GREATEST(a.billing_started_at,p_start)
           < LEAST(COALESCE(a.retention_end,a.request_now),p_end))
   OR EXISTS(SELECT 1 FROM artifact_bounds a WHERE a.template_id IS NOT NULL AND a.base_path IS NULL
       AND a.team_cutover IS NOT NULL
       AND a.billing_started_at >= a.team_cutover
       AND a.baseline_path IS NULL
	       -- An unresolved legacy prefix must not poison a wholly later
	       -- window whose retained receipts have supplied valid provenance.
	       AND GREATEST(a.billing_started_at,p_start)
	           < LEAST(COALESCE(a.retention_end,a.request_now),p_end))
  THEN NULL::numeric
  ELSE (CASE WHEN p_floor_legacy_artifacts THEN FLOOR(artifacts.amount) ELSE artifacts.amount END)
    +overlays.amount+retained_storage_mib_seconds(p_team,p_start,p_end) END amount
 FROM artifacts,overlays
)
SELECT CASE WHEN p_start>=(SELECT period_end FROM bounds) THEN 0::numeric ELSE amount END FROM final_value
$$;

