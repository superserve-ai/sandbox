-- The artifact upload yields to pause generations, so its completion time
-- tracks unrelated load rather than the build. Readiness is recorded from the
-- producer's report; durability stays separate, in accepted_at.

-- Promotion no longer implies a publication row, so a newer revision supersedes
-- once it is promoted, not only once its upload is accepted.
CREATE OR REPLACE FUNCTION template_revision_superseded(p_template uuid,p_revision bigint)
RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT EXISTS (SELECT 1 FROM template_build_publication
            WHERE template_id=p_template AND accepted_at IS NOT NULL AND revision>p_revision)
        OR EXISTS (SELECT 1 FROM template_build tb
            JOIN template_build_execution e ON e.build_id=tb.id
            WHERE tb.template_id=p_template AND tb.status='ready' AND e.revision>p_revision);
$$;

-- Only the finalizer and acceptance put an attempt in 'ready', so gating on the
-- attempt still refuses a direct write from an older binary.
CREATE OR REPLACE FUNCTION guard_template_build_execution() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e template_build_execution;
BEGIN
    SELECT * INTO e FROM template_build_execution WHERE build_id=NEW.id;
    IF NOT FOUND THEN RETURN NEW; END IF;
    IF NEW.status IN ('building','snapshotting') AND NOT EXISTS (
        SELECT 1 FROM template_build_attempt a WHERE a.id=e.current_attempt
        AND a.vm_id=NEW.vmd_build_vm_id AND a.host_id=NEW.vmd_host_id
        AND a.state IN ('claimed','admitted','uploading')) THEN
        RAISE EXCEPTION 'build requires a current fenced attempt';
    END IF;
    IF NEW.status='ready' AND NOT EXISTS (
        SELECT 1 FROM template_build_attempt a WHERE a.id=e.current_attempt AND a.state='ready') THEN
        RAISE EXCEPTION 'build requires a finalized attempt';
    END IF;
    IF NEW.status IN ('failed','cancelled') AND OLD.status IN ('pending','building','snapshotting') THEN
        UPDATE template_build_attempt SET state='fenced', cleanup_pending=true
        WHERE build_id=NEW.id AND state IN ('claimed','admitted','uploading');
    END IF;
    RETURN NEW;
END;
$$;

-- Records durability, and still promotes when it beats the producer's status
-- poll. Replaces the placeholder hashes either way.
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
    INSERT INTO artifact_manifest(template_id,file_name,path,size_bytes,allocated_bytes,sha256)
    SELECT DISTINCT ON (f->>'runtime_path') b.template_id,f->>'name',f->>'runtime_path',(f->>'size_bytes')::bigint,
        GREATEST(COALESCE((f->>'allocated_bytes')::bigint,0),0),f->>'sha256'
    FROM jsonb_array_elements(p.files) f
    WHERE NULLIF(f->>'runtime_path','') IS NOT NULL
    ORDER BY f->>'runtime_path'
    ON CONFLICT (template_id,path) WHERE template_id IS NOT NULL DO UPDATE
    SET file_name=EXCLUDED.file_name,size_bytes=EXCLUDED.size_bytes,
        allocated_bytes=EXCLUDED.allocated_bytes,sha256=EXCLUDED.sha256;
    RETURN true;
END;
$$;

-- The trailing acceptance covers a publication recorded while still building.
CREATE OR REPLACE FUNCTION finalize_template_build(p_build uuid,p_attempt uuid,p_runtime jsonb,
    p_rootfs_allocated bigint,p_base_allocated bigint,p_delta_allocated bigint)
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
    -- Allocation is measured here: storage accounting reads these rows before
    -- any upload finishes. Verified hashes arrive with the publication.
    INSERT INTO artifact_manifest(template_id,file_name,path,size_bytes,allocated_bytes,sha256)
    SELECT DISTINCT ON (a.path) b.template_id,a.file_name,a.path,a.size_bytes,
        GREATEST(COALESCE(a.allocated_bytes,0),0),repeat('0',64)
    FROM (VALUES
        ('rootfs.ext4',p_runtime->>'rootfs_path',COALESCE((p_runtime->>'size_bytes')::bigint,0),p_rootfs_allocated),
        ('base.ext4',NULLIF(p_runtime->>'base_path',''),0::bigint,p_base_allocated),
        ('delta.ext4',NULLIF(p_runtime->>'delta_path',''),0::bigint,p_delta_allocated)
    ) AS a(file_name,path,size_bytes,allocated_bytes)
    WHERE a.path IS NOT NULL
    ORDER BY a.path,(a.file_name='rootfs.ext4') DESC
    ON CONFLICT (template_id,path) WHERE template_id IS NOT NULL DO UPDATE
    SET size_bytes=EXCLUDED.size_bytes,allocated_bytes=EXCLUDED.allocated_bytes;
    PERFORM accept_template_publication(b.id,p_attempt);
    RETURN true;
END;
$$;

-- Banks durability inline: the reconcile loop no longer tracks a ready build.
CREATE OR REPLACE FUNCTION record_template_publication(p_attempt uuid,p_host text,p_bucket text,p_generation text,
    p_manifest text,p_files jsonb,p_runtime jsonb,p_verified timestamptz)
RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE b template_build; a template_build_attempt; e template_build_execution; recorded boolean;
BEGIN
    PERFORM 1 FROM template WHERE id=(SELECT tb.template_id FROM template_build tb JOIN template_build_attempt x ON x.build_id=tb.id WHERE x.id=p_attempt) FOR UPDATE;
    SELECT tb.* INTO b FROM template_build tb JOIN template_build_attempt x ON x.build_id=tb.id
        WHERE x.id=p_attempt FOR UPDATE OF tb;
    SELECT * INTO a FROM template_build_attempt WHERE id=p_attempt;
    SELECT * INTO e FROM template_build_execution WHERE build_id=b.id;
    IF a.id IS NULL OR a.host_id<>p_host OR e.current_attempt IS DISTINCT FROM a.id
       OR a.state NOT IN ('admitted','uploading','ready')
       OR b.status NOT IN ('building','snapshotting','ready') THEN RETURN false; END IF;
    IF EXISTS (SELECT 1 FROM template WHERE id=b.template_id AND deleted_at IS NOT NULL) THEN RETURN false; END IF;
    INSERT INTO template_build_publication(build_id,attempt_id,template_id,team_id,cell,revision,
        bucket,generation,manifest_object,files,runtime,verified_at)
    VALUES (b.id,a.id,b.template_id,b.team_id,e.cell,e.revision,p_bucket,p_generation,p_manifest,p_files,p_runtime,p_verified)
    ON CONFLICT (build_id) DO NOTHING;
    recorded:=EXISTS (SELECT 1 FROM template_build_publication WHERE build_id=b.id AND attempt_id=a.id
        AND bucket=p_bucket AND generation=p_generation AND files=p_files AND runtime=p_runtime);
    IF recorded AND b.status='ready' THEN
        PERFORM accept_template_publication(b.id,a.id);
    END IF;
    RETURN recorded;
END;
$$;
