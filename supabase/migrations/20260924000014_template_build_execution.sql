-- Quiesce legacy submitters, drain or cancel their builds, then quiesce
-- supervisors before migrating. The lock closes the check/write race.
BEGIN;
LOCK TABLE template_build IN SHARE ROW EXCLUSIVE MODE;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM template_build WHERE status IN ('pending','building','snapshotting')) THEN
        RAISE EXCEPTION 'legacy template builds are still active; drain or cancel them before the durable-build upgrade';
    END IF;
END;
$$;

-- Separate tables keep historical local-only builds distinguishable forever.
CREATE SEQUENCE template_build_revision_seq;
CREATE TABLE template_build_execution (
    build_id uuid PRIMARY KEY REFERENCES template_build(id),
    revision bigint NOT NULL DEFAULT nextval('template_build_revision_seq'),
    cell text,
    current_attempt uuid,
    first_started_at timestamptz,
    reconcile_checked_at timestamptz,
    reason text NOT NULL DEFAULT 'waiting for eligible host/capacity'
);
CREATE TABLE template_build_attempt (
    id uuid PRIMARY KEY,
    build_id uuid NOT NULL REFERENCES template_build_execution(build_id),
    host_id text NOT NULL,
    incarnation_id uuid NOT NULL,
    vm_id text NOT NULL UNIQUE,
    state text NOT NULL CHECK (state IN ('claimed','admitted','uploading','failed','fenced','rejected','ready')),
    claimed_at timestamptz NOT NULL DEFAULT now(),
    admitted_at timestamptz,
    reason text NOT NULL DEFAULT '',
    cleanup_checked_at timestamptz,
    cleanup_pending boolean NOT NULL DEFAULT false
);
ALTER TABLE template_build_execution ADD FOREIGN KEY (current_attempt) REFERENCES template_build_attempt(id);
CREATE INDEX template_build_attempt_owner ON template_build_attempt(build_id, claimed_at);
CREATE INDEX template_build_attempt_cleanup ON template_build_attempt(claimed_at) WHERE cleanup_pending;
CREATE TABLE template_build_publication (
    build_id uuid PRIMARY KEY REFERENCES template_build_execution(build_id),
    attempt_id uuid NOT NULL UNIQUE REFERENCES template_build_attempt(id),
    template_id uuid NOT NULL REFERENCES template(id),
    team_id uuid NOT NULL REFERENCES team(id),
    cell text NOT NULL,
    revision bigint NOT NULL,
    bucket text NOT NULL,
    generation text NOT NULL,
    manifest_object text NOT NULL,
    files jsonb NOT NULL,
    runtime jsonb NOT NULL,
    verified_at timestamptz NOT NULL,
    accepted_at timestamptz
);
ALTER TABLE template_build_execution ENABLE ROW LEVEL SECURITY;
ALTER TABLE template_build_attempt ENABLE ROW LEVEL SECURITY;
ALTER TABLE template_build_publication ENABLE ROW LEVEL SECURITY;

CREATE FUNCTION initialize_template_build_execution() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO template_build_execution(build_id) VALUES (NEW.build_id);
    RETURN NEW;
END;
$$;
CREATE TRIGGER initialize_template_build_execution AFTER INSERT ON template_build_input
FOR EACH ROW EXECUTE FUNCTION initialize_template_build_execution();

-- Old binaries cannot dispatch or promote a new-contract build. Cancellation
-- remains compatible; its trigger fences every recorded attempt in the txn.
CREATE FUNCTION guard_template_build_execution() RETURNS trigger LANGUAGE plpgsql AS $$
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
        SELECT 1 FROM template_build_publication p WHERE p.build_id=NEW.id
        AND p.attempt_id=e.current_attempt AND p.accepted_at IS NOT NULL) THEN
        RAISE EXCEPTION 'build requires an accepted durable publication';
    END IF;
    IF NEW.status IN ('failed','cancelled') AND OLD.status IN ('pending','building','snapshotting') THEN
        UPDATE template_build_attempt SET state='fenced', cleanup_pending=true
        WHERE build_id=NEW.id AND state IN ('claimed','admitted','uploading');
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER guard_template_build_execution BEFORE UPDATE ON template_build
FOR EACH ROW EXECUTE FUNCTION guard_template_build_execution();

-- The report identifies builds actually included in VMD's sampled counters.
-- Receipt time alone cannot prove inclusion when a report is delayed.
ALTER TABLE host_pressure ADD COLUMN included_build_vm_ids text[] NOT NULL DEFAULT '{}';
ALTER TABLE host_pressure ADD COLUMN included_build_slot_vm_ids text[] NOT NULL DEFAULT '{}';

-- Call under the host lock so a heartbeat cannot replace pressure between
-- the admission check and the claim. CPU/memory remain ranking signals.
CREATE FUNCTION template_build_host_has_capacity(p_host text, p_incarnation uuid, p_attempt uuid)
RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT EXISTS (
        SELECT 1 FROM host_pressure hp
        CROSS JOIN LATERAL (
            -- VM and slot samples can include an attempt at different times.
            -- A named slot from a report received after claim is already in
            -- used_net_slots; all other pending slots still need a charge.
            SELECT count(*) AS pending,
                   count(*) FILTER (WHERE NOT (
                       hp.reported_at >= a.claimed_at
                       AND a.vm_id = ANY(hp.included_build_slot_vm_ids)
                   )) AS pending_net_slots
            FROM template_build_attempt a
            WHERE a.host_id=p_host AND a.incarnation_id=p_incarnation
              AND a.id IS DISTINCT FROM p_attempt
              AND (a.state IN ('claimed','admitted','uploading') OR a.cleanup_pending)
              AND NOT (a.vm_id = ANY(hp.included_build_vm_ids))
        ) attempts
        WHERE hp.host_id=p_host
          AND hp.reported_at>now()-interval '90 seconds'
          AND hp.unknown_allocation_vms=0
          AND (hp.max_sandboxes=0 OR
               hp.running_sandboxes::bigint+hp.provisioning_sandboxes+hp.paused_sandboxes+attempts.pending+1<=hp.max_sandboxes)
          -- Builds claim fresh slots; they cannot consume a warm slot.
          AND (hp.max_network_slots=0 OR
               hp.used_net_slots::bigint+hp.provisioning_net_slots+hp.warm_net_slots+attempts.pending_net_slots+
               CASE WHEN p_attempt IS NOT NULL AND EXISTS (
                   SELECT 1 FROM template_build_attempt own
                   WHERE own.id=p_attempt AND own.host_id=p_host AND own.incarnation_id=p_incarnation
                     AND own.state='claimed' AND hp.reported_at >= own.claimed_at
                     AND own.vm_id=ANY(hp.included_build_slot_vm_ids)
               ) THEN 0 ELSE 1 END<=hp.max_network_slots)
          AND (hp.net_slot_ceiling=0 OR
               hp.used_net_slots::bigint+hp.provisioning_net_slots+hp.warm_net_slots+attempts.pending_net_slots+
               CASE WHEN p_attempt IS NOT NULL AND EXISTS (
                   SELECT 1 FROM template_build_attempt own
                   WHERE own.id=p_attempt AND own.host_id=p_host AND own.incarnation_id=p_incarnation
                     AND own.state='claimed' AND hp.reported_at >= own.claimed_at
                     AND own.vm_id=ANY(hp.included_build_slot_vm_ids)
               ) THEN 0 ELSE 1 END<=hp.net_slot_ceiling)
    );
$$;

-- Advisory serialization covers the global logical-build limit, including
-- replacement waits. It does not reserve CPU or memory against sandbox work.
CREATE FUNCTION claim_template_build(p_build uuid, p_cell text, p_limit integer)
RETURNS uuid LANGUAGE plpgsql AS $$
DECLARE b template_build; e template_build_execution; h host; aid uuid;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('template-build-dispatch'));
    PERFORM 1 FROM template WHERE id=(SELECT template_id FROM template_build WHERE id=p_build) FOR UPDATE;
    SELECT * INTO b FROM template_build WHERE id=p_build FOR UPDATE;
    SELECT * INTO e FROM template_build_execution WHERE build_id=p_build FOR UPDATE;
    IF NOT FOUND OR b.status NOT IN ('pending','building','snapshotting') OR e.current_attempt IS NOT NULL
       OR p_cell='' OR (e.cell IS NOT NULL AND e.cell<>p_cell)
       OR NOT EXISTS (SELECT 1 FROM template WHERE id=b.template_id AND deleted_at IS NULL) THEN RETURN NULL; END IF;
    IF e.first_started_at IS NULL THEN
        IF b.created_at + interval '2 minutes' <= now() THEN RETURN NULL; END IF;
        IF (SELECT count(*) FROM template_build_execution x JOIN template_build y ON y.id=x.build_id
            WHERE x.first_started_at IS NOT NULL AND y.status IN ('pending','building','snapshotting')) >= p_limit
        THEN RETURN NULL; END IF;
    ELSIF e.first_started_at + interval '30 minutes' <= now() THEN RETURN NULL;
    END IF;
    IF (SELECT count(*) FROM template_build_attempt WHERE build_id=p_build AND state<>'rejected') >= 3
    THEN RETURN NULL; END IF;
    -- Lock candidate before evaluating capabilities in the next statement:
    -- a drain/heartbeat that wins the lock cannot leave a stale attestation.
    FOR h IN SELECT host.* FROM host
        LEFT JOIN host_pressure hp ON hp.host_id=host.id
        WHERE host.status='active' AND host.region=p_cell
          AND host.incarnation_id IS NOT NULL
          AND host.last_heartbeat_at > now()-interval '2 minutes'
          AND NOT EXISTS (SELECT 1 FROM template_build_attempt a
              WHERE a.build_id=p_build AND a.host_id=host.id AND (a.state IN ('failed','fenced') OR (a.state='rejected' AND a.claimed_at>now()-interval '5 seconds')))
        ORDER BY (SELECT count(*) FROM template_build_attempt a WHERE a.host_id=host.id AND a.incarnation_id=host.incarnation_id
                  AND (a.state IN ('claimed','admitted','uploading') OR a.cleanup_pending)),
                 CASE WHEN host.capacity_memory_mib>0 THEN
                   (COALESCE(hp.allocated_memory_mib,0)+(SELECT memory_mib FROM template_build_input WHERE build_id=p_build))::numeric/host.capacity_memory_mib ELSE 1e9 END,
                 CASE WHEN host.capacity_vcpus>0 THEN
                   (COALESCE(hp.allocated_vcpus,0)+(SELECT vcpu FROM template_build_input WHERE build_id=p_build))::numeric/host.capacity_vcpus ELSE 1e9 END, host.id
        FOR SHARE OF host
    LOOP
        IF NOT EXISTS (SELECT 1 FROM host_capability hc WHERE hc.host_id=h.id
            AND hc.capability='template_build_v1' AND hc.heartbeat_at=h.last_heartbeat_at)
        THEN CONTINUE; END IF;
        IF NOT template_build_host_has_capacity(h.id,h.incarnation_id,NULL)
        THEN CONTINUE; END IF;
        aid := gen_random_uuid();
        INSERT INTO template_build_attempt(id,build_id,host_id,incarnation_id,vm_id,state)
        VALUES (aid,p_build,h.id,h.incarnation_id,'build-'||aid::text,'claimed');
        UPDATE template_build_execution SET cell=p_cell,current_attempt=aid,
            first_started_at=COALESCE(first_started_at,now()),reason='dispatching' WHERE build_id=p_build;
        UPDATE template_build SET status='building',started_at=(SELECT first_started_at FROM template_build_execution WHERE build_id=p_build),
            vmd_host_id=h.id,vmd_build_vm_id='build-'||aid::text,updated_at=now() WHERE id=p_build;
        RETURN aid;
    END LOOP;
    UPDATE template_build_execution SET reason='waiting for eligible host/capacity' WHERE build_id=p_build;
    RETURN NULL;
END;
$$;

CREATE FUNCTION admit_template_build(p_attempt uuid,p_host text,p_incarnation uuid)
RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE a template_build_attempt; b template_build; h host;
BEGIN
    PERFORM 1 FROM template WHERE id=(SELECT tb.template_id FROM template_build tb JOIN template_build_attempt x ON x.build_id=tb.id WHERE x.id=p_attempt) FOR UPDATE;
    SELECT tb.* INTO b FROM template_build tb JOIN template_build_attempt x ON x.build_id=tb.id
        WHERE x.id=p_attempt FOR UPDATE OF tb;
    SELECT * INTO a FROM template_build_attempt WHERE id=p_attempt;
    IF a.id IS NULL OR b.status NOT IN ('building','snapshotting') OR a.host_id<>p_host
       OR a.incarnation_id<>p_incarnation OR NOT EXISTS (SELECT 1 FROM template_build_execution
       WHERE build_id=b.id AND current_attempt=a.id AND first_started_at+interval '30 minutes'>now()) THEN RETURN false; END IF;
    IF a.state IN ('admitted','uploading') THEN RETURN false; END IF;
    IF a.state<>'claimed' THEN RETURN false; END IF;
    SELECT * INTO h FROM host WHERE id=p_host FOR SHARE;
    IF NOT FOUND OR h.status<>'active' OR h.incarnation_id IS DISTINCT FROM p_incarnation
       OR h.last_heartbeat_at <= now()-interval '2 minutes' OR NOT EXISTS (
       SELECT 1 FROM host_capability WHERE host_id=p_host AND capability='template_build_v1'
       AND heartbeat_at=h.last_heartbeat_at)
       OR NOT template_build_host_has_capacity(p_host,p_incarnation,a.id) THEN
        UPDATE template_build_attempt SET state='rejected',reason='host admission rejected' WHERE id=a.id;
        UPDATE template_build_execution SET current_attempt=NULL,reason='host admission rejected',
            first_started_at=CASE WHEN NOT EXISTS (SELECT 1 FROM template_build_attempt WHERE build_id=b.id AND state<>'rejected') THEN NULL ELSE first_started_at END
            WHERE build_id=b.id;
        UPDATE template_build SET status='pending',vmd_host_id=NULL,vmd_build_vm_id=NULL,updated_at=now() WHERE id=b.id;
        RETURN false;
    END IF;
    UPDATE template_build_attempt SET state='admitted',admitted_at=now() WHERE id=a.id;
    UPDATE template_build_execution SET reason='running on admitted host' WHERE build_id=b.id;
    RETURN true;
END;
$$;

CREATE FUNCTION transition_template_attempt(p_build uuid,p_attempt uuid,p_action text,p_reason text)
RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE b template_build; e template_build_execution;
BEGIN
    PERFORM 1 FROM template WHERE id=(SELECT template_id FROM template_build WHERE id=p_build) FOR UPDATE;
    SELECT * INTO b FROM template_build WHERE id=p_build FOR UPDATE;
    SELECT * INTO e FROM template_build_execution WHERE build_id=p_build FOR UPDATE;
    IF b.status NOT IN ('pending','building','snapshotting') OR e.build_id IS NULL
       OR e.current_attempt IS DISTINCT FROM p_attempt THEN RETURN false; END IF;
    IF p_action='reject' THEN
        UPDATE template_build_attempt SET state='rejected',reason=p_reason WHERE id=p_attempt AND state='claimed';
        IF NOT FOUND THEN RETURN false; END IF;
        UPDATE template_build_execution SET current_attempt=NULL,reason=p_reason,
            first_started_at=CASE WHEN NOT EXISTS (SELECT 1 FROM template_build_attempt WHERE build_id=p_build AND state<>'rejected') THEN NULL ELSE first_started_at END WHERE build_id=p_build;
        UPDATE template_build SET status='pending',vmd_host_id=NULL,vmd_build_vm_id=NULL,updated_at=now() WHERE id=p_build;
    ELSIF p_action='retry' THEN
        -- A received durable result wins over infrastructure-loss observations.
        IF EXISTS (SELECT 1 FROM template_build_publication WHERE build_id=p_build AND attempt_id=p_attempt)
        THEN RETURN false; END IF;
        UPDATE template_build_attempt SET state='failed',reason=p_reason,cleanup_pending=true WHERE id=p_attempt;
        UPDATE template_build_execution SET current_attempt=NULL,reason=p_reason WHERE build_id=p_build;
        UPDATE template_build SET status='pending',vmd_host_id=NULL,vmd_build_vm_id=NULL,updated_at=now() WHERE id=p_build;
    ELSIF p_action='uploading' THEN
        UPDATE template_build_attempt SET state='uploading' WHERE id=p_attempt AND state IN ('admitted','claimed');
        UPDATE template_build_execution SET reason='waiting for verified durable publication' WHERE build_id=p_build;
    ELSIF p_action='fail' THEN
        UPDATE template_build SET status='failed',error_message=p_reason,finalized_at=now(),updated_at=now() WHERE id=p_build;
        UPDATE template SET status='failed',error_message=p_reason,updated_at=now()
            WHERE id=b.template_id AND rootfs_path IS NULL AND deleted_at IS NULL;
    ELSE RAISE EXCEPTION 'unknown attempt transition'; END IF;
    RETURN true;
END;
$$;

-- The uploader's authenticated verified-generation report is persisted before
-- acknowledging the outbox. Readiness can subsequently recover with no host.
CREATE FUNCTION record_template_publication(p_attempt uuid,p_host text,p_bucket text,p_generation text,
    p_manifest text,p_files jsonb,p_runtime jsonb,p_verified timestamptz)
RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE b template_build; a template_build_attempt; e template_build_execution;
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
    RETURN EXISTS (SELECT 1 FROM template_build_publication WHERE build_id=b.id AND attempt_id=a.id
        AND bucket=p_bucket AND generation=p_generation AND files=p_files AND runtime=p_runtime);
END;
$$;

CREATE FUNCTION accept_template_publication(p_build uuid,p_attempt uuid)
RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE b template_build; p template_build_publication; r jsonb;
BEGIN
    PERFORM 1 FROM template WHERE id=(SELECT template_id FROM template_build WHERE id=p_build) FOR UPDATE;
    SELECT * INTO b FROM template_build WHERE id=p_build FOR UPDATE;
    IF b.status NOT IN ('building','snapshotting') OR NOT EXISTS (SELECT 1 FROM template_build_execution
        WHERE build_id=b.id AND current_attempt=p_attempt AND first_started_at+interval '30 minutes'>now())
    THEN RETURN false; END IF;
    SELECT * INTO p FROM template_build_publication WHERE build_id=b.id AND attempt_id=p_attempt;
    IF NOT FOUND THEN RETURN false; END IF;
    PERFORM 1 FROM template WHERE id=b.template_id AND deleted_at IS NULL FOR UPDATE;
    IF NOT FOUND THEN RETURN false; END IF;
    IF EXISTS (SELECT 1 FROM template_build_publication WHERE template_id=b.template_id
        AND accepted_at IS NOT NULL AND revision>p.revision) THEN
        PERFORM transition_template_attempt(b.id,p_attempt,'fail','superseded by a newer accepted version');
        RETURN false;
    END IF;
    r:=p.runtime;
    UPDATE template_build_publication SET accepted_at=now() WHERE build_id=b.id;
    UPDATE template_build_attempt SET state='ready',cleanup_pending=false WHERE id=p_attempt;
    UPDATE template_build SET status='ready',finalized_at=now(),updated_at=now(),error_message=NULL WHERE id=b.id;
    UPDATE template SET status='ready',rootfs_path=r->>'rootfs_path',snapshot_path=r->>'snapshot_path',
        mem_path=r->>'mem_path',
        vcpu=(SELECT vcpu FROM template_build_input WHERE build_id=b.id),
        memory_mib=(SELECT memory_mib FROM template_build_input WHERE build_id=b.id),
        disk_mib=(SELECT disk_mib FROM template_build_input WHERE build_id=b.id),base_path=NULLIF(r->>'base_path',''),delta_path=NULLIF(r->>'delta_path',''),
        size_bytes=(r->>'size_bytes')::bigint,built_at=now(),updated_at=now(),error_message=NULL WHERE id=b.template_id;
    INSERT INTO artifact_manifest(template_id,file_name,path,size_bytes,allocated_bytes,sha256)
    SELECT b.template_id,f->>'name',f->>'runtime_path',(f->>'size_bytes')::bigint,
        GREATEST(COALESCE((f->>'allocated_bytes')::bigint,0),0),f->>'sha256' FROM jsonb_array_elements(p.files) f;
    RETURN true;
END;
$$;

-- Canonical database identity catches mixed-version hash formats too. Release
-- it only at a logical terminal transition, never between execution attempts.
CREATE TABLE template_build_identity (
    build_id uuid PRIMARY KEY REFERENCES template_build_execution(build_id),
    template_id uuid NOT NULL REFERENCES template(id),
    input_key text NOT NULL,
    UNIQUE(template_id,input_key)
);
ALTER TABLE template_build_identity ENABLE ROW LEVEL SECURITY;
CREATE OR REPLACE FUNCTION initialize_template_build_execution() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO template_build_execution(build_id) VALUES (NEW.build_id);
    INSERT INTO template_build_identity(build_id,template_id,input_key)
    SELECT NEW.build_id,b.template_id,encode(sha256(convert_to(jsonb_build_array(NEW.build_spec,NEW.vcpu,NEW.memory_mib,NEW.disk_mib)::text,'UTF8')),'hex')
    FROM template_build b WHERE b.id=NEW.build_id;
    RETURN NEW;
END;
$$;
CREATE FUNCTION release_template_build_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.status IN ('ready','failed','cancelled') THEN DELETE FROM template_build_identity WHERE build_id=NEW.id; END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER release_template_build_identity AFTER UPDATE OF status ON template_build
FOR EACH ROW EXECUTE FUNCTION release_template_build_identity();

COMMIT;
