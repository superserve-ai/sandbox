SET LOCAL lock_timeout = '250ms';

-- Physical ranges are scoped to a host and a receipt-time inventory epoch.
-- Owner intervals preserve shared references after source deletion.
CREATE TABLE retained_storage_cutover (
 host_id text NOT NULL,
 team_id uuid NOT NULL REFERENCES team(id),
 started_at timestamptz NOT NULL,
 PRIMARY KEY(host_id,team_id)
);
CREATE TABLE retained_storage_interval (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 host_id text NOT NULL,
 team_id uuid NOT NULL REFERENCES team(id),
 owner_kind text NOT NULL CHECK(owner_kind IN ('sandbox','snapshot')),
 owner_id uuid NOT NULL,
 generation text NOT NULL,
 extents jsonb NOT NULL CHECK(jsonb_typeof(extents)='array'),
 started_at timestamptz NOT NULL,
 ended_at timestamptz,
 CHECK(ended_at IS NULL OR ended_at >= started_at),
 UNIQUE(host_id,owner_kind,owner_id,started_at)
);
CREATE UNIQUE INDEX retained_storage_current ON retained_storage_interval(host_id,owner_kind,owner_id) WHERE ended_at IS NULL;
CREATE INDEX retained_storage_team_time ON retained_storage_interval(team_id,started_at);
CREATE INDEX retained_storage_host_time ON retained_storage_interval(host_id,started_at);
-- Billing reads constrain both interval edges before expanding extents. Keep
-- the candidate set indexable so bucketed reads do not repeatedly scan every
-- historical row for a team or host.
CREATE INDEX retained_storage_team_window ON retained_storage_interval(team_id,started_at,ended_at);
CREATE INDEX retained_storage_host_window ON retained_storage_interval(host_id,started_at,ended_at);
CREATE INDEX retained_storage_owner_close ON retained_storage_interval(owner_kind,owner_id) WHERE ended_at IS NULL;
ALTER TABLE retained_storage_cutover ENABLE ROW LEVEL SECURITY;
ALTER TABLE retained_storage_interval ENABLE ROW LEVEL SECURITY;

-- Snapshot the sandbox host at the beginning of each legacy storage interval.
-- Billing must not consult sandbox.host_id later: reassignment is a lifecycle
-- operation and must not move an already-finalized legacy cutover boundary.
ALTER TABLE sandbox_storage_interval ADD COLUMN host_id text;
UPDATE sandbox_storage_interval i SET host_id=s.host_id
FROM sandbox s WHERE s.id=i.sandbox_id AND i.host_id IS NULL;
CREATE FUNCTION stamp_sandbox_storage_interval_host() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.host_id IS NULL THEN
  SELECT host_id INTO NEW.host_id FROM sandbox WHERE id=NEW.sandbox_id;
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER stamp_sandbox_storage_interval_host
 BEFORE INSERT ON sandbox_storage_interval FOR EACH ROW
 EXECUTE FUNCTION stamp_sandbox_storage_interval_host();
CREATE INDEX sandbox_storage_interval_host_window ON sandbox_storage_interval(host_id,started_at,ended_at);

-- These triggers do no discovery or aggregation. The lifecycle row lock also
-- fences the asynchronous report writer; only confirmed deletion ends retention.
CREATE FUNCTION close_retained_storage_owner() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE boundary timestamptz;
BEGIN
 IF TG_TABLE_NAME='sandbox' THEN boundary := NEW.destroyed_at;
 ELSE boundary := NEW.deleted_at; END IF;
 IF boundary IS NOT NULL THEN
  UPDATE retained_storage_interval SET ended_at=GREATEST(started_at,boundary)
  WHERE owner_id=NEW.id AND owner_kind=CASE WHEN TG_TABLE_NAME='sandbox' THEN 'sandbox' ELSE 'snapshot' END
    AND ended_at IS NULL;
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER close_sandbox_retained_storage AFTER UPDATE OF destroyed_at ON sandbox
 FOR EACH ROW WHEN (OLD.destroyed_at IS NULL AND NEW.destroyed_at IS NOT NULL) EXECUTE FUNCTION close_retained_storage_owner();
CREATE TRIGGER close_snapshot_retained_storage AFTER UPDATE OF deleted_at ON sandbox_snapshot
 FOR EACH ROW WHEN (OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL) EXECUTE FUNCTION close_retained_storage_owner();

CREATE FUNCTION retained_storage_mib_seconds(p_team uuid,p_start timestamptz,p_end timestamptz)
RETURNS numeric LANGUAGE plpgsql STABLE AS $$
DECLARE
 event record;
 domain_host text;
 domain_device text;
 previous_at timestamptz;
 total numeric := 0;
 leaves integer;
 left_node integer;
 right_node integer;
 left_parent integer;
 right_parent integer;
 node integer;
 counts integer[];
 spans bigint[];
 covered bigint[];
BEGIN
 -- Sweep receipt events once. Coordinate compression and a coverage tree
 -- keep each add/remove logarithmic in the physical endpoints, regardless
 -- of how many owner generations precede the current receipt boundary.
 FOR event IN
  WITH intervals AS MATERIALIZED (
   SELECT host_id,extents,GREATEST(started_at,p_start) lo,
    LEAST(COALESCE(ended_at,billing_request_now()),p_end,billing_request_now()) hi
   FROM retained_storage_interval
   WHERE team_id=p_team AND p_start<LEAST(p_end,billing_request_now())
    AND started_at<LEAST(p_end,billing_request_now())
    AND COALESCE(ended_at,billing_request_now())>p_start
  ), extents AS MATERIALIZED (
   SELECT host_id,lo,hi,e.device,e.start,e.start+e.length finish
   FROM intervals CROSS JOIN LATERAL jsonb_to_recordset(extents) e(device text,start bigint,length bigint)
   WHERE hi>lo AND e.length>0
  ), endpoints AS MATERIALIZED (
   SELECT host_id,device,point,
    row_number() OVER(PARTITION BY host_id,device ORDER BY point)::integer idx
   FROM (SELECT host_id,device,start point FROM extents UNION SELECT host_id,device,finish FROM extents) p
  ), coordinates AS (
   SELECT host_id,device,array_agg(point ORDER BY idx) points FROM endpoints GROUP BY host_id,device
  ), raw_events AS (
   SELECT e.host_id,e.device,t.at,t.delta,a.idx first_idx,b.idx last_idx
   FROM extents e
   JOIN endpoints a ON a.host_id=e.host_id AND a.device=e.device AND a.point=e.start
   JOIN endpoints b ON b.host_id=e.host_id AND b.device=e.device AND b.point=e.finish
   CROSS JOIN LATERAL (VALUES(e.lo,1),(e.hi,-1)) t(at,delta)
  ), events AS (
   SELECT host_id,device,at,first_idx,last_idx,sum(delta)::integer delta
   FROM raw_events GROUP BY host_id,device,at,first_idx,last_idx HAVING sum(delta)<>0
  ), ordered AS (
   SELECT *,row_number() OVER(PARTITION BY host_id,device ORDER BY at,delta,first_idx,last_idx) ordinal
   FROM events
  )
  SELECT o.*,CASE WHEN ordinal=1 THEN c.points END points
  FROM ordered o JOIN coordinates c USING(host_id,device)
  ORDER BY host_id,device,ordinal
 LOOP
  IF domain_host IS DISTINCT FROM event.host_id OR domain_device IS DISTINCT FROM event.device THEN
   domain_host := event.host_id;
   domain_device := event.device;
   previous_at := event.at;
   leaves := 1;
   WHILE leaves<cardinality(event.points)-1 LOOP leaves := leaves*2; END LOOP;
   counts := array_fill(0,ARRAY[2*leaves]);
   spans := array_fill(0::bigint,ARRAY[2*leaves]);
   covered := array_fill(0::bigint,ARRAY[2*leaves]);
   FOR node IN 1..cardinality(event.points)-1 LOOP
    spans[leaves+node-1] := event.points[node+1]-event.points[node];
   END LOOP;
   node := leaves-1;
   WHILE node>0 LOOP
    spans[node] := spans[2*node]+spans[2*node+1];
    node := node-1;
   END LOOP;
  END IF;
  total := total+covered[1]::numeric*EXTRACT(epoch FROM(event.at-previous_at));
  previous_at := event.at;
  left_node := leaves+event.first_idx-1;
  right_node := leaves+event.last_idx-1;
  left_parent := left_node/2;
  right_parent := (right_node-1)/2;
  WHILE left_node<right_node LOOP
   IF left_node%2=1 THEN
    counts[left_node] := counts[left_node]+event.delta;
    covered[left_node] := CASE WHEN counts[left_node]>0 THEN spans[left_node]
     WHEN left_node>=leaves THEN 0 ELSE covered[2*left_node]+covered[2*left_node+1] END;
    left_node := left_node+1;
   END IF;
   IF right_node%2=1 THEN
    right_node := right_node-1;
    counts[right_node] := counts[right_node]+event.delta;
    covered[right_node] := CASE WHEN counts[right_node]>0 THEN spans[right_node]
     WHEN right_node>=leaves THEN 0 ELSE covered[2*right_node]+covered[2*right_node+1] END;
   END IF;
   left_node := left_node/2;
   right_node := right_node/2;
  END LOOP;
  WHILE left_parent>0 LOOP
   covered[left_parent] := CASE WHEN counts[left_parent]>0 THEN spans[left_parent]
    ELSE covered[2*left_parent]+covered[2*left_parent+1] END;
   covered[right_parent] := CASE WHEN counts[right_parent]>0 THEN spans[right_parent]
    ELSE covered[2*right_parent]+covered[2*right_parent+1] END;
   left_parent := left_parent/2;
   right_parent := right_parent/2;
  END LOOP;
 END LOOP;
 RETURN total/1048576.0;
END;
$$;

-- Legacy accounting is clipped prospectively, as one complete host/team group.
-- Existing pre-cutover quantities and rounding remain unchanged.
-- Series buckets preserve fractional legacy artifact usage until aggregation.
CREATE FUNCTION storage_mib_seconds(p_team uuid,p_start timestamptz,p_end timestamptz,p_floor_legacy_artifacts boolean DEFAULT true)
RETURNS numeric LANGUAGE sql STABLE AS $$
WITH legacy_intervals AS MATERIALIZED (
  SELECT i.sandbox_id,i.team_id,i.host_id,i.disk_mib,i.started_at,LEAST(i.ended_at,c.started_at) ended_at,
   LEAST(s.destroyed_at,c.started_at) artifact_retention_end
  FROM sandbox_storage_interval i
  JOIN sandbox s ON s.id=i.sandbox_id
  LEFT JOIN retained_storage_cutover c ON c.host_id=i.host_id AND c.team_id=i.team_id
  WHERE i.team_id=p_team AND p_start<LEAST(p_end,billing_request_now()) AND i.started_at<COALESCE(c.started_at,'infinity')
 ), artifact_bounds AS (
  -- Keep each host/reference range separate until the final path union. A
  -- sandbox transfer must not bridge two hosts and reopen a prior cutover.
  SELECT s.*,i.host_id,i.started_at billing_started_at,i.artifact_retention_end retention_end
  FROM sandbox s JOIN legacy_intervals i ON i.sandbox_id=s.id
  WHERE s.team_id=p_team AND i.started_at<LEAST(billing_request_now(),p_end)
    AND COALESCE(i.artifact_retention_end,billing_request_now())>p_start
 ), artifact_ranges AS (
  SELECT p.path,MAX(COALESCE(am.allocated_bytes,0))::numeric/1048576.0 artifact_mib,
   range_agg(tstzrange(GREATEST(s.billing_started_at,p_start),LEAST(COALESCE(s.retention_end,billing_request_now()),p_end),'[)')) retained_ranges
  FROM artifact_bounds s LEFT JOIN template t ON t.id=s.template_id
  CROSS JOIN LATERAL unnest(ARRAY[s.base_path,s.delta_path,CASE WHEN s.base_path IS NULL AND s.delta_path IS NULL THEN t.rootfs_path END]) p(path)
  LEFT JOIN artifact_manifest am ON (am.snapshot_id=s.snapshot_id OR am.template_id=t.id) AND am.path=p.path
  WHERE p.path IS NOT NULL GROUP BY p.path
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

CREATE OR REPLACE FUNCTION storage_reports_complete_through(
    p_team_id uuid,
    p_boundary timestamptz
) RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    SELECT NOT EXISTS (
        SELECT 1
        FROM host_storage_report r
        WHERE r.received_at < p_boundary
          AND (
              r.state IN ('pending', 'processing', 'retry_exhausted')
              OR (
                  r.state = 'processed'
                  AND r.payload IS NOT NULL
                  AND (
                      jsonb_typeof(r.payload) <> 'array'
                      OR r.next_measurement_index <> CASE
                          WHEN jsonb_typeof(r.payload) = 'array' THEN jsonb_array_length(r.payload)
                          ELSE -1
                      END
                  )
              )
          )
          AND EXISTS (
              SELECT 1
              FROM sandbox s
              WHERE s.team_id = p_team_id
                AND s.host_id = r.host_id
                AND s.created_at <= r.received_at
                AND (s.destroyed_at IS NULL OR s.destroyed_at > r.received_at)
              UNION ALL SELECT 1 FROM sandbox_snapshot s
              WHERE s.team_id=p_team_id AND s.host_id=r.host_id
                AND s.status IN ('ready','creating','deleting')
                AND s.created_at<=r.received_at
                AND (s.deleted_at IS NULL OR s.deleted_at>r.received_at)
          )
        UNION ALL
        SELECT 1
        FROM legacy_host_storage_report legacy
        WHERE legacy.received_at < p_boundary
          AND EXISTS (
              SELECT 1
              FROM sandbox s
              WHERE s.team_id = p_team_id
                AND s.host_id = legacy.host_id
                AND s.created_at <= legacy.received_at
                AND (s.destroyed_at IS NULL OR s.destroyed_at > legacy.received_at)
              UNION ALL SELECT 1 FROM sandbox_snapshot s
              WHERE s.team_id=p_team_id AND s.host_id=legacy.host_id
                AND s.status IN ('ready','creating','deleting')
                AND s.created_at<=legacy.received_at
                AND (s.deleted_at IS NULL OR s.deleted_at>legacy.received_at)
          )
    )
$$;

DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN
  GRANT SELECT,INSERT,UPDATE ON retained_storage_cutover,retained_storage_interval TO service_role;
  GRANT USAGE,SELECT ON SEQUENCE retained_storage_interval_id_seq TO service_role;
 END IF;
END $$;
