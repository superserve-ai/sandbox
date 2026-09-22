-- net_flow and proxy_audit are range-partitioned by day so retention is a
-- partition drop rather than a delete. The window is seven days (today and
-- the six before it); those rows are carried over, the rest go with the old
-- tables. The copy needs free space for the retained rows and their indexes
-- before the old tables are dropped. log_partitions_maintain() creates the
-- days inside the window and ahead of it and drops the days past it; the
-- control plane runs it hourly.

BEGIN;

CREATE OR REPLACE FUNCTION log_partitions_maintain(parent text, keep_days int, ahead_days int DEFAULT 7)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
  today date := (now() AT TIME ZONE 'UTC')::date;
  d     date;
  child text;
BEGIN
  -- Replicas run this concurrently; one at a time per table.
  PERFORM pg_advisory_xact_lock(hashtext('log_partitions_maintain'), hashtext(parent));
  -- Only a new or expired day is DDL, and DDL waits on readers: give up
  -- well inside the log writers' deadline and let the next pass retry.
  SET LOCAL lock_timeout = '2s';
  FOR i IN 1 - keep_days..ahead_days LOOP
    d := today + i;
    child := format('%s_%s', parent, to_char(d, 'YYYYMMDD'));
    IF to_regclass(child) IS NULL THEN
      EXECUTE format('CREATE TABLE %I PARTITION OF %I FOR VALUES FROM (%L) TO (%L)',
                     child, parent, d::timestamp AT TIME ZONE 'UTC', (d + 1)::timestamp AT TIME ZONE 'UTC');
      EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', child);
    END IF;
  END LOOP;
  FOR child IN
    SELECT c.relname
    FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
    WHERE i.inhparent = parent::regclass
      AND c.relname ~ '_\d{8}$'
      AND to_date(right(c.relname, 8), 'YYYYMMDD') <= today - keep_days
  LOOP
    EXECUTE format('DROP TABLE IF EXISTS %I', child);
  END LOOP;
END $$;

-- net_flow

ALTER TABLE net_flow RENAME TO net_flow_old;
DROP INDEX net_flow_sandbox_ts_idx, net_flow_team_ts_idx;
ALTER TABLE net_flow_old DROP CONSTRAINT net_flow_pkey;

CREATE TABLE net_flow (
    id            bigint NOT NULL DEFAULT nextval('net_flow_id_seq'),
    ts            timestamptz NOT NULL DEFAULT now(),
    team_id       uuid NOT NULL,
    sandbox_id    uuid NOT NULL,
    protocol      text NOT NULL,
    host          text,
    dst_ip        inet NOT NULL,
    dst_port      int  NOT NULL,
    verdict       text NOT NULL,
    match_rule    text,
    bytes_sent    bigint,
    bytes_recv    bigint,
    duration_ms   int,
    PRIMARY KEY (id, ts)
) PARTITION BY RANGE (ts);
ALTER SEQUENCE net_flow_id_seq OWNED BY net_flow.id;

CREATE INDEX net_flow_sandbox_ts_idx ON net_flow (sandbox_id, ts DESC);
CREATE INDEX net_flow_team_ts_idx    ON net_flow (team_id,    ts DESC);
ALTER TABLE net_flow ENABLE ROW LEVEL SECURITY;

SELECT log_partitions_maintain('net_flow', 7);
INSERT INTO net_flow (id, ts, team_id, sandbox_id, protocol, host, dst_ip, dst_port, verdict, match_rule, bytes_sent, bytes_recv, duration_ms)
SELECT id, ts, team_id, sandbox_id, protocol, host, dst_ip, dst_port, verdict, match_rule, bytes_sent, bytes_recv, duration_ms
FROM net_flow_old WHERE ts >= ((now() AT TIME ZONE 'UTC')::date - 6)::timestamp AT TIME ZONE 'UTC';
DROP TABLE net_flow_old;

-- proxy_audit

ALTER TABLE proxy_audit RENAME TO proxy_audit_old;
DROP INDEX proxy_audit_sandbox_ts_idx, proxy_audit_team_ts_idx, proxy_audit_secret_ts_idx;
ALTER TABLE proxy_audit_old DROP CONSTRAINT proxy_audit_pkey;

CREATE TABLE proxy_audit (
    id               bigint NOT NULL DEFAULT nextval('proxy_audit_id_seq'),
    ts               timestamptz NOT NULL DEFAULT now(),
    team_id          uuid NOT NULL,
    sandbox_id       uuid NOT NULL,
    secret_id        uuid,
    method           text NOT NULL,
    host             text NOT NULL,
    path             text NOT NULL,
    status           int  NOT NULL,
    upstream_status  int,
    latency_ms       int,
    error_code       text,
    PRIMARY KEY (id, ts)
) PARTITION BY RANGE (ts);
ALTER SEQUENCE proxy_audit_id_seq OWNED BY proxy_audit.id;

CREATE INDEX proxy_audit_sandbox_ts_idx ON proxy_audit (sandbox_id, ts DESC);
CREATE INDEX proxy_audit_team_ts_idx    ON proxy_audit (team_id,    ts DESC);
CREATE INDEX proxy_audit_secret_ts_idx  ON proxy_audit (secret_id,  ts DESC) WHERE secret_id IS NOT NULL;
ALTER TABLE proxy_audit ENABLE ROW LEVEL SECURITY;

SELECT log_partitions_maintain('proxy_audit', 7);
INSERT INTO proxy_audit (id, ts, team_id, sandbox_id, secret_id, method, host, path, status, upstream_status, latency_ms, error_code)
SELECT id, ts, team_id, sandbox_id, secret_id, method, host, path, status, upstream_status, latency_ms, error_code
FROM proxy_audit_old WHERE ts >= ((now() AT TIME ZONE 'UTC')::date - 6)::timestamp AT TIME ZONE 'UTC';
DROP TABLE proxy_audit_old;

COMMIT;
