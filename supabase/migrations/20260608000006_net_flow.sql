-- net_flow records one row per egress connection seen by the egress proxy,
-- for every sandbox (not just those with secrets attached). It is the
-- connection-level counterpart to proxy_audit's request-level rows; the two
-- union into the per-sandbox network view.

CREATE TABLE IF NOT EXISTS net_flow (
    id            bigserial PRIMARY KEY,
    ts            timestamptz NOT NULL DEFAULT now(),
    -- No FK on team_id/sandbox_id: net_flow is an append-only audit log that
    -- must outlive sandbox/team hard-deletes (sandboxes have no soft-delete).
    team_id       uuid NOT NULL,
    sandbox_id    uuid NOT NULL,
    -- 'http' (port 80), 'tls' (port 443), or 'other' (raw TCP).
    protocol      text NOT NULL,
    -- SNI (tls) or Host header (http). Null for raw 'other' connections.
    host          text,
    dst_ip        inet NOT NULL,
    dst_port      int  NOT NULL,
    -- 'allowed' (connected), 'blocked' (denied by policy or the internal-IP
    -- guard), or 'failed' (policy allowed it but the connection didn't open).
    verdict       text NOT NULL,
    -- Which rule decided: 'domain', 'cidr', 'implicit-deny', etc. Null when
    -- no rule set applied.
    match_rule    text,
    bytes_sent    bigint,
    bytes_recv    bigint,
    duration_ms   int
);

CREATE INDEX IF NOT EXISTS net_flow_sandbox_ts_idx ON net_flow (sandbox_id, ts DESC);
CREATE INDEX IF NOT EXISTS net_flow_team_ts_idx    ON net_flow (team_id,    ts DESC);

-- Internal table — only the control plane (service_role) touches it.
ALTER TABLE public.net_flow ENABLE ROW LEVEL SECURITY;
