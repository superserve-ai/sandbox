-- A deleted sandbox's host-side reclaim (its VM, pause snapshots, and the
-- per-build artifact dir) outlives the request that deleted it: the host may
-- be slow or unreachable, and the control plane may restart. The reclaim is
-- therefore recorded in the same statement that deletes the row and removed
-- only once every step has completed. The deleting request owns the row for
-- one bounded inline attempt; after that the sweeper retries it under leases
-- of its own until it is done. Nothing here is reachable by clients.

CREATE TABLE IF NOT EXISTS sandbox_teardown (
    sandbox_id  uuid PRIMARY KEY REFERENCES sandbox(id) ON DELETE CASCADE,
    host_id     text NOT NULL,
    base_path   text,
    template_id uuid,
    created_at  timestamptz NOT NULL DEFAULT now(),
    -- Owned by a worker until this passes. Born owned by the deleting
    -- request's inline attempt; the sweeper takes its own lease per attempt.
    lease_until timestamptz NOT NULL DEFAULT now() + interval '60 seconds',
    -- Not retried before this: the backoff after a failed attempt.
    retry_at    timestamptz NOT NULL DEFAULT now(),
    attempts    integer NOT NULL DEFAULT 1,
    -- The last attempt failed for a reason retrying cannot fix (the host is
    -- no longer registered); kept for an operator, retried slowly.
    permanent   boolean NOT NULL DEFAULT false,
    last_error  text
);

CREATE INDEX IF NOT EXISTS idx_sandbox_teardown_created ON sandbox_teardown (created_at);
CREATE INDEX IF NOT EXISTS idx_sandbox_teardown_host_lease ON sandbox_teardown (host_id, lease_until);

ALTER TABLE sandbox_teardown ENABLE ROW LEVEL SECURITY;

-- One sweeper attempt per host at a time, fleet-wide: the claim takes the
-- host's row here in the same statement, so replicas racing for the same
-- host serialize on it and only one wins. sandbox_id is the reclaim the
-- holder is working on; the release is fenced on it.
CREATE TABLE IF NOT EXISTS sandbox_teardown_host (
    host_id     text PRIMARY KEY,
    sandbox_id  uuid NOT NULL,
    lease_until timestamptz NOT NULL
);

ALTER TABLE sandbox_teardown_host ENABLE ROW LEVEL SECURITY;

COMMENT ON TABLE sandbox_teardown IS
  'Host-side reclaim still owed for a deleted sandbox; removed when the VM and its artifacts are gone.';
COMMENT ON COLUMN sandbox_teardown.lease_until IS
  'Until when the worker on this reclaim owns it; passed means no one is working on it.';
COMMENT ON COLUMN sandbox_teardown.retry_at IS
  'Not attempted again before this; the backoff after a failed attempt.';
