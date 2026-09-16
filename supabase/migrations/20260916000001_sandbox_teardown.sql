-- A deleted sandbox's host-side reclaim (its VM, pause snapshots, and the
-- per-build artifact dir) outlives the request that deleted it: the host may
-- be slow or unreachable, and the control plane may restart. The reclaim is
-- therefore recorded in the same statement that deletes the row, worked by
-- bounded pools, retried under a lease until it completes, and removed only
-- once it has. Nothing here is reachable by clients; the row's lifecycle is
-- the control plane's alone.

CREATE TABLE IF NOT EXISTS sandbox_teardown (
    sandbox_id  uuid PRIMARY KEY REFERENCES sandbox(id) ON DELETE CASCADE,
    host_id     text NOT NULL,
    base_path   text,
    template_id uuid,
    created_at  timestamptz NOT NULL DEFAULT now(),
    attempts    integer NOT NULL DEFAULT 0,
    lease_until timestamptz,
    last_error  text
);

-- The sweeper takes the oldest rows whose lease is absent or expired.
CREATE INDEX IF NOT EXISTS idx_sandbox_teardown_created
    ON sandbox_teardown (created_at);

ALTER TABLE sandbox_teardown ENABLE ROW LEVEL SECURITY;

COMMENT ON TABLE sandbox_teardown IS
  'Host-side reclaim still owed for a deleted sandbox; removed when the VM and its artifacts are gone.';
COMMENT ON COLUMN sandbox_teardown.lease_until IS
  'Until when the worker that claimed this reclaim may act on it; expired or NULL means claimable.';
