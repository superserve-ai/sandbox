-- A pause outlives any single request: the host may finish after the caller's
-- deadline, so the row converges to what the host did instead of being
-- reverted. Each pause gets a stable identity (also its backup token), a start
-- time, and a lease naming the worker that may act on it. The lease is kept
-- apart from updated_at so renewals never read as activity.
--
-- Nullable columns with a constant default: no table rewrite.

ALTER TABLE sandbox
  ADD COLUMN IF NOT EXISTS pause_op_id uuid,
  ADD COLUMN IF NOT EXISTS pause_op_started_at timestamptz,
  ADD COLUMN IF NOT EXISTS pause_op_lease_until timestamptz,
  ADD COLUMN IF NOT EXISTS pause_op_lease_version bigint NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS pause_op_attention_at timestamptz;

COMMENT ON COLUMN sandbox.pause_op_id IS
  'Identity of the pause in flight, reused as the pause token across every attempt; NULL when no pause is pending.';
COMMENT ON COLUMN sandbox.pause_op_lease_until IS
  'Until when the worker holding pause_op_lease_version may act on the pause; expired or NULL means claimable.';
COMMENT ON COLUMN sandbox.pause_op_attention_at IS
  'When a pause pending past its age threshold was flagged for an operator; set once.';
