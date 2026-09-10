-- A pause is a logical operation that outlives any single request: the host
-- may finish the snapshot after the caller's deadline, and the row must
-- converge to what the host did rather than be reverted on a guess. These
-- columns give each pause a stable identity (also its backup token), an
-- immutable start time, and a lease that says which worker may currently act
-- on it. Leases live here, never in updated_at, so renewing one cannot mask
-- the operation's age or disturb the paths keyed on updated_at.
--
-- Nullable columns and a constant default: metadata-only on this Postgres
-- version, no table rewrite. The claim scan is served by the existing
-- idx_sandbox_status partial index; pausing rows are few.

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
