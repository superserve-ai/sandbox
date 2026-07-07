-- Opt-in garbage collection for paused sandboxes. auto_delete_seconds is the
-- configured window; auto_delete_at is the materialized deadline — armed on
-- pause (or when the setting is applied while already paused), cleared on
-- resume. Both NULL (the default) means paused sandboxes are kept forever.
ALTER TABLE sandbox
    ADD COLUMN IF NOT EXISTS auto_delete_seconds integer,
    ADD COLUMN IF NOT EXISTS auto_delete_at timestamptz;

ALTER TABLE sandbox
    DROP CONSTRAINT IF EXISTS sandbox_auto_delete_seconds_valid;

-- Defense in depth: mirror the API's 0..30-day cap so a non-handler write path
-- can't set an unbounded retention window. 2592000 = 30 days.
ALTER TABLE sandbox
    ADD CONSTRAINT sandbox_auto_delete_seconds_valid
    CHECK (auto_delete_seconds IS NULL
           OR (auto_delete_seconds >= 0 AND auto_delete_seconds <= 2592000));

-- Also fix the pre-existing timeout_seconds comment, which described the old
-- destroy-from-creation semantics rather than today's auto-pause.
COMMENT ON COLUMN sandbox.timeout_seconds IS
    'Auto-pause timeout in seconds, evaluated against the current active '
    'session (re-armed on each resume). NULL = no timeout. Settable at create '
    'and via PATCH. The reaper pauses the sandbox on expiry; it does not delete it.';

-- The delete sweep scans for due deadlines; almost all rows have none, so a
-- partial index keeps it a near-empty btree.
CREATE INDEX IF NOT EXISTS idx_sandbox_auto_delete_due
    ON sandbox (auto_delete_at)
    WHERE auto_delete_at IS NOT NULL AND destroyed_at IS NULL;
