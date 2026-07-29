-- Add team limits separately so no snapshot lock is retained while waiting on
-- the team catalog change. Keep every feature override dark during expand.

BEGIN;

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

ALTER TABLE team
    ADD COLUMN max_snapshots integer NOT NULL DEFAULT 100,
    ADD COLUMN max_snapshots_per_sandbox integer NOT NULL DEFAULT 20,
    ADD COLUMN snapshot_storage_quota_bytes bigint,
    ADD COLUMN snapshot_storage_bytes bigint NOT NULL DEFAULT 0;

INSERT INTO feature_flag (key, enabled, description)
VALUES (
    'sandbox_snapshots_v1',
    false,
    'Allow a team to capture immutable saved snapshots and create sandboxes from them.'
)
ON CONFLICT (key) DO UPDATE
SET enabled = false,
    description = EXCLUDED.description,
    updated_at = now();

-- A team override wins over the global flag, so reset any residue from an
-- earlier manual experiment before the new code is deployed.
UPDATE team_feature_flag
SET enabled = false,
    updated_at = now()
WHERE key = 'sandbox_snapshots_v1'
  AND enabled;

COMMIT;
