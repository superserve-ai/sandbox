-- Extend the activity table to record secret events (create / rotate / delete).
--
-- secret_id uses ON DELETE SET NULL — the activity row outlives the secret so
-- audit history is preserved across hard-delete. secret_name is a denormalized
-- snapshot taken at write time so the row stays readable even after the
-- underlying secret is gone (mirrors how sandbox_name works for sandbox rows).
--
-- Idempotent: every column add and constraint change uses IF [NOT] EXISTS.

ALTER TABLE activity
    ADD COLUMN IF NOT EXISTS secret_id   uuid REFERENCES secret(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS secret_name text;

ALTER TABLE activity DROP CONSTRAINT IF EXISTS activity_resource_consistent;
ALTER TABLE activity ADD CONSTRAINT activity_resource_consistent CHECK (
    (resource_type = 'sandbox'  AND sandbox_id  IS NOT NULL AND template_id IS NULL     AND secret_id   IS NULL     AND secret_name IS NULL) OR
    (resource_type = 'template' AND template_id IS NOT NULL AND sandbox_id  IS NULL     AND secret_id   IS NULL     AND secret_name IS NULL) OR
    (resource_type = 'secret'   AND sandbox_id  IS NULL     AND template_id IS NULL                                 AND secret_name IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_activity_secret_time
    ON activity(team_id, secret_id, created_at DESC)
    WHERE secret_id IS NOT NULL;
