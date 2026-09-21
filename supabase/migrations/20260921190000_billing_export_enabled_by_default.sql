-- Make live billing the default for existing and newly created teams.
-- Explicit team-level false overrides remain opt-outs.

INSERT INTO team_feature_flag (team_id, key, enabled)
SELECT t.id, 'billing_export_enabled', true
FROM team t
WHERE NOT EXISTS (
    SELECT 1
    FROM team_feature_flag existing
    WHERE existing.team_id = t.id
      AND existing.key = 'billing_export_enabled'
)
ON CONFLICT (team_id, key) DO NOTHING;

UPDATE feature_flag
SET enabled = true,
    updated_at = now()
WHERE key = 'billing_export_enabled';
