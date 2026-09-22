-- Make live billing the default for existing and newly created teams.
-- Explicit team-level false overrides remain opt-outs.

-- Backfill the explicit overrides without making the incremental-export
-- trigger enqueue every existing team individually. The global update below
-- triggers paced discovery for the fleet as a whole.
ALTER TABLE public.team_feature_flag
    DISABLE TRIGGER team_feature_flag_incremental_seed;

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

ALTER TABLE public.team_feature_flag
    ENABLE TRIGGER team_feature_flag_incremental_seed;

UPDATE feature_flag
SET enabled = true,
    updated_at = now()
WHERE key = 'billing_export_enabled';
