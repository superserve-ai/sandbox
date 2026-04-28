-- Generalize activity to cover both sandbox and template events.
--
-- Before: every row had a NOT-NULL sandbox_id. Template events had nowhere to
-- land.
-- After:  resource_type ∈ {sandbox, template} drives which of
-- sandbox_id/template_id is populated; a check constraint keeps the two in
-- sync.
ALTER TABLE activity ALTER COLUMN sandbox_id DROP NOT NULL;
ALTER TABLE activity ADD COLUMN template_id uuid REFERENCES template(id);
ALTER TABLE activity ADD COLUMN resource_type text;

UPDATE activity SET resource_type = 'sandbox' WHERE sandbox_id IS NOT NULL;

ALTER TABLE activity ALTER COLUMN resource_type SET NOT NULL;

ALTER TABLE activity ADD CONSTRAINT activity_resource_consistent CHECK (
  (resource_type = 'sandbox' AND sandbox_id IS NOT NULL AND template_id IS NULL) OR
  (resource_type = 'template' AND template_id IS NOT NULL AND sandbox_id IS NULL)
);

CREATE INDEX idx_activity_template_time
  ON activity(team_id, template_id, created_at DESC)
  WHERE template_id IS NOT NULL;
