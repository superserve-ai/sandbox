-- Rename template.alias → template.name (more intuitive, matches sandbox.name).
-- Replace the full UNIQUE (team_id, alias) with a partial unique index that
-- only enforces uniqueness on non-soft-deleted rows, so a deleted template's
-- name is reusable.

ALTER TABLE template RENAME COLUMN alias TO name;

ALTER TABLE template DROP CONSTRAINT IF EXISTS template_alias_unique_per_team;

CREATE UNIQUE INDEX template_name_unique_per_team_active
  ON template (team_id, name) WHERE deleted_at IS NULL;
