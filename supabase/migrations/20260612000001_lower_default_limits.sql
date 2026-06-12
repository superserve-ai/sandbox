-- Lower per-team caps. max_sandboxes default 100 -> 10. Existing teams on
-- the old default are reduced; explicit overrides are preserved.
-- max_templates lives in code (defaultMaxTemplates, also dropped to 5).
-- Per-team exemptions, if any, are applied out-of-band after this runs.
ALTER TABLE team ALTER COLUMN max_sandboxes SET DEFAULT 10;
UPDATE team SET max_sandboxes = 10 WHERE max_sandboxes = 100;
