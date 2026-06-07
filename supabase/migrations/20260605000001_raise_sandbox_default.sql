-- Raise the per-team sandbox default 50 -> 100. New teams get 100; existing
-- teams still at the old default are bumped, but explicit overrides (e.g. 200)
-- and the system team's exemption are left untouched.
ALTER TABLE team ALTER COLUMN max_sandboxes SET DEFAULT 100;
UPDATE team SET max_sandboxes = 100 WHERE max_sandboxes = 50;
