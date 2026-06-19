-- max_sandboxes default 100 -> 20; bumps rows still on the old default. Templates default in code.
ALTER TABLE team ALTER COLUMN max_sandboxes SET DEFAULT 20;
UPDATE team SET max_sandboxes = 20 WHERE max_sandboxes = 100;
