-- max_sandboxes default 100 -> 10. Templates default in code.
ALTER TABLE team ALTER COLUMN max_sandboxes SET DEFAULT 10;
UPDATE team SET max_sandboxes = 10 WHERE max_sandboxes = 100;
