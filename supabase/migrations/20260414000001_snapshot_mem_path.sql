-- Add mem_path column to snapshot table. Previously derived by convention
-- from filepath.Dir(path) + "mem.snap", which is fragile.
ALTER TABLE snapshot ADD COLUMN mem_path text;
