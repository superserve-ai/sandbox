-- For sqlc only; never applied to a database. The migration adds this
-- column inside a DO block so a pre-built column is skipped without locking
-- the sandbox table, and sqlc cannot see DDL inside a DO block.
ALTER TABLE sandbox ADD COLUMN source_snapshot_id uuid;

COMMENT ON COLUMN sandbox.source_snapshot_id IS
  'Snapshot this sandbox was created from; NULL when created from a template.';
