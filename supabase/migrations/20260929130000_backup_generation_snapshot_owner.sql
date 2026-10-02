-- Saved snapshots' disks are backed up as a third owner of backup_generation,
-- beside sandboxes and templates. They get their own column rather than their
-- source sandbox's: a snapshot outlives that sandbox, and a sandbox's backups
-- are purged when it is deleted.
ALTER TABLE backup_generation
    ADD COLUMN IF NOT EXISTS snapshot_id uuid REFERENCES sandbox_snapshot(id) ON DELETE CASCADE;

-- Exactly one owner, now out of three. The original two-owner check was
-- unnamed, so it is found by its definition.
DO $$
DECLARE c text;
BEGIN
  FOR c IN SELECT conname FROM pg_constraint
    WHERE conrelid = 'backup_generation'::regclass AND contype = 'c'
      AND pg_get_constraintdef(oid) LIKE '%num_nonnulls(sandbox_id, template_id)%'
  LOOP
    EXECUTE format('ALTER TABLE backup_generation DROP CONSTRAINT %I', c);
  END LOOP;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint
    WHERE conrelid = 'backup_generation'::regclass
      AND conname = 'backup_generation_one_owner') THEN
    ALTER TABLE backup_generation ADD CONSTRAINT backup_generation_one_owner
      CHECK (num_nonnulls(sandbox_id, template_id, snapshot_id) = 1);
  END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS backup_generation_snapshot_unique
    ON backup_generation (snapshot_id, bucket, generation)
    WHERE snapshot_id IS NOT NULL;
