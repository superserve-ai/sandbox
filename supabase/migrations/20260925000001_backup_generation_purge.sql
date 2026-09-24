-- A deleted sandbox's backups are removed from the bucket by the control
-- plane's purge pass. The claim leases a row to one worker while its objects
-- are deleted; purged_at records that nothing of the generation remains.
ALTER TABLE backup_generation
    ADD COLUMN IF NOT EXISTS purge_claimed_at timestamptz,
    ADD COLUMN IF NOT EXISTS purged_at timestamptz;
