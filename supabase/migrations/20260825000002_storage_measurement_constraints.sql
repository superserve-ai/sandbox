ALTER TABLE sandbox_storage_interval
    DROP CONSTRAINT sandbox_storage_interval_disk_positive,
    DROP CONSTRAINT sandbox_storage_interval_reason_valid,
    ADD CONSTRAINT sandbox_storage_interval_disk_nonnegative
        CHECK (disk_mib >= 0),
    ADD CONSTRAINT sandbox_storage_interval_reason_valid
        CHECK (end_reason IS NULL OR end_reason IN ('deleted', 'measurement'));
