-- Preserve apparent size for integrity while recording host allocation for billing.
ALTER TABLE artifact_manifest
    ADD COLUMN allocated_bytes bigint NOT NULL DEFAULT 0
    CHECK (allocated_bytes >= 0);
