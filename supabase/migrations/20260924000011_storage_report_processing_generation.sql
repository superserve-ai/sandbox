-- Reclaiming a processing lease must invalidate every result from its previous
-- owner, including a delayed cursor update or error that discards the payload.
ALTER TABLE host_storage_report
    ADD COLUMN processing_generation bigint NOT NULL DEFAULT 0;
