ALTER TABLE billing_usage_export
    DROP CONSTRAINT billing_usage_export_status_valid;

ALTER TABLE billing_usage_export
    ADD CONSTRAINT billing_usage_export_status_valid
        CHECK (status IN ('pending', 'sent', 'accepted', 'failed', 'skipped_shadow', 'skipped_zero', 'skipped_disabled'));
