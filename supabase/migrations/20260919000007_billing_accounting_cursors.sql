CREATE INDEX billing_export_event_allocation_cursor ON billing_export_event
    (allocation_id,created_at,id);

DROP INDEX billing_export_correction_period_cursor;
CREATE INDEX billing_export_correction_period_cursor ON billing_export_correction
    (team_id,period_start,period_end,created_at,id);
