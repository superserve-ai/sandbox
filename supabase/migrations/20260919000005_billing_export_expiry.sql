CREATE INDEX billing_export_event_expiry ON billing_export_event(first_attempt_at,id)
    WHERE active AND status IN ('pending','uncertain');
