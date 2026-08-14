-- Seed the storage billing flag in a forward migration so existing databases
-- can pick up the feature flag without reapplying the earlier billing schema.
INSERT INTO feature_flag (key, enabled, description) VALUES
    ('billing_storage_billing_enabled', false, 'Charge storage usage separately from compute usage.')
ON CONFLICT (key) DO NOTHING;
