-- Keep close evidence tied to the provider meter identity collected by the
-- current exporter mapping. Existing discrepancy observations remain ineligible
-- for close until a fresh observation records the identity.
ALTER TABLE billing_export_observation
    ADD COLUMN IF NOT EXISTS meter_id text;
