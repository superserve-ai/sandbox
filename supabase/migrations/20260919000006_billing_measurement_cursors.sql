-- Forward discovery and historical correction work have independent cursors.
ALTER TABLE billing_export_work
    ADD COLUMN correction_after timestamptz,
    ADD COLUMN correction_through timestamptz,
    ADD COLUMN next_correction_at timestamptz NOT NULL DEFAULT now();
