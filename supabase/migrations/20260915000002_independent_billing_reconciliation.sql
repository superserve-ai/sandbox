-- Keep the export deadline intact when provider reconciliation is due sooner.
ALTER TABLE billing_export_work
    ADD COLUMN next_reconcile_at timestamptz NOT NULL DEFAULT now() + interval '6 hours',
    ADD COLUMN reconcile_error text;
CREATE INDEX billing_export_work_next_due
    ON billing_export_work ((least(next_run_at,next_reconcile_at)),team_id);
