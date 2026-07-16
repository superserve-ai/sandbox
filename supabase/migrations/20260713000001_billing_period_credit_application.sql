-- Durable billing-period finalization state.
--
-- Finalization records the gross charge, credits applied, and resulting net
-- invoice amount on the billing period row so retries can return the same
-- result without consuming credits again.
ALTER TABLE team_billing_period
    ADD COLUMN gross_charges_usd numeric(20, 6),
    ADD COLUMN credits_applied_usd numeric(20, 6),
    ADD COLUMN net_invoice_amount_usd numeric(20, 6);

ALTER TABLE team_billing_period
    ADD CONSTRAINT team_billing_period_financials_valid CHECK (
        (finalized_at IS NULL
            AND gross_charges_usd IS NULL
            AND credits_applied_usd IS NULL
            AND net_invoice_amount_usd IS NULL)
        OR (
            finalized_at IS NOT NULL
            AND gross_charges_usd IS NOT NULL
            AND credits_applied_usd IS NOT NULL
            AND net_invoice_amount_usd IS NOT NULL
            AND gross_charges_usd >= 0
            AND credits_applied_usd >= 0
            AND net_invoice_amount_usd >= 0
            AND credits_applied_usd <= gross_charges_usd
            AND net_invoice_amount_usd = gross_charges_usd - credits_applied_usd
        )
    );
