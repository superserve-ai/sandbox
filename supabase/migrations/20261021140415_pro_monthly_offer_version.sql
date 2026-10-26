-- Standard monthly paid terms; provider price mapping stays in billing execution.
-- A preexisting key must fail publication rather than silently adopt other terms.
INSERT INTO billing_commercial_offer_version
(offer_key, version, rate_card_key, plan_tier, currency, term_months,
 charge_amount_cents, charge_interval_months, initial_fee_waived,
 payment_requirement, default_successor_family, allowance_source,
 monthly_allowance_cents, rollover, proration)
VALUES ('pro_monthly', 1, 'payg', 'pro', 'usd', 1,
        120000, 1, false, 'verified_payment', 'pro_monthly', 'usage_allowance',
        ARRAY[100000]::bigint[], false, false);
