-- name: CreateCommercialContract :one
INSERT INTO billing_commercial_contract (
    team_id, offer_key, starts_at, ends_at, customer_id, subscription_id, base_price_id,
    charge_amount_cents, charge_interval_months, entitlement_kind, entitlement_amount_cents,
    entitlement_cadence, entitlement_anchor
) VALUES (
    sqlc.arg(team_id), sqlc.arg(offer_key), sqlc.arg(starts_at), sqlc.narg(ends_at),
    sqlc.arg(customer_id), sqlc.arg(subscription_id), sqlc.arg(base_price_id),
    sqlc.arg(charge_amount_cents), sqlc.arg(charge_interval_months), sqlc.arg(entitlement_kind),
    sqlc.arg(entitlement_amount_cents), sqlc.arg(entitlement_cadence), sqlc.arg(entitlement_anchor)
) RETURNING *;

-- name: GetCurrentCommercialContract :one
SELECT * FROM billing_commercial_contract WHERE team_id = sqlc.arg(team_id) AND status <> 'ended';

-- name: GetCommercialContract :one
SELECT * FROM billing_commercial_contract WHERE team_id = sqlc.arg(team_id) AND id = sqlc.arg(contract_id);

-- name: RecordCommercialBasePayment :one
INSERT INTO billing_contract_payment (
    team_id, contract_id, invoice_id, payment_reference, customer_id, subscription_id, base_price_id,
    service_period_start, service_period_end, base_amount_paid_cents, invoice_amount_paid_cents,
    invoice_amount_remaining_cents, currency, paid_at, verified_at, evidence
) VALUES (
    sqlc.arg(team_id), sqlc.arg(contract_id), sqlc.arg(invoice_id), sqlc.arg(payment_reference),
    sqlc.arg(customer_id), sqlc.arg(subscription_id), sqlc.arg(base_price_id),
    sqlc.arg(service_period_start), sqlc.arg(service_period_end), sqlc.arg(base_amount_paid_cents),
    sqlc.arg(invoice_amount_paid_cents), sqlc.arg(invoice_amount_remaining_cents), sqlc.arg(currency),
    sqlc.arg(paid_at), sqlc.arg(verified_at), sqlc.arg(evidence)
) ON CONFLICT (invoice_id) DO NOTHING RETURNING *;

-- name: GetCommercialBasePayment :one
SELECT * FROM billing_contract_payment WHERE team_id = sqlc.arg(team_id)
    AND contract_id = sqlc.arg(contract_id) AND invoice_id = sqlc.arg(invoice_id);

-- name: ActivateCommercialContract :one
UPDATE billing_commercial_contract SET status = 'active', revision = revision + 1
WHERE team_id = sqlc.arg(team_id) AND id = sqlc.arg(contract_id)
    AND revision = sqlc.arg(expected_revision) AND status = 'pending'
RETURNING *;

-- name: ObserveCommercialCollection :one
UPDATE billing_commercial_contract SET
    collection_has_overdue_balance = sqlc.arg(has_overdue_balance),
    collection_checked_at = sqlc.arg(checked_at), collection_valid_until = sqlc.arg(valid_until),
    collection_evidence = sqlc.arg(evidence), revision = revision + 1
WHERE team_id = sqlc.arg(team_id) AND id = sqlc.arg(contract_id)
    AND revision = sqlc.arg(expected_revision) AND status <> 'ended'
RETURNING *;

-- name: EndCommercialContract :one
UPDATE billing_commercial_contract SET status = 'ended', revision = revision + 1
WHERE team_id = sqlc.arg(team_id) AND id = sqlc.arg(contract_id)
    AND revision = sqlc.arg(expected_revision) AND status <> 'ended'
RETURNING *;

-- name: ClaimCurrentUsageEntitlement :one
WITH contract AS MATERIALIZED (
    SELECT b.* FROM billing_commercial_contract b WHERE b.team_id = sqlc.arg(team_id)
        AND b.id = sqlc.arg(contract_id) FOR UPDATE
)
INSERT INTO billing_usage_entitlement (team_id, contract_id, payment_id, waiver_id, sponsorship_id, kind, period_start, period_end, amount_cents, currency)
SELECT c.team_id, c.id, p.id, w.id, sp.id, c.entitlement_kind, period.period_start, period.period_end, period.amount_cents, c.currency
FROM contract c CROSS JOIN LATERAL billing_contract_entitlement(c::billing_commercial_contract, clock_timestamp()) period
LEFT JOIN billing_contract_payment p ON p.contract_id = c.id
    AND p.service_period_start <= period.period_start AND p.service_period_end >= period.period_end
LEFT JOIN billing_contract_waiver w ON w.contract_id=c.id AND p.id IS NULL
    AND billing_yc_covered(c::billing_commercial_contract,period.period_start,period.period_end,true)
LEFT JOIN billing_sponsored_operation sp ON sp.contract_id=c.id AND p.id IS NULL AND w.id IS NULL
    AND billing_sponsored_covered(c::billing_commercial_contract,period.period_start,period.period_end,true)
WHERE billing_contract_eligible(c::billing_commercial_contract, period.period_start, period.period_end)
ON CONFLICT (team_id, kind, period_start) DO NOTHING
RETURNING *;

-- name: GetUsageEntitlement :one
SELECT * FROM billing_usage_entitlement WHERE team_id = sqlc.arg(team_id) AND id = sqlc.arg(entitlement_id);

-- name: GetCurrentUsageEntitlement :one
SELECT * FROM billing_usage_entitlement WHERE team_id = sqlc.arg(team_id) AND kind = sqlc.arg(kind)
    AND period_start <= clock_timestamp() AND period_end > clock_timestamp();

-- name: BeginUsageEntitlementIssuance :one
WITH contract AS MATERIALIZED (
    SELECT b.* FROM billing_commercial_contract b WHERE b.team_id = sqlc.arg(team_id)
        AND b.id = sqlc.arg(contract_id) FOR UPDATE
), attempt AS MATERIALIZED (SELECT clock_timestamp() AS attempted_at FROM contract)
UPDATE billing_usage_entitlement e SET state = 'uncertain', first_attempt_at = attempt.attempted_at,
    provider_invoice_start = sqlc.arg(invoice_start), provider_invoice_end = sqlc.arg(invoice_end),
    request_payload = jsonb_build_object(
        'customer', c.customer_id, 'category', 'promotional',
        'amount', jsonb_build_object('type','monetary','monetary',jsonb_build_object('currency',e.currency,'value',e.amount_cents)),
        'effective_at', greatest(ceil(extract(epoch FROM attempt.attempted_at))::bigint, extract(epoch FROM sqlc.arg(invoice_start)::timestamptz)::bigint + 1),
        'expires_at', extract(epoch FROM sqlc.arg(invoice_end)::timestamptz)::bigint + 1,
        'applicability_config', jsonb_build_object('scope',jsonb_build_object('prices',sqlc.arg(prices)::jsonb)),
        'metadata', jsonb_build_object('entitlement_id',e.id::text,'entitlement_start',extract(epoch FROM e.period_start)::bigint::text,'entitlement_end',extract(epoch FROM e.period_end)::bigint::text))
FROM contract c CROSS JOIN attempt
WHERE e.team_id = c.team_id AND e.contract_id = c.id AND e.id = sqlc.arg(entitlement_id) AND e.state = 'pending'
    AND billing_contract_eligible(c::billing_commercial_contract, e.period_start, e.period_end) AND e.period_start <= clock_timestamp() AND e.period_end > clock_timestamp()
RETURNING e.*;

-- name: GetReplayableUsageEntitlement :one
SELECT e.* FROM billing_usage_entitlement e JOIN billing_commercial_contract c ON c.id = e.contract_id
WHERE e.team_id = sqlc.arg(team_id) AND e.id = sqlc.arg(entitlement_id) AND e.state = 'uncertain'
    AND e.first_attempt_at > clock_timestamp() - interval '23 hours'
    AND e.period_start <= clock_timestamp() AND e.period_end > clock_timestamp()
    AND billing_contract_eligible(c::billing_commercial_contract, e.period_start, e.period_end);

-- name: ConfirmUsageEntitlementIssued :one
UPDATE billing_usage_entitlement SET state = 'issued',
    stripe_credit_grant_id = sqlc.arg(grant_id), issuance_evidence = sqlc.arg(evidence), issued_at = clock_timestamp()
WHERE team_id = sqlc.arg(team_id) AND id = sqlc.arg(entitlement_id) AND state = 'uncertain'
RETURNING *;

-- name: ListUncertainUsageEntitlements :many
SELECT * FROM billing_usage_entitlement WHERE state = 'uncertain' AND id > sqlc.arg(after_id)
ORDER BY id LIMIT sqlc.arg(batch_size);

-- name: CreateUpfrontCommercialContract :one
INSERT INTO billing_commercial_contract (
    id, team_id, offer_key, starts_at, ends_at, customer_id, subscription_id, base_price_id,
    charge_kind, charge_amount_cents, charge_interval_months, entitlement_kind,
    entitlement_amount_cents, entitlement_cadence, entitlement_anchor
) VALUES (
    sqlc.arg(contract_id), sqlc.arg(team_id), sqlc.arg(offer_key), sqlc.arg(starts_at), sqlc.arg(ends_at),
    sqlc.arg(customer_id), sqlc.arg(subscription_id), sqlc.arg(base_price_id),
    'upfront', sqlc.arg(charge_amount_cents), sqlc.arg(charge_interval_months),
    sqlc.arg(entitlement_kind), sqlc.arg(entitlement_amount_cents), 'scheduled', sqlc.arg(entitlement_anchor)
) RETURNING *;

-- name: AddCommercialEntitlementPeriod :one
INSERT INTO billing_contract_entitlement_schedule (team_id, contract_id, month_offset, amount_cents)
VALUES (sqlc.arg(team_id), sqlc.arg(contract_id), sqlc.arg(month_offset), sqlc.arg(amount_cents))
RETURNING *;

-- name: ListCommercialEntitlementSchedule :many
SELECT * FROM billing_contract_entitlement_schedule
WHERE team_id = sqlc.arg(team_id) AND contract_id = sqlc.arg(contract_id) ORDER BY month_offset;

-- name: AdoptUsageEntitlement :one
WITH contract AS MATERIALIZED (
    SELECT b.* FROM billing_commercial_contract b WHERE b.team_id = sqlc.arg(team_id)
        AND b.id = sqlc.arg(contract_id) AND b.status = 'pending' FOR UPDATE
)
INSERT INTO billing_usage_entitlement (
    team_id, contract_id, payment_id, waiver_id, kind, period_start, period_end, amount_cents, currency,
    state, issuance_source, stripe_credit_grant_id, issuance_evidence, provider_created_at,
    issued_at, adopted_at, adopted_available_balance_cents, provider_invoice_start, provider_invoice_end
)
SELECT c.team_id, c.id, p.id, w.id, c.entitlement_kind, period.period_start, period.period_end, period.amount_cents, c.currency,
    'issued', 'adopted', sqlc.arg(grant_id), sqlc.arg(evidence), sqlc.arg(provider_created_at)::timestamptz,
    sqlc.arg(provider_created_at)::timestamptz, clock_timestamp(), sqlc.arg(available_balance_cents)::bigint,
    sqlc.arg(invoice_start)::timestamptz, sqlc.arg(invoice_end)::timestamptz
FROM contract c CROSS JOIN LATERAL billing_contract_entitlement(c::billing_commercial_contract, clock_timestamp()) period
LEFT JOIN billing_contract_payment p ON p.contract_id = c.id
    AND p.service_period_start <= period.period_start AND p.service_period_end >= period.period_end
LEFT JOIN billing_contract_waiver w ON w.contract_id=c.id AND p.id IS NULL
    AND billing_yc_covered(c::billing_commercial_contract,period.period_start,period.period_end,true)
WHERE p.id IS NOT NULL OR w.id IS NOT NULL
ON CONFLICT (team_id, kind, period_start) DO NOTHING
RETURNING *;

-- name: GetCurrentCommercialPlan :one
WITH contract AS MATERIALIZED (
    -- Nothing ends a fixed-term contract at its boundary, so a lapsed term counts as ended here.
    SELECT b.* FROM billing_commercial_contract b WHERE b.team_id = sqlc.arg(team_id) AND b.status <> 'ended'
        AND b.charge_kind <> 'sponsored_entitlement'
        AND (b.ends_at IS NULL OR b.ends_at > clock_timestamp())
), period AS MATERIALIZED (
    SELECT c.id AS contract_id, p.period_start::timestamptz AS period_start,
        p.period_end::timestamptz AS period_end, p.amount_cents::bigint AS amount_cents
    FROM contract c CROSS JOIN LATERAL billing_contract_entitlement(c::billing_commercial_contract, clock_timestamp()) AS p(period_start, period_end, amount_cents)
)
SELECT c.offer_key, c.status, c.starts_at, c.ends_at, c.charge_amount_cents, c.charge_interval_months,
    period.period_start, period.period_end, period.amount_cents AS period_amount_cents, e.state AS entitlement_state,
    e.stripe_credit_grant_id AS entitlement_grant_id,
    COALESCE((SELECT bp.display_name FROM billing_plan bp WHERE bp.offer_key = c.offer_key), '')::text AS plan_display_name
FROM contract c
LEFT JOIN period ON period.contract_id = c.id
LEFT JOIN billing_usage_entitlement e ON e.team_id = c.team_id AND e.contract_id = c.id
    AND e.kind = c.entitlement_kind AND e.period_start = period.period_start
UNION ALL
SELECT 'pro_annual'::text,'active'::text,a.starts_at,a.waiver_ends_at,0::bigint,12::integer,
 p.period_start::timestamptz,p.period_end::timestamptz,p.amount_cents::bigint,e.state,e.stripe_credit_grant_id,
 COALESCE((SELECT bp.display_name FROM billing_plan bp WHERE bp.offer_key='pro_annual'), '')::text
FROM billing_sponsored_annual_authority a JOIN billing_commercial_contract c ON c.id=a.contract_id
LEFT JOIN LATERAL billing_contract_entitlement(c::billing_commercial_contract,clock_timestamp()) AS p(period_start,period_end,amount_cents) ON true
LEFT JOIN billing_usage_entitlement e ON e.contract_id=c.id AND e.kind=c.entitlement_kind AND e.period_start=p.period_start
WHERE a.team_id=sqlc.arg(team_id) AND a.state='active' AND a.starts_at<=clock_timestamp() AND a.waiver_ends_at>clock_timestamp()
AND NOT EXISTS(SELECT 1 FROM contract);

-- name: BeginImmediateUsageEntitlementIssuance :one
WITH contract AS MATERIALIZED (
    SELECT b.* FROM billing_commercial_contract b WHERE b.team_id = sqlc.arg(team_id)
        AND b.id = sqlc.arg(contract_id) FOR UPDATE
), attempt AS MATERIALIZED (SELECT clock_timestamp() AS attempted_at FROM contract)
UPDATE billing_usage_entitlement e SET state = 'uncertain', first_attempt_at = attempt.attempted_at,
    provider_invoice_start = sqlc.arg(invoice_start), provider_invoice_end = sqlc.arg(invoice_end),
    request_payload = jsonb_build_object(
        'customer', c.customer_id, 'category', 'promotional',
        'amount', jsonb_build_object('type','monetary','monetary',jsonb_build_object('currency',e.currency,'value',e.amount_cents)),
        'priority', 50, 'expires_at', extract(epoch FROM sqlc.arg(invoice_end)::timestamptz)::bigint + 1,
        'applicability_config', jsonb_build_object('scope',jsonb_build_object('prices',sqlc.arg(prices)::jsonb)),
        'metadata', jsonb_build_object('entitlement_id',e.id::text,'entitlement_start',extract(epoch FROM e.period_start)::bigint::text,'entitlement_end',extract(epoch FROM e.period_end)::bigint::text))
FROM contract c CROSS JOIN attempt
WHERE e.team_id = c.team_id AND e.contract_id = c.id AND e.id = sqlc.arg(entitlement_id) AND e.state = 'pending'
    AND billing_contract_eligible(c::billing_commercial_contract, e.period_start, e.period_end) AND e.period_start <= clock_timestamp() AND e.period_end > clock_timestamp()
RETURNING e.*;

-- name: EndLapsedCommercialContracts :execrows
-- A fixed term ends at ends_at; nothing else transitions it, so this sweep does.
UPDATE billing_commercial_contract SET status = 'ended', revision = revision + 1
WHERE status <> 'ended' AND ends_at IS NOT NULL AND ends_at <= clock_timestamp();
