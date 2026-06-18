-- PAYG pricing and billing credits.
--
-- Pricing is versioned and read-only to tenants. Credits are modeled as a
-- balance/grant ledger, not as a separate pricing tier, so teams can remain on
-- PAYG while promotional or support credits are applied at invoice time.

CREATE TABLE pricing_plan (
    key          text PRIMARY KEY,
    name         text NOT NULL,
    currency     text NOT NULL DEFAULT 'USD',
    active       boolean NOT NULL DEFAULT true,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT pricing_plan_key_nonempty CHECK (key <> ''),
    CONSTRAINT pricing_plan_currency_valid CHECK (currency ~ '^[A-Z]{3}$')
);

CREATE TABLE pricing_rate (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    plan_key        text NOT NULL REFERENCES pricing_plan(key),
    resource        text NOT NULL,
    unit            text NOT NULL,
    price_usd       numeric(20, 12) NOT NULL,
    effective_from  timestamptz NOT NULL DEFAULT now(),
    effective_to    timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT pricing_rate_resource_valid
        CHECK (resource IN ('vcpu', 'memory_gib', 'storage_gib')),
    CONSTRAINT pricing_rate_unit_valid
        CHECK (unit = 'second'),
    CONSTRAINT pricing_rate_price_non_negative CHECK (price_usd >= 0),
    CONSTRAINT pricing_rate_period_valid
        CHECK (effective_to IS NULL OR effective_to > effective_from),
    CONSTRAINT pricing_rate_unique_version
        UNIQUE (plan_key, resource, unit, effective_from)
);

CREATE INDEX idx_pricing_rate_active
    ON pricing_rate(plan_key, resource, unit, effective_from DESC);

CREATE TABLE team_pricing_plan (
    team_id         uuid NOT NULL REFERENCES team(id),
    plan_key        text NOT NULL REFERENCES pricing_plan(key),
    effective_from  timestamptz NOT NULL DEFAULT now(),
    effective_to    timestamptz,
    assigned_by     uuid REFERENCES profile(id),
    created_at      timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (team_id, effective_from),
    CONSTRAINT team_pricing_plan_period_valid
        CHECK (effective_to IS NULL OR effective_to > effective_from)
);

CREATE INDEX idx_team_pricing_plan_active
    ON team_pricing_plan(team_id, effective_from DESC)
    WHERE effective_to IS NULL;

CREATE TABLE team_credit_grant (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id        uuid NOT NULL REFERENCES team(id),
    amount_usd     numeric(20, 6) NOT NULL,
    remaining_usd  numeric(20, 6) NOT NULL,
    currency       text NOT NULL DEFAULT 'USD',
    reason         text,
    expires_at     timestamptz,
    created_by     uuid REFERENCES profile(id),
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT team_credit_grant_amount_positive CHECK (amount_usd > 0),
    CONSTRAINT team_credit_grant_remaining_valid
        CHECK (remaining_usd >= 0 AND remaining_usd <= amount_usd),
    CONSTRAINT team_credit_grant_currency_valid CHECK (currency = 'USD'),
    CONSTRAINT team_credit_grant_id_team_unique UNIQUE (id, team_id)
);

CREATE INDEX idx_team_credit_grant_active
    ON team_credit_grant(team_id, expires_at)
    WHERE remaining_usd > 0;

CREATE TABLE team_credit_ledger (
    id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id              uuid NOT NULL REFERENCES team(id),
    grant_id             uuid,
    billing_period_start timestamptz,
    billing_period_end   timestamptz,
    amount_usd           numeric(20, 6) NOT NULL,
    reason               text NOT NULL,
    created_by           uuid REFERENCES profile(id),
    created_at           timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT team_credit_ledger_amount_nonzero CHECK (amount_usd <> 0),
    CONSTRAINT team_credit_ledger_reason_nonempty CHECK (reason <> ''),
    CONSTRAINT team_credit_ledger_period_valid CHECK (
        (billing_period_start IS NULL AND billing_period_end IS NULL)
        OR (billing_period_start IS NOT NULL
            AND billing_period_end IS NOT NULL
            AND billing_period_end > billing_period_start)
    ),
    CONSTRAINT team_credit_ledger_grant_team_fk
        FOREIGN KEY (grant_id, team_id)
        REFERENCES team_credit_grant(id, team_id)
);

CREATE INDEX idx_team_credit_ledger_team_created
    ON team_credit_ledger(team_id, created_at DESC);

-- Internal billing/pricing tables: RLS on, no tenant policies. Customer access
-- must go through backend/service-role APIs so tenants cannot grant credits,
-- mutate pricing, or read another team's billing state directly.
ALTER TABLE public.pricing_plan ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.pricing_rate ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.team_pricing_plan ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.team_credit_grant ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.team_credit_ledger ENABLE ROW LEVEL SECURITY;

INSERT INTO pricing_plan (key, name, currency, active)
VALUES ('payg', 'Pay-as-you-go', 'USD', true)
ON CONFLICT (key) DO UPDATE
SET name = EXCLUDED.name,
    currency = EXCLUDED.currency,
    active = EXCLUDED.active,
    updated_at = now();

-- Source of truth for the current public rates:
-- https://www.superserve.ai/pricing/
INSERT INTO pricing_rate (plan_key, resource, unit, price_usd, effective_from)
VALUES
    ('payg', 'vcpu', 'second', 0.000014000000, '2026-06-17 00:00:00+00'::timestamptz),
    ('payg', 'memory_gib', 'second', 0.000004500000, '2026-06-17 00:00:00+00'::timestamptz),
    ('payg', 'storage_gib', 'second', 0.000000030000, '2026-06-17 00:00:00+00'::timestamptz)
ON CONFLICT (plan_key, resource, unit, effective_from) DO UPDATE
SET price_usd = EXCLUDED.price_usd,
    effective_to = EXCLUDED.effective_to;
