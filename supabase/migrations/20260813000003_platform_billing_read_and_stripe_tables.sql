-- Platform billing read permission plus Stripe integration state.

INSERT INTO permissions (name, description)
VALUES
    ('platform:billing:read', 'Read platform billing state')
ON CONFLICT (name) DO UPDATE
SET description = EXCLUDED.description,
    updated_at = now();

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p
  ON r.name = 'platform_admin'
 AND p.name = 'platform:billing:read'
ON CONFLICT (role_id, permission_id) DO NOTHING;

CREATE TABLE team_billing_account (
    team_id                     uuid PRIMARY KEY REFERENCES team(id) ON DELETE CASCADE,
    stripe_customer_id          text UNIQUE,
    stripe_subscription_id      text UNIQUE,
    stripe_subscription_status  text,
    current_period_start        timestamptz,
    current_period_end          timestamptz,
    cancel_at_period_end        boolean NOT NULL DEFAULT false,
    created_at                  timestamptz NOT NULL DEFAULT now(),
    updated_at                  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT team_billing_account_customer_nonempty
        CHECK (stripe_customer_id IS NULL OR btrim(stripe_customer_id) <> ''),
    CONSTRAINT team_billing_account_subscription_nonempty
        CHECK (stripe_subscription_id IS NULL OR btrim(stripe_subscription_id) <> ''),
    CONSTRAINT team_billing_account_period_valid
        CHECK (
            (current_period_start IS NULL AND current_period_end IS NULL)
            OR (
                current_period_start IS NOT NULL
                AND current_period_end IS NOT NULL
                AND current_period_end > current_period_start
            )
        )
);

ALTER TABLE public.team_billing_account ENABLE ROW LEVEL SECURITY;

CREATE INDEX idx_team_billing_account_customer
    ON team_billing_account(stripe_customer_id)
    WHERE stripe_customer_id IS NOT NULL;

CREATE INDEX idx_team_billing_account_subscription
    ON team_billing_account(stripe_subscription_id)
    WHERE stripe_subscription_id IS NOT NULL;

CREATE TABLE billing_usage_export (
    id                              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id                         uuid NOT NULL REFERENCES team(id) ON DELETE CASCADE,
    period_start                    timestamptz NOT NULL,
    period_end                      timestamptz NOT NULL,
    resource_type                   text NOT NULL,
    stripe_customer_id              text,
    stripe_meter_event_identifier   text NOT NULL,
    stripe_event_name               text NOT NULL,
    value                           numeric NOT NULL,
    status                          text NOT NULL,
    error                           text,
    created_at                      timestamptz NOT NULL DEFAULT now(),
    sent_at                         timestamptz,
    updated_at                      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT billing_usage_export_period_valid
        CHECK (period_end > period_start),
    CONSTRAINT billing_usage_export_resource_valid
        CHECK (resource_type IN ('cpu', 'memory', 'storage')),
    CONSTRAINT billing_usage_export_status_valid
        CHECK (status IN ('pending', 'sent', 'accepted', 'failed', 'skipped_shadow', 'skipped_zero')),
    CONSTRAINT billing_usage_export_identifier_nonempty
        CHECK (btrim(stripe_meter_event_identifier) <> ''),
    CONSTRAINT billing_usage_export_event_name_nonempty
        CHECK (btrim(stripe_event_name) <> ''),
    CONSTRAINT billing_usage_export_customer_nonempty
        CHECK (stripe_customer_id IS NULL OR btrim(stripe_customer_id) <> ''),
    CONSTRAINT billing_usage_export_value_non_negative
        CHECK (value >= 0)
);

ALTER TABLE public.billing_usage_export ENABLE ROW LEVEL SECURITY;

CREATE INDEX idx_billing_usage_export_period
    ON billing_usage_export(team_id, period_start DESC, period_end DESC, resource_type, created_at DESC);

CREATE INDEX idx_billing_usage_export_identifier
    ON billing_usage_export(stripe_meter_event_identifier, created_at DESC);

CREATE TABLE stripe_webhook_event (
    event_id      text PRIMARY KEY,
    event_type    text NOT NULL,
    payload       jsonb NOT NULL,
    received_at   timestamptz NOT NULL DEFAULT now(),
    processed_at  timestamptz,
    last_error    text,
    updated_at    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT stripe_webhook_event_id_nonempty
        CHECK (btrim(event_id) <> ''),
    CONSTRAINT stripe_webhook_event_type_nonempty
        CHECK (btrim(event_type) <> '')
);

ALTER TABLE public.stripe_webhook_event ENABLE ROW LEVEL SECURITY;
