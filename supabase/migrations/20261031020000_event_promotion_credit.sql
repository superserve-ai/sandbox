-- Event promotion codes add usage credit to the Developer or Pro checkout that
-- used them, on top of the plan's included credit. Staff list the codes; the
-- Stripe promotion code's own expiry bounds when a checkout can use one.
CREATE TABLE billing_event_promotion (
 promotion_code text PRIMARY KEY CHECK (promotion_code ~ '^promo_[A-Za-z0-9]+$'),
 label text NOT NULL CHECK (label ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
 credit_cents bigint NOT NULL CHECK (credit_cents > 0 AND credit_cents <= 100000),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- One credit per contract and per team and event; the sweep issues it.
CREATE TABLE billing_event_credit (
 contract_id uuid PRIMARY KEY REFERENCES billing_commercial_contract(id),
 team_id uuid NOT NULL REFERENCES team(id),
 customer_id text NOT NULL,
 promotion_code text NOT NULL REFERENCES billing_event_promotion(promotion_code),
 label text NOT NULL,
 credit_cents bigint NOT NULL CHECK (credit_cents > 0),
 state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','uncertain','issued')),
 stripe_credit_grant_id text,
 first_attempt_at timestamptz,
 next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 failures integer NOT NULL DEFAULT 0,
 last_error text,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 issued_at timestamptz,
 UNIQUE (team_id, label),
 CHECK ((state = 'issued') = (stripe_credit_grant_id IS NOT NULL))
);
CREATE INDEX billing_event_credit_due ON billing_event_credit(next_attempt_at) WHERE state <> 'issued';

ALTER TABLE billing_event_promotion ENABLE ROW LEVEL SECURITY;
ALTER TABLE billing_event_credit ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON billing_event_promotion, billing_event_credit FROM PUBLIC;
DO $$ DECLARE r text; BEGIN
 FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
  IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=r) THEN
   EXECUTE format('REVOKE ALL ON billing_event_promotion, billing_event_credit FROM %I',r);
  END IF;
 END LOOP;
END $$;
