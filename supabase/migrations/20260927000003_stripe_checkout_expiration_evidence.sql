CREATE TABLE stripe_checkout_expiration_evidence (
    team_id uuid NOT NULL REFERENCES team(id) ON DELETE CASCADE,
    stripe_customer_id text NOT NULL,
    checkout_generation timestamptz NOT NULL,
    checkout_session_id text NOT NULL,
    expired_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (team_id, checkout_generation)
);

ALTER TABLE public.stripe_checkout_expiration_evidence ENABLE ROW LEVEL SECURITY;
