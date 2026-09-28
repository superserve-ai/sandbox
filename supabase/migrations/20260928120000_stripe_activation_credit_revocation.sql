CREATE TABLE stripe_activation_credit_revocation (
    team_id uuid PRIMARY KEY REFERENCES team_billing_account(team_id) ON DELETE CASCADE,
    stripe_customer_id text NOT NULL,
    requested_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    stripe_grant_id text,
    CHECK (completed_at IS NULL OR stripe_grant_id IS NOT NULL)
);
ALTER TABLE stripe_activation_credit_revocation ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON stripe_activation_credit_revocation FROM PUBLIC;
CREATE INDEX stripe_activation_credit_revocation_pending
    ON stripe_activation_credit_revocation(requested_at) WHERE completed_at IS NULL;

DO $$
DECLARE r text;
BEGIN
    FOREACH r IN ARRAY ARRAY['anon', 'authenticated'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
            EXECUTE format('REVOKE ALL ON stripe_activation_credit_revocation FROM %I', r);
        END IF;
    END LOOP;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
        GRANT ALL ON stripe_activation_credit_revocation TO service_role;
        CREATE POLICY stripe_activation_credit_revocation_service ON stripe_activation_credit_revocation
            FOR ALL TO service_role USING (true) WITH CHECK (true);
    END IF;
END $$;
