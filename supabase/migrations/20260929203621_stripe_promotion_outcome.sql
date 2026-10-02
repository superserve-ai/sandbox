CREATE TABLE stripe_promotion_outcome (
    event_id text PRIMARY KEY REFERENCES stripe_webhook_event(event_id),
    team_id uuid NOT NULL,
    user_id uuid NOT NULL,
    outcome text NOT NULL CHECK (outcome = 'promotion_ineligible'),
    reason text NOT NULL CHECK (reason IN (
        'ineligible', 'owner_conflict', 'device_already_redeemed',
        'evidence_missing', 'device_reservation_pending', 'authority_unavailable'
    )),
    decided_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE stripe_promotion_outcome ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON stripe_promotion_outcome FROM PUBLIC;
DO $$ DECLARE r text; BEGIN
    FOREACH r IN ARRAY ARRAY['anon', 'authenticated'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
            EXECUTE format('REVOKE ALL ON stripe_promotion_outcome FROM %I', r);
        END IF;
    END LOOP;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
        GRANT SELECT, INSERT ON stripe_promotion_outcome TO service_role;
    END IF;
END $$;
