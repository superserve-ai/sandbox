-- NULL provenance remains compatible with existing human approval writers.
ALTER TABLE team_billing_period ADD COLUMN approval_source text;
ALTER TABLE team_billing_period DROP CONSTRAINT team_billing_period_approval_fields;
ALTER TABLE team_billing_period ADD CONSTRAINT team_billing_period_approval_fields CHECK (
    (approved_at IS NULL AND approved_by IS NULL AND approval_source IS NULL)
    OR (approved_at IS NOT NULL AND approved_by IS NOT NULL AND (approval_source IS NULL OR approval_source='human'))
    OR (approved_at IS NOT NULL AND approved_by IS NULL AND approval_source IS NOT DISTINCT FROM 'system')
);

CREATE TABLE billing_period_close_work (
    team_id uuid NOT NULL,
    period_start timestamptz NOT NULL,
    period_end timestamptz NOT NULL,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    lease_token uuid,
    lease_until timestamptz,
    attempts bigint NOT NULL DEFAULT 0,
    last_attempt_at timestamptz,
    last_progress_at timestamptz,
    last_error text,
    stage text NOT NULL DEFAULT 'pending',
    completed_at timestamptz,
    PRIMARY KEY (team_id, period_start, period_end),
    FOREIGN KEY (team_id, period_start, period_end) REFERENCES team_billing_period(team_id, period_start, period_end) ON DELETE CASCADE,
    CHECK ((lease_token IS NULL) = (lease_until IS NULL))
);
ALTER TABLE billing_period_close_work ENABLE ROW LEVEL SECURITY;

CREATE INDEX billing_period_close_due ON billing_period_close_work(next_attempt_at,team_id,period_start) WHERE completed_at IS NULL;
CREATE INDEX billing_period_close_leased ON billing_period_close_work(lease_until) WHERE lease_token IS NOT NULL;
CREATE INDEX billing_period_close_team_leased ON billing_period_close_work(team_id,lease_until) WHERE lease_token IS NOT NULL;

CREATE TABLE billing_period_close_discovery (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    after_team uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    after_start timestamptz NOT NULL DEFAULT '-infinity',
    after_end timestamptz NOT NULL DEFAULT '-infinity',
    next_run_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE billing_period_close_discovery ENABLE ROW LEVEL SECURITY;

INSERT INTO billing_period_close_discovery DEFAULT VALUES;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='anon') THEN
        REVOKE ALL ON billing_period_close_work, billing_period_close_discovery FROM anon;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='authenticated') THEN
        REVOKE ALL ON billing_period_close_work, billing_period_close_discovery FROM authenticated;
    END IF;
END $$;
