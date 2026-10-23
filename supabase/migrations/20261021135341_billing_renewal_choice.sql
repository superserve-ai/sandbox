-- The journal is inert until authoritative provider and successor adapters exist.
CREATE TABLE billing_renewal_choice (
    team_id uuid NOT NULL REFERENCES team(id),
    assignment_id uuid NOT NULL,
    intended_boundary timestamptz NOT NULL CHECK (isfinite(intended_boundary)),
    revision bigint NOT NULL DEFAULT 0 CHECK (revision >= 0),
    snapshot jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(snapshot) = 'object'),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (team_id, assignment_id, intended_boundary)
);

CREATE TABLE billing_renewal_choice_request (
    team_id uuid NOT NULL,
    assignment_id uuid NOT NULL,
    intended_boundary timestamptz NOT NULL,
    request_id uuid NOT NULL,
    operation_id uuid NOT NULL UNIQUE,
    request jsonb NOT NULL CHECK (jsonb_typeof(request) = 'object'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (team_id, assignment_id, intended_boundary, request_id),
    FOREIGN KEY (team_id, assignment_id, intended_boundary)
        REFERENCES billing_renewal_choice(team_id, assignment_id, intended_boundary)
);

CREATE TABLE billing_renewal_choice_event (
    team_id uuid NOT NULL,
    assignment_id uuid NOT NULL,
    intended_boundary timestamptz NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    event text NOT NULL CHECK (length(event) BETWEEN 1 AND 100),
    snapshot jsonb NOT NULL CHECK (jsonb_typeof(snapshot) = 'object'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (team_id, assignment_id, intended_boundary, revision),
    FOREIGN KEY (team_id, assignment_id, intended_boundary)
        REFERENCES billing_renewal_choice(team_id, assignment_id, intended_boundary)
);

CREATE FUNCTION guard_renewal_choice_history() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'renewal request and event history are immutable';
END $$;
CREATE TRIGGER renewal_choice_request_immutable BEFORE UPDATE OR DELETE ON billing_renewal_choice_request
FOR EACH ROW EXECUTE FUNCTION guard_renewal_choice_history();
CREATE TRIGGER renewal_choice_event_immutable BEFORE UPDATE OR DELETE ON billing_renewal_choice_event
FOR EACH ROW EXECUTE FUNCTION guard_renewal_choice_history();

ALTER TABLE billing_renewal_choice ENABLE ROW LEVEL SECURITY;
ALTER TABLE billing_renewal_choice_request ENABLE ROW LEVEL SECURITY;
ALTER TABLE billing_renewal_choice_event ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON billing_renewal_choice, billing_renewal_choice_request, billing_renewal_choice_event FROM PUBLIC;
