-- De-dup state for quota alerts: a row means this team was already alerted for
-- this resource (cleared when usage drops back under threshold). The atomic
-- INSERT ... ON CONFLICT also makes exactly one replica send each alert.
CREATE TABLE quota_alert_state (
    team_id    uuid NOT NULL REFERENCES team(id) ON DELETE CASCADE,
    quota_type text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (team_id, quota_type)
);
