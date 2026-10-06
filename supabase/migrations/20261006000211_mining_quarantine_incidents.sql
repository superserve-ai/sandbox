-- Stable receipts prevent retries from resurrecting released quarantine.
-- No foreign keys to transient sandboxes: retain the receipt after destruction.
CREATE TABLE abuse_mining_incidents (
 id uuid PRIMARY KEY,
 host_id text NOT NULL,
 sandbox_id uuid NOT NULL,
 team_id uuid NOT NULL,
 assignment text NOT NULL,
 body_digest text NOT NULL,
 disposition text NOT NULL CHECK (disposition IN ('applied','exempt','ignored')),
 restriction_id uuid REFERENCES abuse_restrictions(id) ON DELETE SET NULL,
 evidence jsonb NOT NULL,
 observed_at timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 CHECK ((disposition = 'applied') OR restriction_id IS NULL)
);
CREATE INDEX abuse_mining_incidents_host ON abuse_mining_incidents(host_id);
ALTER TABLE abuse_mining_incidents ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON abuse_mining_incidents FROM PUBLIC;
DO $$
DECLARE role_name text;
BEGIN
    FOREACH role_name IN ARRAY ARRAY['anon', 'authenticated'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name) THEN
            EXECUTE format('REVOKE ALL ON abuse_mining_incidents FROM %I', role_name);
        END IF;
    END LOOP;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON abuse_mining_incidents TO service_role;
    END IF;
END $$;

-- Release fencing runs under the mutation lock; avoid scanning incident history.
CREATE INDEX abuse_state_release_team_cursor ON abuse_state_changes(team_id, id DESC)
 WHERE reason = 'restriction released';
