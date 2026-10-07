CREATE TABLE abuse_runtime_settings (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    mode text NOT NULL DEFAULT 'off' CHECK (mode IN ('off', 'observe', 'enforce')),
    updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO abuse_runtime_settings(singleton) VALUES (true);
ALTER TABLE abuse_runtime_settings ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON abuse_runtime_settings FROM PUBLIC;
DO $$
DECLARE role_name text;
BEGIN
    FOREACH role_name IN ARRAY ARRAY['anon', 'authenticated'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name) THEN
            EXECUTE format('REVOKE ALL ON abuse_runtime_settings FROM %I', role_name);
        END IF;
    END LOOP;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON abuse_runtime_settings TO service_role;
    END IF;
END $$;

CREATE INDEX idx_profile_abuse_email_domain ON profile (lower(split_part(email, '@', 2)));
