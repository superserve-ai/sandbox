-- Durable abuse control-plane state.  Enforcement consumers read these tables
-- directly; no lifecycle cache or worker is owned by this migration.
CREATE TABLE IF NOT EXISTS abuse_team_trust (
    team_id uuid PRIMARY KEY REFERENCES team(id) ON DELETE CASCADE,
    verified boolean NOT NULL DEFAULT false,
    source text NOT NULL DEFAULT 'platform_admin',
    reason text,
    evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz
);

CREATE TABLE IF NOT EXISTS abuse_trusted_identities (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    auth_provider text NOT NULL,
    domain text NOT NULL,
    source text NOT NULL DEFAULT 'platform_admin',
    evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz
);
-- A revoked association remains auditable while allowing the same identity to
-- be trusted again through a new active row.
ALTER TABLE abuse_trusted_identities
    DROP CONSTRAINT IF EXISTS abuse_trusted_identities_auth_provider_domain_key;
CREATE UNIQUE INDEX IF NOT EXISTS abuse_trusted_identity_active_unique
    ON abuse_trusted_identities (auth_provider, domain)
    WHERE revoked_at IS NULL;
ALTER TABLE abuse_trusted_identities ADD CONSTRAINT abuse_trusted_identity_canonical
    CHECK (auth_provider = lower(trim(auth_provider)) AND domain = lower(trim(domain))
           AND domain <> '' AND domain NOT LIKE '%*%' AND domain NOT LIKE '%/%');

CREATE TABLE IF NOT EXISTS abuse_restrictions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    subject_type text NOT NULL,
    subject_value text NOT NULL,
    subject_user_id uuid,
    subject_team_id uuid REFERENCES team(id) ON DELETE CASCADE,
    action text NOT NULL,
    source text NOT NULL,
    reason text NOT NULL,
    evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_by uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz,
    released_at timestamptz,
    released_by uuid,
    CONSTRAINT abuse_restriction_subject_type CHECK (subject_type IN ('user','team','ip','domain')),
    CONSTRAINT abuse_restriction_action CHECK (action IN ('signup','create','resume')),
    CONSTRAINT abuse_restriction_subject_shape CHECK (
      (subject_type = 'user' AND subject_user_id IS NOT NULL AND subject_team_id IS NULL) OR
      (subject_type = 'team' AND subject_team_id IS NOT NULL AND subject_user_id IS NULL) OR
      (subject_type IN ('ip','domain') AND subject_user_id IS NULL AND subject_team_id IS NULL)
    ),
    CONSTRAINT abuse_restriction_exact_subject CHECK (
      (subject_type <> 'ip' OR (subject_value NOT LIKE '%/%' AND subject_value NOT LIKE '%*%')) AND
      (subject_type <> 'domain' OR (subject_value = lower(trim(subject_value)) AND subject_value NOT LIKE '%*%' AND subject_value NOT LIKE '%/%'))
    )
);
CREATE INDEX IF NOT EXISTS idx_abuse_restrictions_active
 ON abuse_restrictions(subject_type, subject_value, action)
 WHERE released_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_abuse_restrictions_team_active
 ON abuse_restrictions(subject_team_id, action) WHERE released_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_abuse_restrictions_user_active
 ON abuse_restrictions(subject_user_id, action) WHERE released_at IS NULL;

CREATE TABLE IF NOT EXISTS abuse_state_changes (
    id bigserial PRIMARY KEY,
    team_id uuid REFERENCES team(id) ON DELETE CASCADE,
    generation bigint NOT NULL DEFAULT 1,
    reason text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_abuse_state_changes_cursor ON abuse_state_changes(id);

-- These tables hold sensitive trust, restriction, and evidence state.  Keep
-- them inaccessible to anon/authenticated clients; control-plane handlers use
-- the service role after platform authorization.
ALTER TABLE abuse_team_trust ENABLE ROW LEVEL SECURITY;
ALTER TABLE abuse_trusted_identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE abuse_restrictions ENABLE ROW LEVEL SECURITY;
ALTER TABLE abuse_state_changes ENABLE ROW LEVEL SECURITY;

INSERT INTO permissions (name, description) VALUES
 ('platform:abuse:read', 'Inspect abuse trust and restrictions'),
 ('platform:abuse:write', 'Mutate abuse trust and restrictions')
ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description, updated_at = now();
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name = 'platform_admin' AND p.name IN ('platform:abuse:read','platform:abuse:write')
ON CONFLICT DO NOTHING;
