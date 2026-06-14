-- Add ON DELETE CASCADE to secret.team_id and sandbox_secret.secret_id so a
-- team or secret hard-delete drops its dependents instead of FK-erroring.

ALTER TABLE secret
    DROP CONSTRAINT IF EXISTS secret_team_id_fkey;
ALTER TABLE secret
    ADD CONSTRAINT secret_team_id_fkey
    FOREIGN KEY (team_id) REFERENCES team(id) ON DELETE CASCADE;

ALTER TABLE sandbox_secret
    DROP CONSTRAINT IF EXISTS sandbox_secret_secret_id_fkey;
ALTER TABLE sandbox_secret
    ADD CONSTRAINT sandbox_secret_secret_id_fkey
    FOREIGN KEY (secret_id) REFERENCES secret(id) ON DELETE CASCADE;
