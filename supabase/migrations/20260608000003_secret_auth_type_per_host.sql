-- Extend the secret.auth_type CHECK constraint to allow the 'per_host' sentinel
-- for multi-rule secrets (auth_config carries a per_host rule list).

ALTER TABLE secret DROP CONSTRAINT IF EXISTS secret_auth_type_check;
ALTER TABLE secret ADD CONSTRAINT secret_auth_type_check
    CHECK (auth_type IN ('bearer', 'basic', 'api-key', 'custom', 'per_host'));
