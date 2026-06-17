-- Require config when the credential store is external (BYO vault); the builtin
-- store (the default) needs none.

ALTER TABLE public.team
    DROP CONSTRAINT IF EXISTS team_credential_store_config_check;

ALTER TABLE public.team
    ADD CONSTRAINT team_credential_store_config_check
    CHECK (credential_store_kind = 'builtin' OR credential_store_config IS NOT NULL);
