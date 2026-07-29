-- Add sandbox lineage columns and install history maintenance atomically.
-- Taking a trigger lock on sandbox_secret closes the rolling-writer gap:
-- changes committed before this transaction are visible to the later
-- backfill, while changes after it are recorded by the trigger.

BEGIN;

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

ALTER TABLE sandbox
    ADD COLUMN source_snapshot_id uuid,
    ADD COLUMN snapshot_operation_id uuid,
    ADD COLUMN snapshot_operation_started_at timestamptz,
    ADD COLUMN secret_env_keys jsonb NOT NULL DEFAULT '[]'::jsonb;

CREATE OR REPLACE FUNCTION remember_sandbox_secret_env_key() RETURNS trigger
    LANGUAGE plpgsql
AS $$
DECLARE
    binding_sandbox_id uuid;
    binding_env_key text;
BEGIN
    IF TG_OP = 'DELETE' THEN
        binding_sandbox_id := OLD.sandbox_id;
        binding_env_key := OLD.env_key;
    ELSE
        binding_sandbox_id := NEW.sandbox_id;
        binding_env_key := NEW.env_key;
    END IF;

    UPDATE sandbox s
    SET secret_env_keys = (
            SELECT jsonb_agg(keys.env_key ORDER BY keys.env_key)
            FROM (
                SELECT jsonb_array_elements_text(s.secret_env_keys) AS env_key
                UNION
                SELECT binding_env_key
            ) keys
        ),
        updated_at = now()
    WHERE s.id = binding_sandbox_id
      AND NOT s.secret_env_keys ? binding_env_key;

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_remember_sandbox_secret_env_key
    AFTER INSERT OR DELETE ON sandbox_secret
    FOR EACH ROW
    EXECUTE FUNCTION remember_sandbox_secret_env_key();

COMMIT;
