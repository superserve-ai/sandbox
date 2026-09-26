-- Env keys detached from a sandbox. Detach removes the binding, but the key
-- stays in the guest's environment holding a revoked token, and a snapshot
-- of the guest keeps it; a sandbox created from that snapshot clears the
-- keys recorded here. A re-attach of the key removes its row.

BEGIN;

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '10s';

CREATE TABLE IF NOT EXISTS sandbox_secret_detached (
    sandbox_id  uuid NOT NULL REFERENCES sandbox(id) ON DELETE CASCADE,
    env_key     text NOT NULL,
    detached_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (sandbox_id, env_key)
);

ALTER TABLE sandbox_secret_detached ENABLE ROW LEVEL SECURITY;

-- What a snapshot records of a sandbox's secrets: every binding, deleted
-- secrets included, and every detached key not bound again, without a
-- secret. A fork re-binds the live ones and clears the rest.
CREATE OR REPLACE FUNCTION sandbox_secret_record(sb uuid) RETURNS jsonb
    LANGUAGE sql STABLE
AS $$
    SELECT COALESCE(jsonb_agg(r.b ORDER BY r.b->>'env_key'), '[]'::jsonb)
    FROM (
        SELECT jsonb_build_object('env_key', ss.env_key, 'secret_id', ss.secret_id) AS b
        FROM sandbox_secret ss
        WHERE ss.sandbox_id = sb
        UNION ALL
        SELECT jsonb_build_object('env_key', d.env_key)
        FROM sandbox_secret_detached d
        WHERE d.sandbox_id = sb
          AND NOT EXISTS (
              SELECT 1 FROM sandbox_secret ss
              WHERE ss.sandbox_id = sb AND ss.env_key = d.env_key
          )
    ) r
$$;

COMMIT;
