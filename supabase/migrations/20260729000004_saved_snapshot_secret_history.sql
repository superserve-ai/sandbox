-- Backfill active bindings without overwriting keys captured by the rolling
-- writer trigger between the column migration and this statement.

BEGIN;

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '2min';

UPDATE sandbox s
SET secret_env_keys = merged.keys,
    updated_at = now()
FROM (
    SELECT source.sandbox_id,
           jsonb_agg(source.env_key ORDER BY source.env_key) AS keys
    FROM (
        SELECT existing.id AS sandbox_id,
               jsonb_array_elements_text(existing.secret_env_keys) AS env_key
        FROM sandbox existing
        UNION
        SELECT binding.sandbox_id, binding.env_key
        FROM sandbox_secret binding
    ) source
    GROUP BY source.sandbox_id
) merged
WHERE s.id = merged.sandbox_id
  AND s.secret_env_keys IS DISTINCT FROM merged.keys;

COMMIT;
