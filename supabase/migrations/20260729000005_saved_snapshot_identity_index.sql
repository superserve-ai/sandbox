-- Supabase CLI applies every migration transactionally, so CONCURRENTLY is
-- unavailable. Isolate the one hot-table index required by expand's composite
-- foreign keys, bound its write-blocking window, and measure it in staging
-- before production approval.

BEGIN;

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

CREATE UNIQUE INDEX snapshot_id_team_unique_idx
    ON snapshot (id, team_id);

COMMIT;
