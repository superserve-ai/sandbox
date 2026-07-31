-- CountActiveSandboxesAtBasePath runs at every destroy to decide whether the
-- per-build artifact dir is safe to GC, and ListPinnedBuildPaths walks the
-- same predicate for the reconciler; neither has an index on base_path, so
-- both sequential-scan the sandbox table. Partial index: only live rows with
-- a base_path are ever matched (equality lookups imply NOT NULL).

BEGIN;

-- CREATE INDEX queued behind a slow writer would block every sandbox write
-- behind it; abort and retry the push instead.
SET LOCAL lock_timeout = '5s';

CREATE INDEX IF NOT EXISTS idx_sandbox_base_path_active
  ON sandbox(base_path)
  WHERE base_path IS NOT NULL AND destroyed_at IS NULL;

COMMIT;
