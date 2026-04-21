-- Enforce one live snapshot row per sandbox so FinalizePause can UPSERT
-- against it. Idempotent; safe to re-run.

-- Collapse historical duplicates: keep the latest live row per sandbox,
-- re-point sandbox.snapshot_id at it, delete the rest. Saved snapshots
-- (saved=true) are unaffected.
UPDATE sandbox s
SET snapshot_id = latest.id
FROM (
  SELECT DISTINCT ON (sandbox_id) sandbox_id, id
  FROM snapshot
  WHERE saved = false
  ORDER BY sandbox_id, created_at DESC
) latest
WHERE s.id = latest.sandbox_id
  AND s.snapshot_id IS DISTINCT FROM latest.id;

DELETE FROM snapshot s
USING (
  SELECT id, ROW_NUMBER() OVER (PARTITION BY sandbox_id ORDER BY created_at DESC) AS rn
  FROM snapshot
  WHERE saved = false
) dup
WHERE s.id = dup.id AND dup.rn > 1;

CREATE UNIQUE INDEX IF NOT EXISTS snapshot_sandbox_live_unique
  ON snapshot (sandbox_id) WHERE saved = false;
