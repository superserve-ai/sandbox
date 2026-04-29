-- Drop unused saved/name scaffolding for a never-shipped named-snapshot
-- feature. Partial unique index becomes a full unique index — one
-- snapshot per sandbox.

DROP INDEX IF EXISTS snapshot_sandbox_live_unique;

ALTER TABLE snapshot DROP COLUMN IF EXISTS saved;
ALTER TABLE snapshot DROP COLUMN IF EXISTS name;

-- Defensive dedup before the new unique index. The partial index only
-- enforced uniqueness on saved=false rows; collapse any same-sandbox
-- duplicates that survived (latest wins).
DELETE FROM snapshot s
USING (
  SELECT id, ROW_NUMBER() OVER (PARTITION BY sandbox_id ORDER BY created_at DESC) AS rn
  FROM snapshot
) dup
WHERE s.id = dup.id AND dup.rn > 1;

CREATE UNIQUE INDEX IF NOT EXISTS snapshot_sandbox_unique
  ON snapshot (sandbox_id);
