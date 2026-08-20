-- Explicit pause-coverage identity on backup_generation. The report
-- handler verifies, under the sandbox row lock FinalizePause also takes,
-- that a generation's manifest matches every digest the head snapshot's
-- pause-time manifest recorded; these columns persist that verdict as a
-- link to the exact pause it matched: the snapshot row AND its
-- generation counter (which advances on every pause even while the
-- legacy one-row-per-sandbox upsert reuses the row id). Coverage
-- questions then read the link instead of re-deriving identity from
-- timestamps or manifest containment, both of which misidentify a
-- previous pause's generation under delayed outbox delivery.
--
-- ON DELETE SET NULL: a snapshot row removed by generation GC clears the
-- link, and an unlinked generation simply stops counting as coverage for
-- any current pause (it never covered the head anyway if the head moved).
ALTER TABLE backup_generation
    ADD COLUMN IF NOT EXISTS covered_snapshot_id uuid REFERENCES snapshot(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS covered_snapshot_generation bigint;
