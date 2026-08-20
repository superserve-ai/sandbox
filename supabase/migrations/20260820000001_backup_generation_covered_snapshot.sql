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

-- pause_token is the control plane's minted identity for the pause that
-- produced this snapshot row, sent through the pause RPC and echoed back
-- in the host's upload report. Token equality is the STRONG coverage
-- match: it names the exact pause, where content digests cannot
-- (identical vmstate bytes with different disk contents are possible
-- while pause-time manifests are vmstate-only) and timestamps cannot
-- (reports are delivered at-least-once, arbitrarily late). NULL on rows
-- finalized before the token existed; their reports carry no token and
-- fall back to content matching.
ALTER TABLE snapshot
    ADD COLUMN IF NOT EXISTS pause_token text;

-- Backfill coverage links for generations reported BEFORE the link
-- columns existed: their reports were delivered and acked, and the
-- host's outbox never redelivers an acked completion, so without this
-- they would read as unbacked forever. The link is seeded with the same
-- content match the report handler applied at the time (every recorded
-- manifest digest present in the generation's files) — the best evidence
-- history has; new reports use the token. Only currently-paused
-- sandboxes' head snapshots matter: the count reads nothing else.
UPDATE backup_generation bg
SET covered_snapshot_id = s.snapshot_id,
    covered_snapshot_generation = snap.generation
FROM sandbox s
JOIN snapshot snap ON snap.id = s.snapshot_id
WHERE bg.sandbox_id = s.id
  AND bg.covered_snapshot_id IS NULL
  AND s.status = 'paused'
  AND s.destroyed_at IS NULL
  AND EXISTS (SELECT 1 FROM artifact_manifest am
              WHERE am.snapshot_id = snap.id)
  AND NOT EXISTS (
    SELECT 1 FROM artifact_manifest am
    WHERE am.snapshot_id = snap.id
      AND NOT (bg.files @> jsonb_build_array(
            jsonb_build_object('name', am.file_name,
                               'sha256', am.sha256))));
