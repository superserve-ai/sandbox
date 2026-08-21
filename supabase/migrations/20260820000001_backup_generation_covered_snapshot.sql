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
-- in the host's upload report. Coverage links require token equality
-- with both sides present: it names the exact pause, where content
-- digests cannot (identical vmstate bytes with different disk contents
-- are possible while pause-time manifests are vmstate-only) and
-- timestamps cannot (reports are delivered at-least-once, arbitrarily
-- late). NULL on rows finalized before the token existed; their reports
-- carry no token and stay UNLINKED — the same evidence standard the
-- no-backfill decision below applies to history.
--
-- Rolling-deploy wrinkle, accepted as inert: a pre-change replica's
-- legacy one-row finalize does not mention this column, so PostgreSQL
-- preserves the PREVIOUS pause's token under the rewritten artifacts.
-- That stale token cannot mislink anything — the new pause's report is
-- tokenless (an old replica minted none) and tokenless reports never
-- link, while the old pause's delayed tokened report fails the content
-- match against the rewritten manifest. The stale value is overwritten
-- by the sandbox's next new-replica pause.
ALTER TABLE snapshot
    ADD COLUMN IF NOT EXISTS pause_token text;

-- Deliberately NO backfill of links for generations reported before
-- these columns existed. The only identity history offers is the
-- pause-time manifest, which is vmstate-only: a stale generation whose
-- vmstate digest coincides with the current pause (different disk
-- contents) would be linked permanently, making the operator's unbacked
-- count read a false zero — on the number that gates machine
-- retirement. Unlinked historical generations read as unbacked instead:
-- over-reported risk that clears as sandboxes pause again (each pause
-- re-verifies coverage through the report path, now token-bound).
