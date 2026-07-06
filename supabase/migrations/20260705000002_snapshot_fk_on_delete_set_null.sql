-- fk_sandbox_snapshot (sandbox.snapshot_id → snapshot.id) had no ON DELETE
-- action, so deleting a snapshot row still referenced by a sandbox — including
-- a soft-deleted one, whose row and FK still exist — raised a foreign-key
-- violation (SQLSTATE 23503). Every snapshot-row cleanup path hit this and left
-- the row behind. SET NULL nulls the back-reference instead of blocking;
-- snapshots are only ever deleted for already-destroyed or unreferenced
-- sandboxes, so no live sandbox loses a snapshot it still needs.
ALTER TABLE sandbox
    DROP CONSTRAINT IF EXISTS fk_sandbox_snapshot;

ALTER TABLE sandbox
    ADD CONSTRAINT fk_sandbox_snapshot
    FOREIGN KEY (snapshot_id) REFERENCES snapshot(id) ON DELETE SET NULL;
