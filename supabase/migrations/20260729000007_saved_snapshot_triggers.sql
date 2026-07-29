-- Install hot-table triggers in a short catalog-only transaction after all
-- referenced functions and ledger tables exist.

BEGIN;

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

CREATE TRIGGER trg_saved_snapshot_quota_on_insert
    BEFORE INSERT ON snapshot
    FOR EACH ROW
    EXECUTE FUNCTION saved_snapshot_quota_on_insert();

CREATE TRIGGER trg_saved_snapshot_immutable_on_update
    BEFORE UPDATE ON snapshot
    FOR EACH ROW
    EXECUTE FUNCTION saved_snapshot_immutable_on_update();

CREATE TRIGGER trg_snapshot_storage_snapshot_lifecycle
    AFTER UPDATE ON snapshot
    FOR EACH ROW
    WHEN (OLD.kind = 'saved')
    EXECUTE FUNCTION snapshot_storage_snapshot_lifecycle();

CREATE TRIGGER trg_snapshot_storage_sandbox_insert
    AFTER INSERT ON sandbox
    FOR EACH ROW
    EXECUTE FUNCTION snapshot_storage_sandbox_lifecycle();

-- PostgreSQL runs same-kind triggers in name order. This storage trigger must
-- acquire any ancestor-owner sandbox locks before trg_sandbox_quota_on_update
-- acquires the team row; capture finalization uses the same sandbox -> team
-- order. The numeric prefix makes that lock order explicit and deadlock-free.
CREATE TRIGGER trg_00_snapshot_storage_sandbox_update
    AFTER UPDATE ON sandbox
    FOR EACH ROW
    EXECUTE FUNCTION snapshot_storage_sandbox_lifecycle();

COMMIT;
