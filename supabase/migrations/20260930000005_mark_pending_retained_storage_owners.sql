SET LOCAL lock_timeout = '250ms';

-- Drain inserts using the former trigger before making the marker mandatory.
LOCK TABLE sandbox, sandbox_snapshot IN SHARE ROW EXCLUSIVE MODE;

-- Both owner-insert triggers use this function. The pending marker survives
-- contention with an earlier report until commit/rollback. Reports only inspect
-- this shared lock; they must never acquire its exclusive side and block inserts.
CREATE OR REPLACE FUNCTION fence_retained_storage_owner_creation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('retained-storage-owner-pending:' || NEW.host_id, 0));
 -- Preserve the existing fence for receivers deployed before the marker check.
 PERFORM pg_try_advisory_xact_lock_shared(hashtextextended('retained-storage-owner:' || NEW.host_id, 0));
 IF NEW.created_at IS NULL THEN
  NEW.created_at := clock_timestamp();
 END IF;
 RETURN NEW;
END;
$$;
