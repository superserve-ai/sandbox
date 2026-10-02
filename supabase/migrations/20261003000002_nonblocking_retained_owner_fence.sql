-- Lifecycle writers must not wait behind settlement aggregation.  A failed
-- shared acquisition simply timestamps the new owner after the settlement
-- receipt boundary; the next inventory includes it prospectively.
CREATE OR REPLACE FUNCTION fence_retained_storage_owner_creation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  PERFORM pg_try_advisory_xact_lock_shared(hashtextextended('retained-storage-owner-pending:' || NEW.host_id, 0));
  PERFORM pg_try_advisory_xact_lock_shared(hashtextextended('retained-storage-owner:' || NEW.host_id, 0));
  IF NEW.created_at IS NULL THEN
    NEW.created_at := clock_timestamp();
  END IF;
  RETURN NEW;
END;
$$;
