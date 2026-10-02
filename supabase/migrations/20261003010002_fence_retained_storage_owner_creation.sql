SET LOCAL lock_timeout = '250ms';

-- Covers every insert path, including API instances predating the retained
-- receiver. Concurrent creations share the fence; the report writer tries
-- the exclusive side only after locking existing owners, and retries if busy.
CREATE FUNCTION fence_retained_storage_owner_creation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('retained-storage-owner:' || NEW.host_id, 0));
 -- A transaction can begin before an inventory receipt and insert afterward.
 -- Stamp default creation time after the fence, not at transaction start.
 IF NEW.created_at IS NULL THEN
  NEW.created_at := clock_timestamp();
 END IF;
 RETURN NEW;
END;
$$;

-- NOT NULL remains enforced after the trigger fills the default; explicit
-- timestamps are preserved. All API creation queries omit this field.
ALTER TABLE sandbox ALTER COLUMN created_at DROP DEFAULT;
ALTER TABLE sandbox_snapshot ALTER COLUMN created_at DROP DEFAULT;
CREATE TRIGGER fence_retained_storage_owner_creation
 BEFORE INSERT ON sandbox FOR EACH ROW EXECUTE FUNCTION fence_retained_storage_owner_creation();
CREATE TRIGGER fence_retained_storage_owner_creation
 BEFORE INSERT ON sandbox_snapshot FOR EACH ROW EXECUTE FUNCTION fence_retained_storage_owner_creation();
