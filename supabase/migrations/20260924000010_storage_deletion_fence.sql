-- A deletion statement can start before a measurement transaction commits,
-- then wait on its sandbox lock. Its original snapshot cannot see the newly
-- opened storage interval. Trigger SQL takes a fresh snapshot after the update
-- so the deletion closes that interval too, including for older API binaries.
CREATE FUNCTION close_storage_intervals_on_sandbox_destruction()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE sandbox_storage_interval
    SET ended_at = GREATEST(NEW.destroyed_at, started_at), end_reason = 'deleted'
    WHERE sandbox_id = NEW.id AND ended_at IS NULL;
    RETURN NEW;
END;
$$;

CREATE TRIGGER sandbox_destruction_close_storage
AFTER UPDATE OF destroyed_at ON sandbox
FOR EACH ROW
WHEN (OLD.destroyed_at IS NULL AND NEW.destroyed_at IS NOT NULL)
EXECUTE FUNCTION close_storage_intervals_on_sandbox_destruction();
