-- Serialize accounting with retention/ownership changes, not routine resume or
-- source-snapshot reads. Report ingestion takes this host fence without waiting.
CREATE FUNCTION fence_retained_storage_lifetime() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.host_id IS NOT NULL THEN
  PERFORM pg_advisory_xact_lock(hashtextextended('retained-storage-owner:' || OLD.host_id, 0));
 END IF;
 RETURN NEW;
END;
$$;

CREATE TRIGGER a_fence_retained_storage_lifetime
 BEFORE UPDATE OF destroyed_at,host_id,team_id ON sandbox
 FOR EACH ROW WHEN (
  OLD.destroyed_at IS DISTINCT FROM NEW.destroyed_at
  OR OLD.host_id IS DISTINCT FROM NEW.host_id
  OR OLD.team_id IS DISTINCT FROM NEW.team_id
 ) EXECUTE FUNCTION fence_retained_storage_lifetime();

CREATE TRIGGER a_fence_retained_storage_lifetime
 BEFORE UPDATE OF status,deleted_at,host_id,team_id ON sandbox_snapshot
 FOR EACH ROW WHEN (
  OLD.deleted_at IS DISTINCT FROM NEW.deleted_at
  OR OLD.host_id IS DISTINCT FROM NEW.host_id
  OR OLD.team_id IS DISTINCT FROM NEW.team_id
  OR (OLD.status IN ('creating','ready','deleting') AND NEW.status NOT IN ('creating','ready','deleting'))
 ) EXECUTE FUNCTION fence_retained_storage_lifetime();
