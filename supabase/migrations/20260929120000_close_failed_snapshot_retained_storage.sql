SET LOCAL lock_timeout = '250ms';

CREATE FUNCTION close_snapshot_retained_storage_owner() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE boundary timestamptz;
BEGIN
 -- Failed captures have no deletion timestamp. Use the database transition
 -- time, not the start of a transaction that may have waited on the owner.
 boundary := COALESCE(NEW.deleted_at,clock_timestamp());
 UPDATE retained_storage_interval SET ended_at=GREATEST(started_at,boundary)
 WHERE owner_id=NEW.id AND owner_kind='snapshot' AND ended_at IS NULL;
 RETURN NEW;
END;
$$;

DROP TRIGGER close_snapshot_retained_storage ON sandbox_snapshot;
CREATE TRIGGER close_snapshot_retained_storage AFTER UPDATE OF status,deleted_at ON sandbox_snapshot
 FOR EACH ROW WHEN (
  (OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL)
  OR (OLD.status IN ('creating','ready','deleting') AND NEW.status NOT IN ('creating','ready','deleting'))
 ) EXECUTE FUNCTION close_snapshot_retained_storage_owner();
