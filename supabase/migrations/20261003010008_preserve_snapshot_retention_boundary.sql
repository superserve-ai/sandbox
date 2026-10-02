SET LOCAL lock_timeout = '250ms';

ALTER TABLE sandbox_snapshot ADD COLUMN retention_ended_at timestamptz;

CREATE OR REPLACE FUNCTION close_snapshot_retained_storage_owner() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 -- Persist the boundary even when a received report has not opened an
 -- interval yet. Later deletion must not extend a failed capture's lifetime.
 NEW.retention_ended_at := LEAST(OLD.retention_ended_at,COALESCE(NEW.deleted_at,clock_timestamp()));
 UPDATE retained_storage_interval SET ended_at=GREATEST(started_at,NEW.retention_ended_at)
 WHERE owner_id=NEW.id AND owner_kind='snapshot' AND ended_at IS NULL;
 RETURN NEW;
END;
$$;

DROP TRIGGER close_snapshot_retained_storage ON sandbox_snapshot;
CREATE TRIGGER close_snapshot_retained_storage BEFORE UPDATE OF status,deleted_at ON sandbox_snapshot
 FOR EACH ROW WHEN (
  (OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL)
  OR (OLD.status IN ('creating','ready','deleting') AND NEW.status NOT IN ('creating','ready','deleting'))
 ) EXECUTE FUNCTION close_snapshot_retained_storage_owner();
