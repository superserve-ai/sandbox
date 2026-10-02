-- A failed capture is retired by the status transition.  The retention
-- trigger assigns retention_ended_at in BEFORE UPDATE, so the obligation
-- closer must subscribe to status as well as the derived timestamp.
CREATE OR REPLACE FUNCTION open_retained_snapshot_measurement_obligation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.deleted_at IS NULL
     AND NEW.retention_ended_at IS NULL
     AND NEW.status IN ('creating','ready','deleting')
     AND feature_enabled('billing_metrics_write', NEW.team_id)
     AND EXISTS (
       SELECT 1 FROM retained_storage_cutover c
       WHERE c.team_id=NEW.team_id AND c.host_id=NEW.host_id
         AND c.started_at <= clock_timestamp()
     ) THEN
    INSERT INTO retained_storage_measurement_obligation
      (team_id,owner_kind,owner_id,host_id,effective_at)
    VALUES (NEW.team_id,'snapshot',NEW.id,NEW.host_id,clock_timestamp())
    ON CONFLICT (owner_kind,owner_id) WHERE resolved_at IS NULL AND ended_at IS NULL DO NOTHING;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS open_retained_snapshot_measurement_obligation ON sandbox_snapshot;
CREATE TRIGGER open_retained_snapshot_measurement_obligation
AFTER INSERT OR UPDATE OF status,host_id,deleted_at,retention_ended_at ON sandbox_snapshot
FOR EACH ROW EXECUTE FUNCTION open_retained_snapshot_measurement_obligation();

DROP TRIGGER IF EXISTS close_retained_snapshot_measurement_obligation ON sandbox_snapshot;
CREATE TRIGGER close_retained_snapshot_measurement_obligation
AFTER UPDATE OF status,deleted_at,retention_ended_at ON sandbox_snapshot
FOR EACH ROW WHEN (
  (OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL)
  OR (OLD.retention_ended_at IS NULL AND NEW.retention_ended_at IS NOT NULL)
  OR (OLD.status IS DISTINCT FROM NEW.status AND NEW.status='failed')
)
EXECUTE FUNCTION close_retained_snapshot_measurement_obligation();
