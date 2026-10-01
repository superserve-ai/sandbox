-- Team migration must not use cell-local generated ids as durable identity.
-- The UUID is additive so existing obligation history remains unchanged while
-- retries can converge without colliding with another team's local id.
ALTER TABLE retained_storage_measurement_obligation
  ADD COLUMN migration_identity uuid NOT NULL DEFAULT gen_random_uuid();

CREATE UNIQUE INDEX retained_storage_measurement_obligation_migration_identity
  ON retained_storage_measurement_obligation(migration_identity);

GRANT SELECT, INSERT, UPDATE ON retained_storage_measurement_obligation TO service_role;
