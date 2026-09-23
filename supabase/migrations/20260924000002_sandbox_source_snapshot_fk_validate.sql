-- Validates the fork pointer's foreign key added NOT VALID in the previous
-- migration. VALIDATE scans the sandbox table but only takes a lock that lets
-- sandbox writes proceed, so it gets its own transaction and a scan-sized
-- budget. A no-op once valid.

BEGIN;

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '10min';

ALTER TABLE sandbox VALIDATE CONSTRAINT sandbox_source_snapshot_fk;

COMMIT;
