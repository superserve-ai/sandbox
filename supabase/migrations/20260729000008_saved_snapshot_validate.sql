-- Validate pre-existing rows under PostgreSQL's weaker validation locks.
-- NOT VALID constraints already protect every row written after migration 6.

BEGIN;

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '2min';

ALTER TABLE snapshot VALIDATE CONSTRAINT snapshot_name_valid;
ALTER TABLE snapshot VALIDATE CONSTRAINT snapshot_idempotency_key_valid;
ALTER TABLE snapshot VALIDATE CONSTRAINT snapshot_vcpu_positive;
ALTER TABLE snapshot VALIDATE CONSTRAINT snapshot_memory_positive;
ALTER TABLE snapshot VALIDATE CONSTRAINT snapshot_disk_positive;
ALTER TABLE snapshot VALIDATE CONSTRAINT snapshot_logical_size_non_negative;
ALTER TABLE snapshot VALIDATE CONSTRAINT snapshot_exclusive_size_non_negative;
ALTER TABLE snapshot VALIDATE CONSTRAINT snapshot_artifact_metadata_object;
ALTER TABLE snapshot VALIDATE CONSTRAINT snapshot_secret_bindings_array;
ALTER TABLE snapshot VALIDATE CONSTRAINT snapshot_secret_env_keys_array;
ALTER TABLE snapshot VALIDATE CONSTRAINT snapshot_runtime_shape;
ALTER TABLE snapshot VALIDATE CONSTRAINT snapshot_saved_source_shape;
ALTER TABLE snapshot VALIDATE CONSTRAINT snapshot_ready_artifact_shape;
ALTER TABLE snapshot VALIDATE CONSTRAINT snapshot_deleted_state;
ALTER TABLE snapshot VALIDATE CONSTRAINT snapshot_template_id_fk;
ALTER TABLE snapshot VALIDATE CONSTRAINT snapshot_parent_team_fk;
ALTER TABLE snapshot VALIDATE CONSTRAINT snapshot_source_sandbox_team_fk;

ALTER TABLE team VALIDATE CONSTRAINT team_max_snapshots_positive;
ALTER TABLE team VALIDATE CONSTRAINT team_max_snapshots_per_sandbox_positive;
ALTER TABLE team VALIDATE CONSTRAINT team_snapshot_storage_quota_non_negative;
ALTER TABLE team VALIDATE CONSTRAINT team_snapshot_storage_non_negative;

ALTER TABLE sandbox VALIDATE CONSTRAINT sandbox_source_snapshot_team_fk;
ALTER TABLE sandbox VALIDATE CONSTRAINT sandbox_snapshot_operation_team_fk;
ALTER TABLE sandbox VALIDATE CONSTRAINT sandbox_snapshot_operation_pair;
ALTER TABLE sandbox VALIDATE CONSTRAINT sandbox_secret_env_keys_array;

COMMIT;
