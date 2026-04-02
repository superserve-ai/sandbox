-- 003_control_plane_v2.sql
-- Simplify VM lifecycle: add 'paused' state, store snapshot paths for resume,
-- add disk_size_mib column.

ALTER TYPE vm_status ADD VALUE IF NOT EXISTS 'paused' AFTER 'running';

-- Store snapshot paths returned by VMD so resume doesn't reconstruct them.
ALTER TABLE vms ADD COLUMN IF NOT EXISTS snapshot_path text;
ALTER TABLE vms ADD COLUMN IF NOT EXISTS mem_file_path text;

-- Track disk size alongside vcpu/memory.
ALTER TABLE vms ADD COLUMN IF NOT EXISTS disk_size_mib int NOT NULL DEFAULT 512;
