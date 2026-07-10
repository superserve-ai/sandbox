-- Raise template size CHECK constraints to match the new platform ceilings
-- (8 vcpu, memory 10 GiB, disk 20 GiB).

ALTER TABLE template
  DROP CONSTRAINT IF EXISTS template_vcpu_range,
  DROP CONSTRAINT IF EXISTS template_memory_range,
  DROP CONSTRAINT IF EXISTS template_disk_range;

ALTER TABLE template
  ADD CONSTRAINT template_vcpu_range CHECK (vcpu BETWEEN 1 AND 8),
  ADD CONSTRAINT template_memory_range CHECK (memory_mib BETWEEN 256 AND 10240),
  ADD CONSTRAINT template_disk_range CHECK (disk_mib BETWEEN 1024 AND 20480);
