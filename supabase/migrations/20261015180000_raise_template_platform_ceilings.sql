ALTER TABLE template
  DROP CONSTRAINT template_vcpu_range,
  ADD CONSTRAINT template_vcpu_range CHECK (vcpu BETWEEN 1 AND 32),
  DROP CONSTRAINT template_memory_range,
  ADD CONSTRAINT template_memory_range CHECK (memory_mib BETWEEN 256 AND 131072),
  DROP CONSTRAINT template_disk_range,
  ADD CONSTRAINT template_disk_range CHECK (disk_mib BETWEEN 1024 AND 131072);
