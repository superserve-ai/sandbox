ALTER TABLE template
  DROP CONSTRAINT template_disk_range,
  ADD CONSTRAINT template_disk_range CHECK (disk_mib BETWEEN 1024 AND 65536);
