-- Per-team limit overrides. NULL means "use code default."

ALTER TABLE team
  ADD COLUMN max_template_vcpu       int,
  ADD COLUMN max_template_memory_mib int,
  ADD COLUMN max_template_disk_mib   int,
  ADD COLUMN max_templates           int,
  ADD COLUMN max_sandboxes           int;
