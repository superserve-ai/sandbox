-- Capture the base OCI image's runtime config (ENTRYPOINT/CMD/env/workdir/user)
-- on the template so sandboxes can run the image's own start command without
-- hand-authored build_spec.start_cmd (bring-your-image). Populated by
-- FinalizeBuild from the value the builder captures during pull.
--
-- Nullable: legacy templates (built before this column existed) stay NULL and
-- behave as today (no auto-start). Shape matches builder.ImageDefaults:
--   { "entrypoint": [...], "cmd": [...], "env": {...}, "working_dir": "", "user": "" }
ALTER TABLE template ADD COLUMN image_config jsonb;
