-- Snapshot the build artifact paths at create time so a later template
-- rebuild can't overwrite base.ext4 under a paused sandbox. NULL for
-- pre-migration sandboxes (resume falls back to template.*).

ALTER TABLE sandbox
    ADD COLUMN snapshot_path text,
    ADD COLUMN mem_path      text,
    ADD COLUMN base_path     text,
    ADD COLUMN delta_path    text;
