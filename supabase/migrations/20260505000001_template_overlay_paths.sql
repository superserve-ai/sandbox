-- Overlay-mode artifacts. NULL for legacy templates (still use rootfs_path).

ALTER TABLE template
    ADD COLUMN base_path  text,
    ADD COLUMN delta_path text;
