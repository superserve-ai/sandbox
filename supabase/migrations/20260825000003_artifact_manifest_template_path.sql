-- Preserve allocation manifests for older build paths while a template is
-- still pinned by retained sandboxes. A template may therefore have one row
-- per physical path and file name is only descriptive.
DROP INDEX IF EXISTS artifact_manifest_template_file;

CREATE UNIQUE INDEX artifact_manifest_template_path
    ON artifact_manifest (template_id, path)
    WHERE template_id IS NOT NULL;
