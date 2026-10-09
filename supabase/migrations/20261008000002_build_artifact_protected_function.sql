-- The destroy-time collector asks about one build; a reconciler has to ask
-- about every build it is considering, inside a WHERE. Two copies of a rule
-- this subtle would drift, so it lives here and both callers call it.
--
-- Protection means something is still owed these artifacts: the attempt is in
-- flight, it owes a cleanup, it backs the template's current paths, or its
-- upload has not reached the bucket. Being 'ready' only records that the
-- attempt was once promoted and never clears, so it is not protection.
--
-- Live sandbox and snapshot references are deliberately absent: they key on
-- the exact base_path, which is indexed, and callers already hold one. A
-- reconciler takes the whole pinned set once per pass instead of asking per
-- candidate.
--
-- Both of the last two reasons are conditioned on the template still being
-- live. record_template_publication refuses a deleted template's upload, so
-- an outstanding one is owed nothing and would otherwise hold its generation
-- for good.
CREATE OR REPLACE FUNCTION build_artifact_protected(p_vm_id text)
RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT EXISTS(
    SELECT 1 FROM template_build_attempt a JOIN template_build b ON b.id = a.build_id
    WHERE a.vm_id = p_vm_id AND (
        a.state IN ('claimed','admitted','uploading')
     OR a.cleanup_pending
     OR EXISTS(SELECT 1 FROM template t WHERE t.id = b.template_id AND t.deleted_at IS NULL
               AND (t.base_path LIKE '%/'||a.vm_id||'/%'
                 OR t.rootfs_path LIKE '%/'||a.vm_id||'/%'
                 OR t.snapshot_path LIKE '%/'||a.vm_id||'/%'
                 OR (a.state = 'ready' AND NOT EXISTS(SELECT 1 FROM template_build_publication p
                                                      WHERE p.attempt_id = a.id))))
    ));
$$;
