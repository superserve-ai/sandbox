-- Deleted sandboxes retain snapshot references until ON DELETE SET NULL runs.
-- CD prebuilds this index concurrently; fresh databases build it here.
DO $$
BEGIN
  IF to_regclass('public.idx_sandbox_snapshot_id') IS NULL THEN
    CREATE INDEX idx_sandbox_snapshot_id ON public.sandbox(snapshot_id)
      WHERE snapshot_id IS NOT NULL;
  END IF;
  IF NOT EXISTS (
    SELECT FROM pg_index
    WHERE indexrelid = to_regclass('public.idx_sandbox_snapshot_id')
      AND indisvalid AND indisready AND indislive
      AND pg_get_indexdef(indexrelid) =
        'CREATE INDEX idx_sandbox_snapshot_id ON public.sandbox USING btree (snapshot_id) WHERE (snapshot_id IS NOT NULL)'
  ) THEN
    RAISE EXCEPTION 'sandbox snapshot reference index is invalid or mismatched';
  END IF;
END $$;
