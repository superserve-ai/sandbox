-- Expand phase for per-sandbox snapshot generations.
--
-- Adds the generation counter and optional customer-facing name. The
-- legacy snapshot_sandbox_unique index is deliberately RETAINED: rolling
-- control planes still upsert against it, and the new finalize runs in a
-- compatibility mode (bump generation in place) while it exists. Dropping
-- the index is the contract phase, shipped separately once every writer
-- understands generations; at that moment finalizes start inserting real
-- history rows with no code change.
--
-- Contract-phase precondition: the index drop also requires vmd to stage
-- each pause's artifacts under per-generation paths first. History rows
-- sharing the per-VM vmstate/mem paths that pauses overwrite in place
-- would describe bytes that no longer exist for every generation but the
-- newest.
ALTER TABLE snapshot ADD COLUMN generation bigint NOT NULL DEFAULT 1;
ALTER TABLE snapshot ADD COLUMN name text CHECK (name IS NULL OR char_length(name) BETWEEN 1 AND 64);

-- UNIQUE is the backstop for generation allocation: finalizes serialize
-- on the sandbox row lock, so a duplicate (sandbox_id, generation) can
-- only arise from a bug, and it must surface as an insert error rather
-- than silently forked history. Existing rows all hold the default
-- generation 1 and at most one row per sandbox (legacy unique index), so
-- the index creates cleanly.
CREATE UNIQUE INDEX snapshot_sandbox_generation
    ON snapshot (sandbox_id, generation DESC);
