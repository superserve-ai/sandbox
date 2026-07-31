-- Expand phase for per-sandbox snapshot generations.
--
-- Adds the generation counter and optional customer-facing name. The
-- legacy snapshot_sandbox_unique index is deliberately RETAINED: rolling
-- control planes still upsert against it, and the new finalize runs in a
-- compatibility mode (bump generation in place) while it exists. Dropping
-- the index is the contract phase, shipped separately once every writer
-- understands generations; at that moment finalizes start inserting real
-- history rows with no code change.
ALTER TABLE snapshot ADD COLUMN generation bigint NOT NULL DEFAULT 1;
ALTER TABLE snapshot ADD COLUMN name text CHECK (name IS NULL OR char_length(name) BETWEEN 1 AND 64);

CREATE INDEX snapshot_sandbox_generation
    ON snapshot (sandbox_id, generation DESC);
