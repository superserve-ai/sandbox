-- Add user-supplied metadata to sandboxes — flat string→string tags
-- attached at creation time, immutable afterward, filterable on list.
--
-- Storage shape: jsonb object whose values are all strings.
--   { "env": "prod", "owner": "agent-7" }
--
-- Why jsonb (not hstore, not a side table):
--   * jsonb @> $filter is the right primitive for "match all of these tags"
--     and combined with a GIN index gives us a single index probe per query.
--   * hstore would also work but is a less first-class type and requires the
--     extension; jsonb is core PG and the rest of the schema already uses it
--     (sandbox.network_config).
--   * A side table (sandbox_tag with one row per key) would scale better at
--     enormous tag counts but is overkill for the per-row caps we enforce
--     (64 keys, 16 KB total) and adds joins for the read path.
--
-- NOT NULL DEFAULT '{}'::jsonb intentionally — every sandbox always has a
-- map, even if empty. This eliminates nil checks at every read site and
-- means the @> filter operates on a real value, not NULL.
ALTER TABLE sandbox
    ADD COLUMN metadata jsonb NOT NULL DEFAULT '{}'::jsonb;

COMMENT ON COLUMN sandbox.metadata IS
    'User-supplied flat string→string tags attached at creation. Immutable. '
    'Filterable on list endpoints via jsonb @> containment. Always non-null; '
    'an absent value is the empty object {}, never NULL.';

-- Composite GIN index on (team_id, metadata).
--
-- Every metadata query is multi-tenant — we always filter by team_id first
-- and then by tag containment. Putting team_id at the leading position via
-- the btree_gin extension lets a single index serve "list this team's
-- sandboxes that match these tags" as one probe instead of (a) a btree
-- lookup on team_id followed by (b) a heap recheck of metadata.
--
-- Partial WHERE destroyed_at IS NULL keeps the index small: deleted rows
-- are never queried by the list endpoint and dominate row count over time.
CREATE EXTENSION IF NOT EXISTS btree_gin;

CREATE INDEX idx_sandbox_team_metadata
    ON sandbox USING GIN (team_id, metadata)
    WHERE destroyed_at IS NULL;

-- Defense-in-depth: coerce any attempt to write NULL into the empty object.
--
-- The column is NOT NULL DEFAULT '{}', so a well-behaved INSERT can't get
-- NULL in there. But an UPDATE that explicitly SETs metadata = NULL would
-- be rejected with an error, which is loud and confusing if the bug is in
-- a client. The trigger silently fixes it instead — buggy clients still
-- get a working sandbox, and the empty-object invariant is preserved.
--
-- This is intentionally permissive (no error) because metadata is meant to
-- be immutable post-creation; the only way to hit this trigger from the
-- application path is a bug, not a real workflow we'd want to surface.
CREATE OR REPLACE FUNCTION sandbox_metadata_default_empty()
    RETURNS trigger
    LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.metadata IS NULL THEN
        NEW.metadata := '{}'::jsonb;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_sandbox_metadata_default_empty
    BEFORE INSERT OR UPDATE OF metadata ON sandbox
    FOR EACH ROW
    EXECUTE FUNCTION sandbox_metadata_default_empty();
