-- Each team is homed to exactly one region: all of its sandboxes, snapshots,
-- and API activity live in that region's cell. home_region is the single
-- routing source of truth for every team-scoped request as we go multi-region.
--
-- Region codes are short slugs used in key/ID prefixes (e.g. ss_live_use_...):
--   use = us-east (current region, so it is the backfill default)
--   usw = us-west
ALTER TABLE team
    ADD COLUMN IF NOT EXISTS home_region text NOT NULL DEFAULT 'use';

-- Guard against typos at the write site; extend the list as regions launch.
ALTER TABLE team
    DROP CONSTRAINT IF EXISTS team_home_region_valid;

ALTER TABLE team
    ADD CONSTRAINT team_home_region_valid CHECK (home_region IN ('use', 'usw'));
