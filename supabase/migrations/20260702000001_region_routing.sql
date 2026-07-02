ALTER TABLE team
ADD COLUMN home_region text NOT NULL DEFAULT 'use',
ADD CONSTRAINT team_home_region_check CHECK (home_region IN ('use', 'usw'));

ALTER TABLE sandbox
ADD COLUMN region text NOT NULL DEFAULT 'use',
ADD CONSTRAINT sandbox_region_check CHECK (region IN ('use', 'usw'));

UPDATE sandbox s
SET region = t.home_region
FROM team t
WHERE t.id = s.team_id;

ALTER TABLE api_key
ADD COLUMN region text,
ADD CONSTRAINT api_key_region_check CHECK (region IS NULL OR region IN ('use', 'usw'));

UPDATE api_key k
SET region = t.home_region
FROM team t
WHERE t.id = k.team_id;
