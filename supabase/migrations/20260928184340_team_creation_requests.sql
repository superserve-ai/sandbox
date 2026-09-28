BEGIN;

-- A completed intent survives team deletion so its request key cannot create again.
CREATE TABLE team_creation_requests (
    actor_id uuid NOT NULL,
    cell text NOT NULL,
    request_id text NOT NULL,
    name text NOT NULL,
    region text NOT NULL,
    team_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    deleted_at timestamptz,
    PRIMARY KEY (actor_id, cell, request_id),
    UNIQUE (team_id),
    CHECK (cell = region)
);

ALTER TABLE team_creation_requests ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION tombstone_team_creation_requests() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    UPDATE team_creation_requests SET deleted_at = now()
    WHERE team_id = OLD.id AND deleted_at IS NULL;
    RETURN OLD;
END $$;
CREATE TRIGGER team_creation_request_tombstone
    BEFORE DELETE ON team FOR EACH ROW EXECUTE FUNCTION tombstone_team_creation_requests();
REVOKE ALL ON FUNCTION tombstone_team_creation_requests() FROM PUBLIC;
REVOKE ALL ON team_creation_requests FROM PUBLIC;
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
        REVOKE ALL ON team_creation_requests FROM anon;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
        REVOKE ALL ON team_creation_requests FROM authenticated;
    END IF;
END $$;

COMMIT;
