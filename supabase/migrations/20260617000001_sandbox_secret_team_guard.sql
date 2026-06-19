-- A sandbox may only bind secrets owned by its own team. The create path already
-- resolves secrets team-scoped, so this never fires today; it guarantees the
-- invariant at the DB layer for any future insert path that takes a raw
-- secret_id, which a hand-written query could otherwise leak across tenants.

CREATE OR REPLACE FUNCTION sandbox_secret_team_match() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF (SELECT team_id FROM sandbox WHERE id = NEW.sandbox_id)
       IS DISTINCT FROM
       (SELECT team_id FROM secret WHERE id = NEW.secret_id) THEN
        RAISE EXCEPTION 'sandbox_secret: sandbox % and secret % belong to different teams',
            NEW.sandbox_id, NEW.secret_id;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS sandbox_secret_team_match_trg ON sandbox_secret;
CREATE TRIGGER sandbox_secret_team_match_trg
    BEFORE INSERT ON sandbox_secret
    FOR EACH ROW EXECUTE FUNCTION sandbox_secret_team_match();
