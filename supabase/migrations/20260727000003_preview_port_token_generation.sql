-- Phase 3: durable per-port token generations.
--
-- This migration is stacked after 20260727000002_preview_port_access_policy.sql,
-- which adds sandbox_published_port.access. Generations deliberately reference
-- only sandbox: deleting a publication retains its generation as a tombstone,
-- so re-publishing the same port cannot revive a previously minted token.

CREATE TABLE sandbox_preview_port_token_generation (
    sandbox_id uuid NOT NULL REFERENCES sandbox (id) ON DELETE CASCADE,
    port integer NOT NULL,
    token_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (sandbox_id, port),
    CONSTRAINT sandbox_preview_port_token_generation_port_range
        CHECK (port >= 1024 AND port <= 65535 AND port <> 49983),
    CONSTRAINT sandbox_preview_port_token_generation_version_positive
        CHECK (token_version > 0)
);

-- Token generations are authorization state in Supabase's API-exposed public
-- schema. No client policy is intentional: only the privileged control-plane
-- role may mint, rotate, or retain these revocation tombstones.
ALTER TABLE public.sandbox_preview_port_token_generation ENABLE ROW LEVEL SECURITY;

COMMENT ON TABLE sandbox_preview_port_token_generation IS
    'Durable preview-token generation. Rows outlive publication deletion so '
    're-publishing a port revokes credentials minted for an earlier publication.';

COMMENT ON COLUMN sandbox_preview_port_token_generation.token_version IS
    'Positive monotonic generation embedded in per-port preview credentials.';

-- PostgreSQL bigint addition already fails on overflow. Keeping the boundary
-- check explicit gives operators a stable SQLSTATE and a useful error before a
-- generation could ever wrap and make an old credential current again.
CREATE FUNCTION next_sandbox_preview_port_token_version(current_version bigint)
RETURNS bigint
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
BEGIN
    IF current_version < 1 THEN
        RAISE EXCEPTION 'preview token version must be positive (got %)', current_version
            USING ERRCODE = '22003';
    END IF;
    IF current_version = 9223372036854775807::bigint THEN
        RAISE EXCEPTION 'preview token version exhausted bigint range'
            USING ERRCODE = '22003';
    END IF;
    RETURN current_version + 1;
END;
$$;

-- Used for both a newly inserted publication and a real access-mode change.
-- Missing rows initialize at version 1; retained tombstones increment under
-- the row lock taken by ON CONFLICT, so concurrent re-publications cannot lose
-- a generation bump.
CREATE FUNCTION bump_sandbox_preview_port_token_generation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO sandbox_preview_port_token_generation AS generation (
        sandbox_id,
        port,
        token_version
    )
    VALUES (NEW.sandbox_id, NEW.port, 1)
    ON CONFLICT (sandbox_id, port) DO UPDATE
    SET token_version = next_sandbox_preview_port_token_version(generation.token_version),
        updated_at = now();

    RETURN NEW;
END;
$$;

-- AFTER INSERT is intentional: INSERT ... ON CONFLICT DO UPDATE for an
-- already-published port does not fire it, so an idempotent Phase 2 publish
-- cannot revoke tokens. A true reinsert after DELETE does fire it and bumps
-- the retained tombstone.
CREATE TRIGGER trg_preview_port_token_generation_on_insert
    AFTER INSERT ON sandbox_published_port
    FOR EACH ROW
    EXECUTE FUNCTION bump_sandbox_preview_port_token_generation();

-- A public/private transition changes the authorization contract and revokes
-- credentials minted before the transition. Merely writing the same access
-- value (as Phase 2's idempotent upsert does) is explicitly a no-op.
CREATE TRIGGER trg_preview_port_token_generation_on_access_update
    AFTER UPDATE OF access ON sandbox_published_port
    FOR EACH ROW
    WHEN (OLD.access IS DISTINCT FROM NEW.access)
    EXECUTE FUNCTION bump_sandbox_preview_port_token_generation();

-- Install triggers before backfilling. Any publication committed while the
-- migration runs is therefore initialized by the INSERT trigger; DO NOTHING
-- makes the backfill safe if it observes the same row afterward.
INSERT INTO sandbox_preview_port_token_generation (
    sandbox_id,
    port,
    token_version
)
SELECT sandbox_id, port, 1
FROM sandbox_published_port
ON CONFLICT (sandbox_id, port) DO NOTHING;
