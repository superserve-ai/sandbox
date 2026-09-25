//go:build integration

// Package promotiontest installs a synthetic trusted Auth source for database
// tests. It is not used by production provisioning or identity resolution.
package promotiontest

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

func Install(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		CREATE SCHEMA promotion_auth;
		CREATE TABLE promotion_auth.identity_source (
			id uuid PRIMARY KEY, email text, email_confirmed_at timestamptz, deleted_at timestamptz
		);
		CREATE FUNCTION promotion_auth.publish_test_evidence() RETURNS trigger LANGUAGE plpgsql
		SECURITY DEFINER SET search_path = pg_catalog, public AS $$
		DECLARE version uuid;
		BEGIN
			IF TG_OP = 'DELETE' THEN
				DELETE FROM promotion_identity_current WHERE user_id=OLD.id;
				RETURN OLD;
			END IF;
			INSERT INTO promotion_identity_evidence(user_id,email,email_verified,auth_updated_at,observed_at)
			VALUES(NEW.id,NEW.email,NEW.email_confirmed_at IS NOT NULL AND NEW.deleted_at IS NULL,clock_timestamp(),clock_timestamp())
			RETURNING evidence_version INTO version;
			INSERT INTO promotion_identity_current(user_id,evidence_version) VALUES(NEW.id,version)
			ON CONFLICT(user_id) DO UPDATE SET evidence_version=EXCLUDED.evidence_version;
			RETURN NEW;
		END $$;
		CREATE TRIGGER publish_test_evidence AFTER INSERT OR UPDATE OR DELETE ON promotion_auth.identity_source
			FOR EACH ROW EXECUTE FUNCTION promotion_auth.publish_test_evidence();
		CREATE FUNCTION promotion_auth.test_fixture_identity() RETURNS trigger LANGUAGE plpgsql
		SECURITY DEFINER SET search_path = pg_catalog AS $$
		BEGIN
			IF current_setting('test.omit_promotion_identity', true) IS DISTINCT FROM 'on' THEN
				INSERT INTO promotion_auth.identity_source(id, email, email_confirmed_at)
				VALUES(NEW.id, NEW.id::text || '@example.com', now()) ON CONFLICT DO NOTHING;
			END IF;
			RETURN NEW;
		END $$;
		CREATE TRIGGER test_fixture_identity AFTER INSERT ON profile
			FOR EACH ROW EXECUTE FUNCTION promotion_auth.test_fixture_identity();
		SELECT enable_canonical_promotion_identity('{"reference":"synthetic integration authority","all_writers_ready":true,"rollback_ready":true}');
	`)
	return err
}
