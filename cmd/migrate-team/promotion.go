package main

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Read-committed snapshots must follow the locks: an in-flight reservation
// otherwise remains invisible until after destination ownership is published.
func lockSourcePromotionMigration(ctx context.Context, tx pgx.Tx, teamID uuid.UUID) error {
	var expanded, canonical, provenance, claims bool
	if err := tx.QueryRow(ctx, `SELECT
		to_regclass('public.user_promotion_entitlement') IS NOT NULL,
		to_regclass('public.promotion_identity') IS NOT NULL,
		to_regclass('public.team_signup_trial_provenance') IS NOT NULL,
		to_regclass('public.user_signup_trial_claim') IS NOT NULL`).Scan(&expanded, &canonical, &provenance, &claims); err != nil {
		return fmt.Errorf("check source promotion locks: %w", err)
	}
	if !expanded {
		return nil
	}
	if canonical {
		if _, err := tx.Exec(ctx, `SELECT canonical_promotion_identity_enabled()`); err != nil {
			return fmt.Errorf("lock source promotion gate: %w", err)
		}
	}
	actorSQL := fmt.Sprintf(`SELECT id FROM profile WHERE %s`, profileScope) + `
		UNION SELECT user_id FROM user_promotion_entitlement WHERE stripe_redemption_team_id=$1 OR stripe_redemption_reserved_team_id=$1
		UNION SELECT stripe_activation_user_id FROM team_billing_account WHERE team_id=$1 AND stripe_activation_user_id IS NOT NULL
		UNION SELECT stripe_checkout_actor_id FROM team_billing_account WHERE team_id=$1 AND stripe_checkout_actor_id IS NOT NULL`
	if provenance {
		actorSQL += ` UNION SELECT creator_user_id FROM team_signup_trial_provenance WHERE team_id=$1 AND completed_at IS NOT NULL AND creator_user_id IS NOT NULL`
	}
	if claims {
		actorSQL += ` UNION SELECT user_id FROM user_signup_trial_claim WHERE team_id=$1`
	}
	actorSQL = `SELECT ARRAY(SELECT id FROM (` + actorSQL + `) actors ORDER BY id)`
	var actors []uuid.UUID
	if err := tx.QueryRow(ctx, actorSQL, teamID).Scan(&actors); err != nil {
		return fmt.Errorf("read source promotion actors: %w", err)
	}
	for _, actor := range actors {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('stripe-promo-user:' || $1::uuid::text)::bigint)`, actor); err != nil {
			return fmt.Errorf("lock source promotion actor: %w", err)
		}
	}
	if canonical {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('promotion-identity:' || identity_key)::bigint)
			FROM (
			 SELECT identity_key FROM promotion_identity_binding WHERE user_id=ANY($2::uuid[])
			 UNION SELECT 'legacy:' || unnest($2::uuid[])::text
			 UNION SELECT unnest(identity_keys) FROM promotion_identity_history WHERE team_id=$1 OR user_id=ANY($2::uuid[])
			 UNION SELECT stripe_activation_identity_key FROM team_billing_account WHERE team_id=$1
			 UNION SELECT promotion_identity_key(e.user_id,e.email,e.email_verified)
			 FROM promotion_identity_evidence e WHERE evidence_version IN (
			   SELECT evidence_version FROM promotion_identity_current WHERE user_id=ANY($2::uuid[])
			   UNION SELECT stripe_checkout_identity_evidence_version FROM team_billing_account WHERE team_id=$1
			   UNION SELECT stripe_activation_identity_evidence_version FROM team_billing_account WHERE team_id=$1)
			 ORDER BY 1
			) keys WHERE identity_key IS NOT NULL`, teamID, actors); err != nil {
			return fmt.Errorf("lock source promotion identities: %w", err)
		}
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('stripe-promo-team:' || $1::uuid::text)::bigint)`, teamID); err != nil {
		return fmt.Errorf("lock source promotion team: %w", err)
	}
	var currentActors []uuid.UUID
	if err := tx.QueryRow(ctx, actorSQL, teamID).Scan(&currentActors); err != nil {
		return fmt.Errorf("recheck source promotion actors: %w", err)
	}
	if !slices.Equal(actors, currentActors) {
		return fmt.Errorf("source promotion actors changed while locking; retry team migration")
	}
	var pending bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM user_promotion_entitlement
		WHERE (user_id=ANY($2::uuid[]) OR stripe_redemption_reserved_team_id=$1)
		AND (stripe_redemption_reserved_team_id IS NOT NULL OR stripe_redemption_reserved_at IS NOT NULL OR stripe_redemption_attempted_at IS NOT NULL))
		OR EXISTS(SELECT 1 FROM team_billing_account WHERE team_id=$1
		AND stripe_activation_credit_reserved_at IS NOT NULL
		AND stripe_activation_credit_grant_id IS NULL AND stripe_activation_credit_granted_at IS NULL)`, teamID, actors).Scan(&pending); err != nil {
		return fmt.Errorf("check locked source Stripe reservations: %w", err)
	}
	if !pending && canonical {
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM promotion_identity i
			WHERE i.stripe_reserved_team_id=$1 OR (i.stripe_reserved_team_id IS NOT NULL
			AND (i.stripe_reserved_user_id=ANY($2::uuid[]) OR EXISTS(SELECT 1 FROM promotion_identity_binding b
			WHERE b.identity_key=i.identity_key AND b.user_id=ANY($2::uuid[])))))`, teamID, actors).Scan(&pending); err != nil {
			return fmt.Errorf("check locked source canonical reservations: %w", err)
		}
	}
	if pending {
		return fmt.Errorf("settle pending Stripe promotions before migrating this team")
	}
	return nil
}

func fenceSourcePromotionMigration(ctx context.Context, src *pgxpool.Pool, teamID uuid.UUID) error {
	tx, err := src.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin source promotion fence: %w", err)
	}
	defer tx.Rollback(ctx)
	if err := lockSourcePromotionMigration(ctx, tx, teamID); err != nil {
		return err
	}
	var expanded, fenced bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass('public.user_promotion_entitlement') IS NOT NULL,
		to_regclass('public.stripe_promotion_migration_fence') IS NOT NULL`).Scan(&expanded, &fenced); err != nil {
		return fmt.Errorf("check source promotion fence authority: %w", err)
	}
	if expanded && !fenced {
		return fmt.Errorf("source requires the promotion migration fence before team migration")
	}
	if fenced {
		if _, err := tx.Exec(ctx, `INSERT INTO stripe_promotion_migration_fence(team_id) VALUES($1) ON CONFLICT DO NOTHING`, teamID); err != nil {
			return fmt.Errorf("fence source promotions (source administrator credential required): %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit source promotion fence: %w", err)
	}
	return nil
}

// UUID consumption remains authoritative while canonical enforcement is off,
// and historical grants need not have a signup claim or canonical binding.
func mergeStripePromotionState(ctx context.Context, src querier, dst *pgxpool.Pool, teamID uuid.UUID, claimants string) error {
	const schema = `SELECT to_regclass('public.user_promotion_entitlement') IS NOT NULL`
	var source, target bool
	if err := src.QueryRow(ctx, schema).Scan(&source); err != nil {
		return fmt.Errorf("check source Stripe entitlement authority: %w", err)
	}
	if err := dst.QueryRow(ctx, schema).Scan(&target); err != nil {
		return fmt.Errorf("check destination Stripe entitlement authority: %w", err)
	}
	if !source && !target {
		return nil
	}
	if !source || !target {
		return fmt.Errorf("both cells require Stripe entitlement authority before team migration")
	}
	rows, err := src.Query(ctx, `WITH actors AS (`+claimants+`
		UNION SELECT user_id FROM user_promotion_entitlement
		WHERE stripe_redemption_team_id=$1 OR stripe_redemption_reserved_team_id=$1)
		SELECT a.id, e.stripe_redemption_at, e.stripe_redemption_team_id, to_jsonb(p),
		       e.stripe_redemption_reserved_team_id IS NOT NULL OR e.stripe_redemption_reserved_at IS NOT NULL
		       OR e.stripe_redemption_attempted_at IS NOT NULL
		FROM actors a LEFT JOIN user_promotion_entitlement e ON e.user_id=a.id
		LEFT JOIN profile p ON p.id=a.id ORDER BY a.id`, teamID)
	if err != nil {
		return fmt.Errorf("read Stripe entitlement state: %w", err)
	}
	type redemption struct {
		userID    uuid.UUID
		claimedAt *time.Time
		teamID    *uuid.UUID
		profile   json.RawMessage
	}
	var redemptions []redemption
	for rows.Next() {
		var r redemption
		var pending bool
		if err := rows.Scan(&r.userID, &r.claimedAt, &r.teamID, &r.profile, &pending); err != nil {
			rows.Close()
			return fmt.Errorf("scan Stripe entitlement state: %w", err)
		}
		if pending {
			rows.Close()
			return fmt.Errorf("settle pending Stripe promotions before migrating this team")
		}
		redemptions = append(redemptions, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read Stripe entitlement state: %w", err)
	}
	tx, err := dst.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin Stripe entitlement merge: %w", err)
	}
	defer tx.Rollback(ctx)
	var canonical bool
	if err := tx.QueryRow(ctx, `SELECT to_regprocedure('public.canonical_promotion_identity_enabled()') IS NOT NULL`).Scan(&canonical); err != nil {
		return fmt.Errorf("check canonical promotion gate: %w", err)
	}
	if canonical {
		if _, err := tx.Exec(ctx, `SELECT canonical_promotion_identity_enabled()`); err != nil {
			return fmt.Errorf("lock canonical promotion gate: %w", err)
		}
	}
	actors := make([]uuid.UUID, 0, len(redemptions))
	for _, r := range redemptions {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('stripe-promo-user:' || $1::uuid::text)::bigint)`, r.userID); err != nil {
			return fmt.Errorf("lock Stripe entitlement: %w", err)
		}
		actors = append(actors, r.userID)
	}
	if canonical {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('promotion-identity:' || identity_key)::bigint)
			FROM (SELECT DISTINCT identity_key FROM promotion_identity_binding WHERE user_id=ANY($1::uuid[]) ORDER BY identity_key) keys`, actors); err != nil {
			return fmt.Errorf("lock destination Stripe identities: %w", err)
		}
		var pending bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM promotion_identity i
			JOIN promotion_identity_binding b USING(identity_key)
			WHERE b.user_id=ANY($1::uuid[]) AND i.stripe_reserved_team_id IS NOT NULL)`, actors).Scan(&pending); err != nil {
			return fmt.Errorf("check destination Stripe identities: %w", err)
		}
		if pending {
			return fmt.Errorf("settle pending destination Stripe promotions before migrating this team")
		}
	}
	for _, r := range redemptions {
		var pending bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM user_promotion_entitlement WHERE user_id=$1
			AND (stripe_redemption_reserved_team_id IS NOT NULL OR stripe_redemption_reserved_at IS NOT NULL
			OR stripe_redemption_attempted_at IS NOT NULL))`, r.userID).Scan(&pending); err != nil {
			return fmt.Errorf("check destination Stripe reservation: %w", err)
		}
		if pending {
			return fmt.Errorf("settle pending destination Stripe promotions before migrating this team")
		}
		if r.claimedAt == nil {
			continue
		}
		if len(r.profile) == 0 {
			return fmt.Errorf("Stripe entitlement is missing its actor profile; reconcile before team migration")
		}
		if _, err := tx.Exec(ctx, `INSERT INTO profile SELECT * FROM jsonb_populate_record(NULL::profile,$1::jsonb)
			ON CONFLICT(id) DO NOTHING`, r.profile); err != nil {
			return fmt.Errorf("copy Stripe claimant profile: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO user_promotion_entitlement(user_id,stripe_redemption_at,stripe_redemption_team_id)
			VALUES($1,$2,(SELECT id FROM team WHERE id=$3))
			ON CONFLICT(user_id) DO UPDATE SET stripe_redemption_at=EXCLUDED.stripe_redemption_at,
			stripe_redemption_team_id=EXCLUDED.stripe_redemption_team_id,updated_at=now()
			WHERE user_promotion_entitlement.stripe_redemption_at IS NULL`, r.userID, r.claimedAt, r.teamID); err != nil {
			return fmt.Errorf("merge Stripe entitlement: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit Stripe entitlement merge: %w", err)
	}
	return nil
}

func checkCanonicalMigrationPrivileges(ctx context.Context, dst querier) error {
	var allowed bool
	if err := dst.QueryRow(ctx, `SELECT CASE WHEN to_regclass('public.promotion_identity_history') IS NULL THEN true
		ELSE has_table_privilege(current_user,'public.promotion_identity_history','SELECT')
		AND has_table_privilege(current_user,'public.promotion_identity_history','INSERT')
		AND has_table_privilege(current_user,'public.promotion_identity_history','UPDATE') END`).Scan(&allowed); err != nil {
		return fmt.Errorf("check canonical migration privileges: %w", err)
	}
	if !allowed {
		return fmt.Errorf("canonical team migration requires a destination administrator credential with promotion history privileges; the application service role is insufficient")
	}
	return nil
}

// Canonical consumption must arrive before either billing-account pins or owner
// triggers. User bindings intentionally survive profiles and team membership.
func mergeCanonicalPromotionState(ctx context.Context, src querier, dst *pgxpool.Pool, teamID uuid.UUID, claimants string) error {
	const schema = `SELECT to_regclass('public.promotion_identity') IS NOT NULL,
		to_regclass('public.promotion_identity_binding') IS NOT NULL,
		to_regclass('public.promotion_identity_history') IS NOT NULL,
		to_regclass('public.team_signup_promotion_outcome') IS NOT NULL`
	var source, target [4]bool
	if err := src.QueryRow(ctx, schema).Scan(&source[0], &source[1], &source[2], &source[3]); err != nil {
		return fmt.Errorf("check source canonical authority: %w", err)
	}
	if err := dst.QueryRow(ctx, schema).Scan(&target[0], &target[1], &target[2], &target[3]); err != nil {
		return fmt.Errorf("check destination canonical authority: %w", err)
	}
	if source == [4]bool{} && target == [4]bool{} {
		return nil
	}
	if source != [4]bool{true, true, true, true} || target != source {
		return fmt.Errorf("both cells require the complete canonical promotion authority before team migration")
	}
	var payload json.RawMessage
	var pending bool
	if err := src.QueryRow(ctx, `WITH actors AS (`+claimants+`
		UNION SELECT user_id FROM user_signup_trial_claim WHERE team_id=$1
		UNION SELECT user_id FROM user_promotion_entitlement WHERE stripe_redemption_team_id=$1 OR stripe_redemption_reserved_team_id=$1
		UNION SELECT user_id FROM team_signup_promotion_outcome WHERE team_id=$1),
		history AS (SELECT h.* FROM promotion_identity_history h WHERE h.team_id=$1 OR h.user_id IN (SELECT * FROM actors)),
		keys AS (SELECT identity_key FROM promotion_identity_binding WHERE user_id IN (SELECT * FROM actors)
		UNION SELECT stripe_activation_identity_key FROM team_billing_account WHERE team_id=$1
		UNION SELECT identity_key FROM team_signup_promotion_outcome WHERE team_id=$1
		UNION SELECT unnest(identity_keys) FROM history),
		identities AS (SELECT i.* FROM promotion_identity i WHERE i.identity_key IN (SELECT * FROM keys))
		SELECT jsonb_build_object(
		'identities', COALESCE((SELECT jsonb_agg(i ORDER BY identity_key) FROM identities i),'[]'),
		'bindings', COALESCE((SELECT jsonb_agg(b ORDER BY user_id,identity_key) FROM promotion_identity_binding b WHERE identity_key IN (SELECT * FROM keys)),'[]'),
		'evidence', COALESCE((SELECT jsonb_agg(e ORDER BY evidence_version) FROM promotion_identity_evidence e
		 WHERE evidence_version IN (SELECT evidence_version FROM history
		 UNION SELECT stripe_checkout_identity_evidence_version FROM team_billing_account WHERE team_id=$1
		 UNION SELECT stripe_activation_identity_evidence_version FROM team_billing_account WHERE team_id=$1)),'[]'),
		'history', COALESCE((SELECT jsonb_agg(h ORDER BY history_key) FROM history h),'[]'),
		'outcomes', COALESCE((SELECT jsonb_agg(o) FROM team_signup_promotion_outcome o WHERE team_id=$1),'[]')),
		EXISTS(SELECT 1 FROM identities WHERE stripe_reserved_team_id IS NOT NULL)
		OR EXISTS(SELECT 1 FROM user_promotion_entitlement WHERE stripe_redemption_reserved_team_id=$1
		  OR (user_id IN (SELECT * FROM actors) AND stripe_redemption_reserved_team_id IS NOT NULL))`, teamID).Scan(&payload, &pending); err != nil {
		return fmt.Errorf("read canonical promotion state: %w", err)
	}
	if pending {
		return fmt.Errorf("settle pending Stripe promotions before migrating this team")
	}
	tx, err := dst.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin canonical promotion merge: %w", err)
	}
	defer tx.Rollback(ctx)
	locks := []string{
		`SELECT canonical_promotion_identity_enabled() WHERE $1::jsonb IS NOT NULL`,
		`INSERT INTO promotion_identity_evidence SELECT * FROM jsonb_populate_recordset(NULL::promotion_identity_evidence,$1::jsonb->'evidence')
		 ON CONFLICT(evidence_version) DO NOTHING`,
		`SELECT pg_advisory_xact_lock(hashtext('stripe-promo-user:' || user_id::text)::bigint)
		 FROM (SELECT DISTINCT user_id FROM jsonb_populate_recordset(NULL::promotion_identity_binding,$1::jsonb->'bindings') ORDER BY user_id) b`,
		`SELECT pg_advisory_xact_lock(hashtext('promotion-identity:' || identity_key)::bigint)
		 FROM (SELECT identity_key FROM jsonb_populate_recordset(NULL::promotion_identity,$1::jsonb->'identities') ORDER BY identity_key) i`,
	}
	for _, statement := range locks {
		if _, err := tx.Exec(ctx, statement, payload); err != nil {
			return fmt.Errorf("lock canonical promotion consumption: %w", err)
		}
	}
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM promotion_identity i
		JOIN jsonb_populate_recordset(NULL::promotion_identity,$1::jsonb->'identities') s USING(identity_key)
		WHERE i.stripe_reserved_team_id IS NOT NULL)`, payload).Scan(&pending); err != nil {
		return fmt.Errorf("check destination canonical Stripe reservation: %w", err)
	}
	if pending {
		return fmt.Errorf("settle pending destination Stripe promotions before migrating this team")
	}
	statements := []string{
		`INSERT INTO promotion_identity(identity_key,signup_claimed_at,stripe_redemption_at,created_at)
		 SELECT identity_key,signup_claimed_at,stripe_redemption_at,created_at
		 FROM jsonb_populate_recordset(NULL::promotion_identity,$1::jsonb->'identities')
		 ON CONFLICT(identity_key) DO UPDATE SET
		 signup_claimed_at=COALESCE(promotion_identity.signup_claimed_at,EXCLUDED.signup_claimed_at),
		 stripe_redemption_at=COALESCE(promotion_identity.stripe_redemption_at,EXCLUDED.stripe_redemption_at)`,
		`INSERT INTO promotion_identity_binding SELECT * FROM jsonb_populate_recordset(NULL::promotion_identity_binding,$1::jsonb->'bindings')
		 ON CONFLICT DO NOTHING`,
		`INSERT INTO team_signup_promotion_outcome SELECT o.* FROM jsonb_populate_recordset(NULL::team_signup_promotion_outcome,$1::jsonb->'outcomes') o
		 WHERE EXISTS(SELECT 1 FROM team WHERE id=o.team_id) ON CONFLICT(team_id) DO NOTHING`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(ctx, statement, payload); err != nil {
			return fmt.Errorf("merge canonical promotion consumption: %w", err)
		}
	}
	var evidenceConflicts int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM jsonb_populate_recordset(NULL::promotion_identity_evidence,$1::jsonb->'evidence') i
		JOIN promotion_identity_evidence e USING(evidence_version) WHERE to_jsonb(e) IS DISTINCT FROM to_jsonb(i)`, payload).Scan(&evidenceConflicts); err != nil {
		return fmt.Errorf("check captured promotion identity evidence: %w", err)
	}
	if evidenceConflicts != 0 {
		return fmt.Errorf("conflicting captured promotion identity evidence; reconcile both cells before team migration")
	}
	var historyConflicts int
	if err := tx.QueryRow(ctx, `WITH incoming AS (
		SELECT * FROM jsonb_populate_recordset(NULL::promotion_identity_history,$1::jsonb->'history')),
		merged AS (INSERT INTO promotion_identity_history SELECT * FROM incoming
		ON CONFLICT(history_key) DO UPDATE SET history_key=EXCLUDED.history_key RETURNING *)
		SELECT count(*) FROM merged m JOIN incoming i USING(history_key) WHERE to_jsonb(m) IS DISTINCT FROM to_jsonb(i)`, payload).Scan(&historyConflicts); err != nil {
		return fmt.Errorf("merge canonical promotion history: %w", err)
	}
	if historyConflicts != 0 {
		return fmt.Errorf("conflicting historical promotion evidence; reconcile both cells before team migration")
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit canonical promotion merge: %w", err)
	}
	return nil
}
