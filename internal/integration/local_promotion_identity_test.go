//go:build integration

package integration

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func localIdentityTransaction(t *testing.T, enabled bool) pgx.Tx {
	t.Helper()
	tx, err := testPool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	rolloutExec(t, tx, `SET LOCAL test.omit_promotion_identity = 'on'`)
	// The suite normally exercises enforcement. Isolate the staged rollout
	// state in this transaction; production deliberately has no disable API.
	rolloutExec(t, tx, `ALTER TABLE promotion_identity_enforcement DISABLE TRIGGER promotion_identity_enforcement_irreversible`)
	rolloutExec(t, tx, `UPDATE promotion_identity_enforcement SET enabled=$1,
		enabled_at=CASE WHEN $1 THEN now() END,
		readiness_reference=CASE WHEN $1 THEN 'isolated test fixture' END`, enabled)
	rolloutExec(t, tx, `ALTER TABLE promotion_identity_enforcement ENABLE TRIGGER promotion_identity_enforcement_irreversible`)
	return tx
}

func localIdentityWrite(t *testing.T, tx pgx.Tx, user uuid.UUID, email any, verified bool, revision, observed time.Time) uuid.UUID {
	t.Helper()
	var outcome string
	var version uuid.UUID
	if err := tx.QueryRow(context.Background(), `SELECT outcome,evidence_version
		FROM upsert_profile_with_promotion_identity($1,$2,$3,$4,$5)`, user, email, verified, revision, observed).Scan(&outcome, &version); err != nil {
		t.Fatal(err)
	}
	if outcome != "applied" && outcome != "replayed" {
		t.Fatalf("unexpected evidence outcome %q", outcome)
	}
	return version
}

func localIdentityError(t *testing.T, tx pgx.Tx, code, statement string, args ...any) {
	t.Helper()
	rolloutExec(t, tx, `SAVEPOINT local_identity_expected_error`)
	_, err := tx.Exec(context.Background(), statement, args...)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != code {
		t.Fatalf("want SQLSTATE %s, got %v", code, err)
	}
	rolloutExec(t, tx, `ROLLBACK TO SAVEPOINT local_identity_expected_error`)
}

func localIdentityTeam(t *testing.T, tx pgx.Tx, user uuid.UUID) (uuid.UUID, string) {
	t.Helper()
	var team uuid.UUID
	var outcome string
	if err := tx.QueryRow(context.Background(), `SELECT id FROM create_team_with_signup_trial($1,$2,'use')`, "local-identity-"+uuid.NewString(), user).Scan(&team); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(context.Background(), `SELECT outcome FROM team_signup_promotion_outcome WHERE team_id=$1`, team).Scan(&outcome); err != nil {
		t.Fatal(err)
	}
	return team, outcome
}

func TestIntegration_LocalPromotionEvidenceAtomicAndMonotonic(t *testing.T) {
	ctx := context.Background()
	tx := localIdentityTransaction(t, false)
	user := uuid.New()
	now := time.Now().UTC().Truncate(time.Microsecond)
	email := "Mixed.Case+Alias@googlemail.com"
	first := localIdentityWrite(t, tx, user, email, true, now.Add(-time.Hour), now)
	rolloutExec(t, tx, `UPDATE profile SET full_name='Example Person',avatar_url='https://example.com/avatar.png',storage_quota_bytes=4096 WHERE id=$1`, user)
	second := localIdentityWrite(t, tx, user, email, true, now.Add(-time.Hour), now.Add(time.Second))
	if first == second {
		t.Fatal("refresh overwrote its immutable snapshot")
	}
	if replay := localIdentityWrite(t, tx, user, email, true, now.Add(-time.Hour), now.Add(time.Second)); replay != second {
		t.Fatal("identical delivery created a different snapshot")
	}
	for _, args := range [][]any{
		{user, "changed@example.com", true, now.Add(-2 * time.Hour), now},
		{user, "changed@example.com", true, now.Add(-time.Hour), now},
		{user, email, false, now.Add(-time.Hour), now},
		{user, email, true, now, now.Add(-6 * time.Minute)},
		{user, email, true, now, now.Add(time.Minute)},
	} {
		localIdentityError(t, tx, "22023", `SELECT upsert_profile_with_promotion_identity($1,$2,$3,$4,$5)`, args...)
	}
	localIdentityError(t, tx, "55000", `UPDATE promotion_identity_evidence SET email='changed@example.com' WHERE evidence_version=$1`, first)
	localIdentityError(t, tx, "55000", `DELETE FROM promotion_identity_evidence WHERE evidence_version=$1`, first)
	var intact bool
	if err := tx.QueryRow(ctx, `SELECT p.email=$2 AND p.full_name='Example Person' AND p.storage_quota_bytes=4096
		AND p.avatar_url='https://example.com/avatar.png' AND c.evidence_version=$3
		AND (SELECT count(*) FROM promotion_identity_evidence WHERE user_id=$1)=2
		AND NOT EXISTS(SELECT 1 FROM promotion_identity_binding WHERE user_id=$1)
		AND NOT EXISTS(SELECT 1 FROM user_promotion_entitlement WHERE user_id=$1)
		FROM profile p JOIN promotion_identity_current c ON c.user_id=p.id WHERE p.id=$1`, user, email, second).Scan(&intact); err != nil || !intact {
		t.Fatalf("profile/evidence atomicity or profile preservation failed: %t %v", intact, err)
	}
	rolloutExec(t, tx, `SAVEPOINT local_identity_rollback`)
	rolledBack := uuid.New()
	localIdentityWrite(t, tx, rolledBack, "rollback@example.com", true, now, now)
	rolloutExec(t, tx, `ROLLBACK TO SAVEPOINT local_identity_rollback`)
	if err := tx.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM profile WHERE id=$1)
		AND NOT EXISTS(SELECT 1 FROM promotion_identity_evidence WHERE user_id=$1)`, rolledBack).Scan(&intact); err != nil || !intact {
		t.Fatalf("transaction rollback retained profile or evidence: %t %v", intact, err)
	}
}

func TestIntegration_LocalPromotionGateOffPreservesUserClaimsAndHistory(t *testing.T) {
	ctx := context.Background()
	tx := localIdentityTransaction(t, false)
	user := uuid.New()
	rolloutExec(t, tx, `INSERT INTO profile(id,email) VALUES($1,'old-writer@example.com')`, user)
	team, outcome := localIdentityTeam(t, tx, user)
	if outcome != "granted" {
		t.Fatalf("OFF rejected legacy writer: %s", outcome)
	}
	if _, outcome = localIdentityTeam(t, tx, user); outcome != "already_claimed" {
		t.Fatalf("OFF reopened user claim: %s", outcome)
	}
	var pending bool
	if err := tx.QueryRow(ctx, `SELECT status='pending' AND evidence_version IS NULL
		FROM promotion_identity_history WHERE history_key='signup-grant:'||$1::text`, team).Scan(&pending); err != nil || !pending {
		t.Fatalf("OFF grant lost historical obligation: %t %v", pending, err)
	}
	now := time.Now().UTC()
	localIdentityWrite(t, tx, user, "later@example.com", true, now, now)
	if err := tx.QueryRow(ctx, `SELECT status='pending' AND evidence_version IS NULL
		FROM promotion_identity_history WHERE history_key='signup-grant:'||$1::text`, team).Scan(&pending); err != nil || !pending {
		t.Fatalf("later evidence resolved an old grant: %t %v", pending, err)
	}
	localIdentityError(t, tx, "55000", `SELECT enable_canonical_promotion_identity('{"reference":"test readiness","all_writers_ready":true,"rollback_ready":true}')`)
	rolloutExec(t, tx, `DELETE FROM team_credit_grant WHERE team_id=$1`, team)
	rolloutExec(t, tx, `DELETE FROM team WHERE id=$1`, team)
	rolloutExec(t, tx, `DELETE FROM team_member WHERE profile_id=$1`, user)
	rolloutExec(t, tx, `DELETE FROM profile WHERE id=$1`, user)
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM promotion_identity_history WHERE user_id=$1 AND status='pending')`, user).Scan(&pending); err != nil || !pending {
		t.Fatalf("deletion erased historical obligation: %t %v", pending, err)
	}
	rolloutExec(t, tx, `INSERT INTO profile(id,email) VALUES($1,'recreated@example.com')`, user)
	if _, outcome := localIdentityTeam(t, tx, user); outcome != "already_claimed" {
		t.Fatalf("OFF deletion reopened the same user's entitlement: %s", outcome)
	}
}

func TestIntegration_LocalPromotionGateEnableConsumesOffAliases(t *testing.T) {
	ctx := context.Background()
	tx := localIdentityTransaction(t, false)
	// Other tests may leave pending reservations. Remove only their gate
	// blockers inside this transaction, which is rolled back after the test.
	rolloutExec(t, tx, `DELETE FROM promotion_identity_history`)
	rolloutExec(t, tx, `UPDATE user_promotion_entitlement SET stripe_redemption_reserved_team_id=NULL,stripe_redemption_reserved_at=NULL,stripe_redemption_attempted_at=NULL`)
	rolloutExec(t, tx, `UPDATE promotion_identity SET stripe_reserved_team_id=NULL,stripe_reserved_user_id=NULL`)
	rolloutExec(t, tx, `UPDATE team_billing_account SET stripe_activation_credit_reserved_at=NULL,checkout_initializing_at=NULL,checkout_completed_at=NULL`)
	mailbox := "staged" + strings.ReplaceAll(uuid.NewString(), "-", "")
	now := time.Now().UTC()
	for _, email := range []string{mailbox + "@gmail.com", mailbox + "+off@googlemail.com"} {
		user := uuid.New()
		localIdentityWrite(t, tx, user, email, true, now, now)
		if _, outcome := localIdentityTeam(t, tx, user); outcome != "granted" {
			t.Fatalf("OFF enforced canonical aliases: %s", outcome)
		}
	}
	localIdentityError(t, tx, "22023", `SELECT enable_canonical_promotion_identity('ticket-only')`)
	localIdentityError(t, tx, "22023", `SELECT enable_canonical_promotion_identity('{"reference":"test readiness","all_writers_ready":true}')`)
	rolloutExec(t, tx, `SELECT enable_canonical_promotion_identity('{"reference":"test readiness","all_writers_ready":true,"rollback_ready":true}')`)
	localIdentityError(t, tx, "55000", `UPDATE promotion_identity_enforcement SET enabled=false,enabled_at=NULL,readiness_reference=NULL`)
	alias := uuid.New()
	localIdentityWrite(t, tx, alias, mailbox+"+on@gmail.com", true, now, now)
	if _, outcome := localIdentityTeam(t, tx, alias); outcome != "already_claimed" {
		t.Fatalf("enable reopened OFF consumption: %s", outcome)
	}
	var grants int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM promotion_identity_history
		WHERE promotion='signup' AND status='reconciled' AND identity_keys=ARRAY[promotion_identity_key($1,$2,true)]`, alias, mailbox+"@gmail.com").Scan(&grants); err != nil || grants != 2 {
		t.Fatalf("OFF grants were not atomically consumed: %d %v", grants, err)
	}
}

func TestIntegration_LocalPromotionFreshnessAndCapturedVersion(t *testing.T) {
	ctx := context.Background()
	tx := localIdentityTransaction(t, true)
	now := time.Now().UTC()
	user := uuid.New()
	mailbox := "captured" + strings.ReplaceAll(uuid.NewString(), "-", "") + "@gmail.com"
	first := localIdentityWrite(t, tx, user, mailbox, true, now.Add(-time.Hour), now)
	stale := uuid.New()
	rolloutExec(t, tx, `INSERT INTO promotion_identity_evidence(evidence_version,user_id,email,email_verified,auth_updated_at,observed_at)
		VALUES($1,$2,$3,true,$4,$5)`, stale, user, mailbox, now.Add(-time.Hour), now.Add(-6*time.Minute))
	rolloutExec(t, tx, `UPDATE promotion_identity_current SET evidence_version=$1 WHERE user_id=$2`, stale, user)
	localIdentityError(t, tx, "55000", `SELECT capture_promotion_identity_evidence($1)`, user)
	localIdentityError(t, tx, "55000", `SELECT resolve_promotion_identity_evidence($1,$2)`, uuid.New(), first)
	var key string
	if err := tx.QueryRow(ctx, `SELECT resolve_promotion_identity_evidence($1,$2)`, user, stale).Scan(&key); err != nil || !strings.HasPrefix(key, "gmail:") {
		t.Fatalf("captured evidence incorrectly expired: %q %v", key, err)
	}
	localIdentityError(t, tx, "55000", `SELECT capture_promotion_identity_evidence($1)`, uuid.New())
	for _, email := range []any{nil, "not-an-email", "name@gmail.com."} {
		actor := uuid.New()
		localIdentityWrite(t, tx, actor, email, true, now, now)
		if _, outcome := localIdentityTeam(t, tx, actor); outcome != "promotion_ineligible" {
			t.Fatalf("invalid authoritative address was not ineligible: %s", outcome)
		}
	}
	unverified := uuid.New()
	localIdentityWrite(t, tx, unverified, "unverified@example.com", false, now, now)
	if _, outcome := localIdentityTeam(t, tx, unverified); outcome != "promotion_ineligible" {
		t.Fatalf("authoritative unverified address was not ineligible: %s", outcome)
	}
}

func TestIntegration_LocalPromotionCompletedReplayDoesNotNeedEvidence(t *testing.T) {
	ctx := context.Background()
	tx := localIdentityTransaction(t, true)
	rolloutExec(t, tx, `DELETE FROM promotion_identity_history WHERE status='pending'`)
	user := uuid.New()
	now := time.Now().UTC()
	localIdentityWrite(t, tx, user, "replay"+strings.ReplaceAll(user.String(), "-", "")+"@gmail.com", true, now, now)
	team, outcome := localIdentityTeam(t, tx, user)
	if outcome != "granted" {
		t.Fatal(outcome)
	}
	rolloutExec(t, tx, `DELETE FROM promotion_identity_current WHERE user_id=$1`, user)
	if err := tx.QueryRow(ctx, `SELECT outcome FROM claim_team_signup_trial($1,$2)`, team, user).Scan(&outcome); err != nil || outcome != "granted" {
		t.Fatalf("completed result depended on current evidence: %s %v", outcome, err)
	}
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM team_credit_grant WHERE team_id=$1 AND reason='signup trial credit'`, team).Scan(&count); err != nil || count != 1 {
		t.Fatalf("replay duplicated grant: %d %v", count, err)
	}
}

func TestIntegration_LocalPromotionBindingSurvivesEmailChangeAndDeletion(t *testing.T) {
	ctx := context.Background()
	tx := localIdentityTransaction(t, true)
	rolloutExec(t, tx, `DELETE FROM promotion_identity_history WHERE status='pending'`)
	user := uuid.New()
	now := time.Now().UTC()
	oldMailbox := "before" + strings.ReplaceAll(user.String(), "-", "")
	newMailbox := "after" + strings.ReplaceAll(user.String(), "-", "")
	localIdentityWrite(t, tx, user, oldMailbox+"@gmail.com", true, now.Add(-time.Hour), now)
	team, outcome := localIdentityTeam(t, tx, user)
	if outcome != "granted" {
		t.Fatal(outcome)
	}
	localIdentityWrite(t, tx, user, newMailbox+"@gmail.com", true, now, now)
	if _, outcome := localIdentityTeam(t, tx, user); outcome != "already_claimed" {
		t.Fatalf("email change reopened the user's grant: %s", outcome)
	}
	rolloutExec(t, tx, `DELETE FROM team_credit_grant WHERE team_id=$1`, team)
	rolloutExec(t, tx, `DELETE FROM team WHERE id=$1`, team)
	rolloutExec(t, tx, `DELETE FROM team_member WHERE profile_id=$1`, user)
	rolloutExec(t, tx, `DELETE FROM profile WHERE id=$1`, user)
	for _, mailbox := range []string{oldMailbox, newMailbox} {
		alias := uuid.New()
		localIdentityWrite(t, tx, alias, mailbox+"+recreated@googlemail.com", true, now, now)
		if _, outcome := localIdentityTeam(t, tx, alias); outcome != "already_claimed" {
			t.Fatalf("deletion reopened a bound mailbox: %s", outcome)
		}
	}
	var retained bool
	if err := tx.QueryRow(ctx, `SELECT count(*)=2 FROM promotion_identity_binding WHERE user_id=$1`, user).Scan(&retained); err != nil || !retained {
		t.Fatalf("deletion erased mailbox bindings: %t %v", retained, err)
	}
}

func TestIntegration_LocalPromotionWriterPrivileges(t *testing.T) {
	ctx := context.Background()
	tx := localIdentityTransaction(t, false)
	rolloutExec(t, tx, `DO $$ DECLARE r text; BEGIN FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
		IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname=r) THEN EXECUTE format('CREATE ROLE %I NOLOGIN',r); END IF; END LOOP; END $$`)
	migration, err := os.ReadFile("../../supabase/migrations/20260925195235_canonical_promotion_identity.sql")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(migration), "REVOKE ALL ON FUNCTION promotion_identity_key")
	end := strings.LastIndex(string(migration), "\nCOMMIT;")
	if start < 0 || end <= start {
		t.Fatal("promotion privilege segment missing")
	}
	// The migration commits itself; this fragment must retain the test rollback.
	rolloutExec(t, tx, string(migration[start:end]))
	if tx.Conn().PgConn().TxStatus() != 'T' {
		t.Fatal("privilege fragment ended the fixture transaction")
	}
	for _, role := range []string{"anon", "authenticated", "service_role"} {
		var write, enable, mutate bool
		if err := tx.QueryRow(ctx, `SELECT
			has_function_privilege($1,'upsert_profile_with_promotion_identity(uuid,text,boolean,timestamptz,timestamptz)','EXECUTE'),
			has_function_privilege($1,'enable_canonical_promotion_identity(text)','EXECUTE'),
			has_table_privilege($1,'promotion_identity_evidence','INSERT,UPDATE,DELETE,TRUNCATE')
			OR has_table_privilege($1,'promotion_identity_current','INSERT,UPDATE,DELETE,TRUNCATE')
			OR has_table_privilege($1,'promotion_identity_enforcement','INSERT,UPDATE,DELETE,TRUNCATE')`, role).Scan(&write, &enable, &mutate); err != nil {
			t.Fatal(err)
		}
		if write != (role == "service_role") || enable || mutate {
			t.Fatalf("unexpected %s privileges: writer=%t enable=%t raw mutation=%t", role, write, enable, mutate)
		}
	}
	rolloutExec(t, tx, `SET LOCAL ROLE service_role`)
	now := time.Now().UTC()
	localIdentityWrite(t, tx, uuid.New(), "trusted-writer@example.com", true, now, now)
	localIdentityError(t, tx, "42501", `SELECT enable_canonical_promotion_identity('{"reference":"untrusted","all_writers_ready":true,"rollback_ready":true}')`)
	localIdentityError(t, tx, "42501", `INSERT INTO promotion_identity_evidence(user_id,email,email_verified,auth_updated_at,observed_at)
		VALUES(gen_random_uuid(),'untrusted@example.com',true,now(),now())`)
}

func TestIntegration_LocalPromotionGateSerializesActivation(t *testing.T) {
	ctx := context.Background()
	claim, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer claim.Rollback(ctx)
	// Every claim and reservation holds this shared lock through its grant or
	// pending-history commit. Activation must wait before checking that history.
	rolloutExec(t, claim, `SELECT canonical_promotion_identity_enabled()`)
	enable, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer enable.Rollback(ctx)
	rolloutExec(t, enable, `SET LOCAL lock_timeout='100ms'`)
	_, err = enable.Exec(ctx, `SELECT enable_canonical_promotion_identity('{"reference":"concurrent readiness","all_writers_ready":true,"rollback_ready":true}')`)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
		t.Fatalf("gate activation raced an open claim: %v", err)
	}
}
