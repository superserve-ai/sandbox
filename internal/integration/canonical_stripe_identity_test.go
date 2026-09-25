//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/superserve-ai/sandbox/internal/db"
)

func canonicalStripeActor(t *testing.T, email string, verified bool) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := testPool.Exec(context.Background(), `INSERT INTO profile(id,email) VALUES($1,$2)`, id, email); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(context.Background(), `SELECT * FROM upsert_profile_with_promotion_identity($1,$2,$3,clock_timestamp(),clock_timestamp())`, id, email, verified); err != nil {
		t.Fatal(err)
	}
	return id
}

func canonicalStripeTeam(t *testing.T) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := testPool.Exec(context.Background(), `INSERT INTO team(id,name) VALUES($1,$2)`, id, "canonical-credit-"+id.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(context.Background(), `INSERT INTO team_billing_account(team_id,stripe_subscription_status) VALUES($1,'active')`, id); err != nil {
		t.Fatal(err)
	}
	return id
}

func canonicalStripeReserve(t *testing.T, teamID, userID uuid.UUID, eventID string) string {
	t.Helper()
	var state string
	if err := testPool.QueryRow(context.Background(), `SELECT reserve_stripe_promotion_for_event_state($1,$2,$3)`, teamID, userID, eventID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	return state
}

func TestIntegration_CanonicalStripeAliasesShareDurableFence(t *testing.T) {
	ctx := context.Background()
	mailbox := "stripe" + uuid.New().String()[:8]
	users := []uuid.UUID{
		canonicalStripeActor(t, mailbox[:5]+"."+mailbox[5:]+"+one@gmail.com", true),
		canonicalStripeActor(t, mailbox+"+two@googlemail.com", true),
	}
	teams := []uuid.UUID{canonicalStripeTeam(t), canonicalStripeTeam(t)}
	states := make([]string, 2)
	errs := make([]error, 2)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range users {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = testPool.QueryRow(ctx, `SELECT reserve_stripe_promotion_for_event_state($1,$2,$3)`, teams[i], users[i], fmt.Sprintf("evt_canonical_%s", teams[i])).Scan(&states[i])
		}(i)
	}
	close(start)
	wg.Wait()
	winner := -1
	for i, state := range states {
		if errs[i] != nil {
			t.Fatal(errs[i])
		}
		if state == "acquired" {
			if winner != -1 {
				t.Fatalf("aliases both acquired: %v", states)
			}
			winner = i
		} else if state != "blocked" {
			t.Fatalf("unexpected reservation states: %v", states)
		}
	}
	if winner == -1 {
		t.Fatalf("neither alias acquired: %v", states)
	}
	loser := 1 - winner
	if state := canonicalStripeReserve(t, teams[winner], users[loser], "evt_takeover"); state != "blocked" {
		t.Fatalf("alias took over another actor's reservation: %s", state)
	}
	if _, err := testPool.Exec(ctx, `SELECT release_stripe_promotion_for_event($1,$2,'evt_takeover')`, teams[winner], users[loser]); err != nil {
		t.Fatal(err)
	}
	if state := canonicalStripeReserve(t, teams[winner], users[winner], fmt.Sprintf("evt_canonical_%s", teams[winner])); state != "existing" {
		t.Fatalf("alias cleanup released winner: %s", state)
	}
	if _, err := testPool.Exec(ctx, `SELECT finalize_stripe_promotion($1,$2,'credit_canonical')`, teams[winner], users[winner]); err != nil {
		t.Fatal(err)
	}
	if state := canonicalStripeReserve(t, teams[loser], users[loser], "evt_after_finalize"); state != "ineligible" {
		t.Fatalf("redeemed mailbox became eligible through an alias: %s", state)
	}
	if _, err := testPool.Exec(ctx, `DELETE FROM team_credit_grant WHERE team_id=$1`, teams[winner]); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `DELETE FROM team WHERE id=$1`, teams[winner]); err != nil {
		t.Fatal(err)
	}
	if state := canonicalStripeReserve(t, teams[loser], users[loser], "evt_after_delete"); state != "ineligible" {
		t.Fatalf("team deletion reopened mailbox entitlement: %s", state)
	}
	var signup uuid.UUID
	if err := testPool.QueryRow(ctx, `SELECT id FROM create_team_with_signup_trial($1,$2)`, "independent-signup-"+uuid.NewString(), users[loser]).Scan(&signup); err != nil {
		t.Fatal(err)
	}
	var grants int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM team_credit_grant WHERE team_id=$1 AND reason='signup trial credit'`, signup).Scan(&grants); err != nil || grants != 1 {
		t.Fatalf("Stripe consumption incorrectly consumed signup: grants=%d err=%v", grants, err)
	}
}

func TestIntegration_CanonicalStripeRetryUsesPinnedIdentityWithoutAuthority(t *testing.T) {
	ctx := context.Background()
	mailbox := "pinned" + uuid.New().String()[:8]
	userID := canonicalStripeActor(t, mailbox+"@gmail.com", true)
	teamID := canonicalStripeTeam(t)
	eventID := "evt_pinned_" + teamID.String()
	if state := canonicalStripeReserve(t, teamID, userID, eventID); state != "acquired" {
		t.Fatalf("reserve: %s", state)
	}
	var originalKey string
	if err := testPool.QueryRow(ctx, `SELECT stripe_activation_identity_key FROM team_billing_account WHERE team_id=$1`, teamID).Scan(&originalKey); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE user_promotion_entitlement SET stripe_redemption_attempted_at=now() WHERE user_id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `DELETE FROM promotion_identity_current WHERE user_id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	if state := canonicalStripeReserve(t, teamID, userID, eventID); state != "existing" {
		t.Fatalf("durable retry required new identity evidence: %s", state)
	}
	var pinnedState string
	if err := testPool.QueryRow(ctx, `SELECT reserve_stripe_promotion_for_subscription_event_state(
		$1,$2,$3,'sub_unrelated',NULL,true)`, teamID, userID, eventID).Scan(&pinnedState); err != nil || pinnedState != "existing" {
		t.Fatalf("durable retry was affected by missing generation proof: %s %v", pinnedState, err)
	}
	if state := canonicalStripeReserve(t, teamID, userID, "evt_newer"); state != "blocked" {
		t.Fatalf("newer event stole ambiguous fence: %s", state)
	}
	if _, err := testPool.Exec(ctx, `SELECT finalize_stripe_promotion($1,$2,'credit_pinned')`, teamID, userID); err != nil {
		t.Fatalf("settlement required new identity evidence: %v", err)
	}
	var consumed bool
	if err := testPool.QueryRow(ctx, `SELECT stripe_redemption_at IS NOT NULL AND stripe_reserved_team_id IS NULL FROM promotion_identity WHERE identity_key=$1`, originalKey).Scan(&consumed); err != nil || !consumed {
		t.Fatalf("pinned identity not consumed: %v err=%v", consumed, err)
	}
	alias := canonicalStripeActor(t, mailbox+"+later@googlemail.com", true)
	if state := canonicalStripeReserve(t, canonicalStripeTeam(t), alias, "evt_pinned_alias"); state != "ineligible" {
		t.Fatalf("pinned mailbox was not fenced: %s", state)
	}
}

func TestIntegration_CanonicalStripeInsufficientEvidenceCannotReserve(t *testing.T) {
	ctx := context.Background()
	userID := canonicalStripeActor(t, "unverified"+uuid.New().String()[:8]+"@gmail.com", false)
	teamID := canonicalStripeTeam(t)
	if state := canonicalStripeReserve(t, teamID, userID, "evt_unverified"); state != "ineligible" {
		t.Fatalf("unverified evidence reserved: %s", state)
	}
	if _, err := testPool.Exec(ctx, `DELETE FROM promotion_identity_current WHERE user_id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	var state string
	err := testPool.QueryRow(ctx, `SELECT reserve_stripe_promotion_for_event_state($1,$2,'evt_unavailable')`, teamID, userID).Scan(&state)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "55000" {
		t.Fatalf("unavailable authority did not fail closed: state=%q err=%v", state, err)
	}
	var pending bool
	if err := testPool.QueryRow(ctx, `SELECT stripe_activation_credit_reserved_at IS NOT NULL FROM team_billing_account WHERE team_id=$1`, teamID).Scan(&pending); err != nil || pending {
		t.Fatalf("failed evidence left a reservation: %v err=%v", pending, err)
	}
}

func TestIntegration_CanonicalStripeHistoricalPendingRemainsRecoverable(t *testing.T) {
	ctx := context.Background()
	userID := canonicalStripeActor(t, "historical"+uuid.New().String()[:8]+"@gmail.com", true)
	teamID := canonicalStripeTeam(t)
	migration, err := os.ReadFile("../../supabase/migrations/20260924191922_canonical_stripe_promotion_fences.sql")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(migration), "-- Existing external attempts")
	end := strings.Index(string(migration), "CREATE OR REPLACE FUNCTION lock_stripe_promotion")
	if start < 0 || end <= start {
		t.Fatal("historical reservation migration segment missing")
	}
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `INSERT INTO user_promotion_entitlement(user_id,stripe_redemption_reserved_team_id,stripe_redemption_reserved_at,stripe_redemption_attempted_at)
		VALUES($1,$2,now()-interval '2 hours',now()-interval '1 hour')`, userID, teamID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE team_billing_account SET stripe_activation_user_id=$2,
		stripe_activation_credit_reserved_at=now()-interval '2 hours',stripe_activation_credit_reservation_event_id='evt_historical'
		WHERE team_id=$1`, teamID, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, string(migration[start:end])); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM promotion_identity_current WHERE user_id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	var state string
	if err := tx.QueryRow(ctx, `SELECT reserve_stripe_promotion_for_event_state($1,$2,'evt_historical')`, teamID, userID).Scan(&state); err != nil || state != "existing" {
		t.Fatalf("historical retry: %s err=%v", state, err)
	}
	var intact bool
	if err := tx.QueryRow(ctx, `SELECT a.stripe_activation_identity_key='legacy:'||$2::text
		AND u.stripe_redemption_attempted_at=now()-interval '1 hour'
		AND promotion_identity_history_pending('stripe')
		FROM team_billing_account a JOIN user_promotion_entitlement u ON u.user_id=a.stripe_activation_user_id
		WHERE a.team_id=$1`, teamID, userID).Scan(&intact); err != nil || !intact {
		t.Fatalf("migration lost ambiguous attempt/quarantine: %v err=%v", intact, err)
	}
	if _, err := tx.Exec(ctx, `SELECT finalize_stripe_promotion($1,$2,'credit_historical')`, teamID, userID); err != nil {
		t.Fatalf("historical settlement depends on unavailable identity: %v", err)
	}
	if err := tx.QueryRow(ctx, `SELECT stripe_redemption_at IS NOT NULL AND stripe_reserved_team_id IS NULL
		FROM promotion_identity WHERE identity_key='legacy:'||$1::text`, userID).Scan(&intact); err != nil || !intact {
		t.Fatalf("historical settlement lost consumption: %v err=%v", intact, err)
	}
}

func TestIntegration_CanonicalStripeCheckoutPinsEvidenceForItsGeneration(t *testing.T) {
	ctx := context.Background()
	teamID, key, actorID := seedTeamAndKeyWithRole(t, "team_owner")
	enableBillingExportForCheckoutActorTest(t, teamID)
	firstEmail := "checkout" + uuid.New().String()[:8] + "@gmail.com"
	if _, err := testPool.Exec(ctx, `SELECT * FROM upsert_profile_with_promotion_identity($1,$2,true,clock_timestamp(),clock_timestamp())`, actorID, firstEmail); err != nil {
		t.Fatal(err)
	}
	stripe := &fakeStripeClient{nextCustomerID: "cus_" + teamID.String()}
	router := newBillingRouter(t, stripe)
	if w := do(router, "POST", "/stripe/checkout-session", key, checkoutRegressionBody); w.Code != http.StatusOK {
		t.Fatalf("checkout: %d %s", w.Code, w.Body.String())
	}
	var pinned uuid.UUID
	if err := testPool.QueryRow(ctx, `SELECT stripe_checkout_identity_evidence_version FROM team_billing_account WHERE team_id=$1`, teamID).Scan(&pinned); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `SELECT * FROM upsert_profile_with_promotion_identity($1,$2,true,clock_timestamp(),clock_timestamp())`, actorID, "changed"+uuid.New().String()[:8]+"@gmail.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `DELETE FROM promotion_identity_current WHERE user_id=$1`, actorID); err != nil {
		t.Fatal(err)
	}
	if w := do(router, "POST", "/stripe/checkout-session", key, checkoutRegressionBody); w.Code != http.StatusOK {
		t.Fatalf("generation retry required fresh evidence: %d %s", w.Code, w.Body.String())
	}
	var same bool
	if err := testPool.QueryRow(ctx, `SELECT stripe_checkout_identity_evidence_version=$2 FROM team_billing_account WHERE team_id=$1`, teamID, pinned).Scan(&same); err != nil || !same {
		t.Fatalf("retry changed captured evidence: %v %v", same, err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	completionID := "evt_complete_identity_" + teamID.String()
	completion := []byte(strings.ReplaceAll(string(stripeCheckoutWebhookPayload(t, completionID, teamID.String(), stripe.nextCustomerID, "sub_"+teamID.String(), now)), "cs_"+completionID, "cs_test_123"))
	req := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(completion)))
	req.Header.Set("Stripe-Signature", stripeSignature(t, completion, now))
	if w := doRequest(router, req); w.Code != http.StatusOK {
		t.Fatalf("delayed checkout completion: %d %s", w.Code, w.Body.String())
	}
	otherActor := canonicalStripeActor(t, uuid.NewString()+"@example.com", true)
	if w := sendStripeActivationWebhook(t, router, "evt_delayed_"+teamID.String(), teamID, otherActor, now); w.Code != http.StatusOK {
		t.Fatalf("delayed activation did not use generation capture: %d %s", w.Code, w.Body.String())
	}
	if len(stripe.creditGrantCalls) != 1 {
		t.Fatalf("captured generation issued %d grants, want one", len(stripe.creditGrantCalls))
	}
	var otherConsumed bool
	if err := testPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM user_promotion_entitlement WHERE user_id=$1 AND stripe_redemption_at IS NOT NULL)`, otherActor).Scan(&otherConsumed); err != nil || otherConsumed {
		t.Fatalf("subscription metadata overrode captured billing actor: consumed=%v err=%v", otherConsumed, err)
	}
	var original bool
	if err := testPool.QueryRow(ctx, `SELECT stripe_activation_identity_key=promotion_identity_key($2,$3,true)
		AND stripe_activation_identity_evidence_version=$4 FROM team_billing_account WHERE team_id=$1`, teamID, actorID, firstEmail, pinned).Scan(&original); err != nil || !original {
		t.Fatalf("activation used changed identity: %v %v", original, err)
	}
	alias := canonicalStripeActor(t, strings.Replace(firstEmail, "@gmail.com", "+alias@googlemail.com", 1), true)
	if state := canonicalStripeReserve(t, canonicalStripeTeam(t), alias, "evt_original_mailbox"); state != "ineligible" {
		t.Fatalf("captured original mailbox was not consumed: %s", state)
	}
}

func TestIntegration_CanonicalStripeDefinitiveCheckoutFailureClearsEvidence(t *testing.T) {
	ctx := context.Background()
	teamID, firstKey, firstActor := seedTeamAndKeyWithRole(t, "team_owner")
	secondKey := seedKeyForExistingTeamWithRole(t, teamID, "team_owner")
	enableBillingExportForCheckoutActorTest(t, teamID)
	stripe := &fakeStripeClient{nextCustomerID: "cus_failure_" + teamID.String(), checkoutErr: errors.New("Stripe returned 400")}
	router := newBillingRouter(t, stripe)
	if w := do(router, "POST", "/stripe/checkout-session", firstKey, checkoutRegressionBody); w.Code != http.StatusBadGateway {
		t.Fatalf("definitive failure: %d %s", w.Code, w.Body.String())
	}
	var cleared bool
	if err := testPool.QueryRow(ctx, `SELECT stripe_checkout_actor_id IS NULL AND stripe_checkout_identity_evidence_version IS NULL
		FROM team_billing_account WHERE team_id=$1`, teamID).Scan(&cleared); err != nil || !cleared {
		t.Fatalf("failed generation retained identity: %v %v", cleared, err)
	}
	stripe.checkoutErr = nil
	if w := do(router, "POST", "/stripe/checkout-session", secondKey, checkoutRegressionBody); w.Code != http.StatusOK {
		t.Fatalf("replacement writer: %d %s", w.Code, w.Body.String())
	}
	var replaced bool
	if err := testPool.QueryRow(ctx, `SELECT a.stripe_checkout_actor_id<>$2 AND e.user_id=a.stripe_checkout_actor_id
		FROM team_billing_account a JOIN promotion_identity_evidence e ON e.evidence_version=a.stripe_checkout_identity_evidence_version
		WHERE a.team_id=$1`, teamID, firstActor).Scan(&replaced); err != nil || !replaced {
		t.Fatalf("replacement writer inherited failed actor evidence: %v %v", replaced, err)
	}
}

func TestIntegration_CanonicalStripeAmbiguousCheckoutKeepsCapturedEvidence(t *testing.T) {
	ctx := context.Background()
	teamID, key, actor := seedTeamAndKeyWithRole(t, "team_owner")
	enableBillingExportForCheckoutActorTest(t, teamID)
	stripe := &fakeStripeClient{nextCustomerID: "cus_ambiguous_identity_" + teamID.String(), checkoutErr: errors.New("transport timeout")}
	router := newBillingRouter(t, stripe)
	if w := do(router, "POST", "/stripe/checkout-session", key, checkoutRegressionBody); w.Code != http.StatusBadGateway {
		t.Fatalf("ambiguous checkout: %d %s", w.Code, w.Body.String())
	}
	var evidence uuid.UUID
	if err := testPool.QueryRow(ctx, `SELECT stripe_checkout_identity_evidence_version FROM team_billing_account WHERE team_id=$1`, teamID).Scan(&evidence); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `DELETE FROM promotion_identity_current WHERE user_id=$1`, actor); err != nil {
		t.Fatal(err)
	}
	stripe.checkoutErr = nil
	if w := do(router, "POST", "/stripe/checkout-session", key, checkoutRegressionBody); w.Code != http.StatusOK {
		t.Fatalf("ambiguous retry required new evidence: %d %s", w.Code, w.Body.String())
	}
	var preserved bool
	if err := testPool.QueryRow(ctx, `SELECT stripe_checkout_identity_evidence_version=$2 AND stripe_checkout_actor_id=$3
		FROM team_billing_account WHERE team_id=$1`, teamID, evidence, actor).Scan(&preserved); err != nil || !preserved {
		t.Fatalf("ambiguous retry replaced evidence: %v %v", preserved, err)
	}
}

func TestIntegration_CanonicalStripeOldSubscriptionCannotUseReplacementCheckoutActor(t *testing.T) {
	ctx := context.Background()
	teamID, _, oldActor := seedTeamAndKeyWithRole(t, "team_owner")
	replacementKey := seedKeyForExistingTeamWithRole(t, teamID, "team_owner")
	enableBillingExportForCheckoutActorTest(t, teamID)
	if _, err := testPool.Exec(ctx, `INSERT INTO team_billing_account
		(team_id,stripe_customer_id,stripe_subscription_id,stripe_subscription_status,stripe_subscription_event_at)
		VALUES($1,$2,$3,'incomplete',now()-interval '1 day')`, teamID, "cus_"+teamID.String(), "sub_"+teamID.String()); err != nil {
		t.Fatal(err)
	}
	stripe := &fakeStripeClient{}
	router := newBillingRouter(t, stripe)
	if w := do(router, "POST", "/stripe/checkout-session", replacementKey, checkoutRegressionBody); w.Code != http.StatusOK {
		t.Fatalf("replacement checkout: %d %s", w.Code, w.Body.String())
	}
	var replacementActor uuid.UUID
	if err := testPool.QueryRow(ctx, `SELECT stripe_checkout_actor_id FROM team_billing_account WHERE team_id=$1`, teamID).Scan(&replacementActor); err != nil || replacementActor == oldActor {
		t.Fatalf("replacement actor: %s %v", replacementActor, err)
	}
	if w := sendStripeActivationWebhook(t, router, "evt_old_payment_"+teamID.String(), teamID, oldActor, time.Now().UTC().Truncate(time.Second)); w.Code != http.StatusOK {
		t.Fatalf("older subscription payment completion: %d %s", w.Code, w.Body.String())
	}
	var correctlyAttributed bool
	if err := testPool.QueryRow(ctx, `SELECT a.stripe_activation_user_id=$2 AND a.stripe_checkout_actor_id=$3
		AND a.checkout_initializing_at IS NOT NULL
		AND NOT EXISTS(SELECT 1 FROM user_promotion_entitlement WHERE user_id=$3 AND stripe_redemption_at IS NOT NULL)
		FROM team_billing_account a WHERE a.team_id=$1`, teamID, oldActor, replacementActor).Scan(&correctlyAttributed); err != nil || !correctlyAttributed {
		t.Fatalf("older subscription consumed replacement actor entitlement: %v %v", correctlyAttributed, err)
	}
	if len(stripe.creditGrantCalls) != 1 {
		t.Fatalf("older activation grant calls=%d, want one", len(stripe.creditGrantCalls))
	}
}

func TestIntegration_CanonicalStripeDisabledRecordsUnresolvedConsumption(t *testing.T) {
	ctx := context.Background()
	actor := canonicalStripeActor(t, uuid.NewString()+"@example.com", true)
	teamID := canonicalStripeTeam(t)
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	// Recreate the migration's initial gate state only inside this rolled-back
	// fixture; production activation remains irreversible.
	if _, err := tx.Exec(ctx, `ALTER TABLE promotion_identity_enforcement DISABLE TRIGGER promotion_identity_enforcement_irreversible;
		UPDATE promotion_identity_enforcement SET enabled=false,enabled_at=NULL,readiness_reference=NULL WHERE singleton;
		ALTER TABLE promotion_identity_enforcement ENABLE TRIGGER promotion_identity_enforcement_irreversible;`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM promotion_identity_current WHERE user_id=$1`, actor); err != nil {
		t.Fatal(err)
	}
	var state string
	if err := tx.QueryRow(ctx, `SELECT reserve_stripe_promotion_for_event_state($1,$2,'evt_legacy_no_evidence')`, teamID, actor).Scan(&state); err != nil || state != "acquired" {
		t.Fatalf("disabled gate broke legacy reservation: %s %v", state, err)
	}
	if _, err := tx.Exec(ctx, `SELECT finalize_stripe_promotion($1,$2,'credit_legacy_no_evidence')`, teamID, actor); err != nil {
		t.Fatal(err)
	}
	var fenced bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM promotion_identity_history WHERE user_id=$1 AND team_id=$2
		AND promotion='stripe' AND status='pending' AND grant_state='granted')
		AND EXISTS(SELECT 1 FROM user_promotion_entitlement WHERE user_id=$1 AND stripe_redemption_at IS NOT NULL)`, actor, teamID).Scan(&fenced); err != nil || !fenced {
		t.Fatalf("disabled grant was not quarantined for activation: %v %v", fenced, err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM team_credit_grant WHERE team_id=$1`, teamID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM team WHERE id=$1`, teamID); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM promotion_identity_history WHERE user_id=$1 AND status='pending')`, actor).Scan(&fenced); err != nil || !fenced {
		t.Fatalf("deletion erased transition history: %v %v", fenced, err)
	}
}

func TestIntegration_CanonicalStripeOldSubscriptionCannotBorrowReplacementIdentity(t *testing.T) {
	for _, generation := range []string{"absent", "stale", "invalid", "empty"} {
		t.Run(generation, func(t *testing.T) {
			ctx := context.Background()
			teamID, key, actor := seedTeamAndKeyWithRole(t, "team_owner")
			enableBillingExportForCheckoutActorTest(t, teamID)
			firstEmail, replacementEmail := strings.ReplaceAll(uuid.NewString(), "-", "")+"@gmail.com", strings.ReplaceAll(uuid.NewString(), "-", "")+"@gmail.com"
			if _, err := testPool.Exec(ctx, `SELECT * FROM upsert_profile_with_promotion_identity($1,$2,true,clock_timestamp(),clock_timestamp())`, actor, firstEmail); err != nil {
				t.Fatal(err)
			}
			if _, err := testPool.Exec(ctx, `INSERT INTO team_billing_account
				(team_id,stripe_customer_id,stripe_subscription_id,stripe_subscription_status,stripe_subscription_event_at)
				VALUES($1,$2,$3,'incomplete',now()-interval '1 day')`, teamID, "cus_"+teamID.String(), "sub_"+teamID.String()); err != nil {
				t.Fatal(err)
			}
			if _, err := testPool.Exec(ctx, `SELECT * FROM upsert_profile_with_promotion_identity($1,$2,true,clock_timestamp(),clock_timestamp())`, actor, replacementEmail); err != nil {
				t.Fatal(err)
			}
			stripe := &fakeStripeClient{}
			router := newBillingRouter(t, stripe)
			if w := do(router, "POST", "/stripe/checkout-session", key, checkoutRegressionBody); w.Code != http.StatusOK {
				t.Fatalf("replacement checkout: %d %s", w.Code, w.Body.String())
			}
			account, err := testQueries.GetTeamBillingAccount(ctx, teamID)
			if err != nil {
				t.Fatal(err)
			}
			var capturedVersion uuid.UUID
			if err := testPool.QueryRow(ctx, `SELECT stripe_checkout_identity_evidence_version FROM team_billing_account WHERE team_id=$1`, teamID).Scan(&capturedVersion); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC().Truncate(time.Second)
			metadata := map[string]string{"activation_user_id": actor.String()}
			switch generation {
			case "stale":
				metadata["checkout_generation"] = now.Add(-time.Hour).Format(time.RFC3339Nano)
			case "invalid":
				metadata["checkout_generation"] = "not-a-timestamp"
			case "empty":
				metadata["checkout_generation"] = ""
			}
			payload := stripeSubscriptionWebhookPayloadWithMetadata(t, "evt_old_identity_"+teamID.String(),
				"customer.subscription.updated", "sub_"+teamID.String(), "cus_"+teamID.String(), "active", now, now, now.AddDate(0, 1, 0), metadata)
			deliver := func() {
				t.Helper()
				req := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(payload)))
				req.Header.Set("Stripe-Signature", stripeSignature(t, payload, now))
				if w := doRequest(router, req); w.Code != http.StatusInternalServerError {
					t.Fatalf("unproven original identity must remain retryable: %d %s", w.Code, w.Body.String())
				}
				if len(stripe.creditGrantCalls) != 0 {
					t.Fatalf("old subscription received %d grants using replacement evidence", len(stripe.creditGrantCalls))
				}
			}
			deliver()
			var unchanged bool
			if err := testPool.QueryRow(ctx, `SELECT stripe_checkout_actor_id=$2 AND stripe_checkout_identity_evidence_version=$3
				AND checkout_initializing_at=$4 AND stripe_activation_credit_reserved_at IS NULL
				AND NOT EXISTS(SELECT 1 FROM user_promotion_entitlement WHERE user_id=$2
					AND (stripe_redemption_at IS NOT NULL OR stripe_redemption_reserved_team_id IS NOT NULL))
				AND NOT EXISTS(SELECT 1 FROM promotion_identity WHERE identity_key IN
					(promotion_identity_key($2,$5,true),promotion_identity_key($2,$6,true))
					AND (stripe_redemption_at IS NOT NULL OR stripe_reserved_team_id IS NOT NULL))
				FROM team_billing_account WHERE team_id=$1`, teamID, actor, capturedVersion,
				account.CheckoutInitializingAt, firstEmail, replacementEmail).Scan(&unchanged); err != nil || !unchanged {
				t.Fatalf("blocked old event changed the newer generation or entitlement: %v %v", unchanged, err)
			}
			if generation != "absent" {
				if err := testQueries.AbortTeamBillingCheckout(ctx, db.AbortTeamBillingCheckoutParams{
					TeamID: teamID, LeaseStartedAt: account.CheckoutInitializingAt,
				}); err != nil {
					t.Fatal(err)
				}
				deliver()
			}
		})
	}
}

func TestIntegration_CanonicalStripeExpiredCaptureRemainsValidForCheckout(t *testing.T) {
	ctx := context.Background()
	mailbox := "expired" + uuid.New().String()[:8] + "@gmail.com"
	actor := canonicalStripeActor(t, mailbox, true)
	teamID := canonicalStripeTeam(t)
	version := uuid.New()
	// Reconstruct a generation captured while this observation was fresh. Its
	// immutable snapshot must remain usable after the five-minute login TTL.
	if _, err := testPool.Exec(ctx, `INSERT INTO promotion_identity_evidence
		(evidence_version,user_id,email,email_verified,auth_updated_at,observed_at)
		VALUES($1,$2,$3,true,now()-interval '2 hours',now()-interval '2 hours')`, version, actor, mailbox); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE promotion_identity_current SET evidence_version=$2 WHERE user_id=$1`, actor, version); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE team_billing_account SET stripe_checkout_actor_id=$2,
		stripe_checkout_identity_evidence_version=$3,checkout_initializing_at=now()-interval '2 hours'
		WHERE team_id=$1`, teamID, actor, version); err != nil {
		t.Fatal(err)
	}
	_, err := testPool.Exec(ctx, `SELECT capture_promotion_identity_evidence($1)`, actor)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "55000" {
		t.Fatalf("uncaptured stale evidence did not require refresh: %v", err)
	}
	if _, err := testPool.Exec(ctx, `SELECT prepare_stripe_checkout_identity($1,$2)`, teamID, actor); err != nil {
		t.Fatalf("captured generation preflight expired: %v", err)
	}
	if state := canonicalStripeReserve(t, teamID, actor, "evt_unassociated_capture"); state != "blocked" {
		t.Fatalf("unassociated event borrowed captured evidence: %s", state)
	}
	var state string
	if err := testPool.QueryRow(ctx, `SELECT reserve_stripe_promotion_for_subscription_event_state(
		team_id,$2,'evt_expired_capture','sub_expired_capture',checkout_initializing_at,true)
		FROM team_billing_account WHERE team_id=$1`, teamID, actor).Scan(&state); err != nil || state != "acquired" {
		t.Fatalf("captured generation reservation expired: %s %v", state, err)
	}
	if _, err := testPool.Exec(ctx, `SELECT finalize_stripe_promotion($1,$2,'credit_expired_capture')`, teamID, actor); err != nil {
		t.Fatal(err)
	}
}

func TestIntegration_CanonicalStripeVerifiedCheckoutAssociationWinsOverGeneration(t *testing.T) {
	ctx := context.Background()
	for _, matchingSubscription := range []bool{true, false} {
		t.Run(fmt.Sprintf("matching_subscription_%t", matchingSubscription), func(t *testing.T) {
			actor := canonicalStripeActor(t, strings.ReplaceAll(uuid.NewString(), "-", "")+"@gmail.com", true)
			teamID := canonicalStripeTeam(t)
			if _, err := testPool.Exec(ctx, `UPDATE team_billing_account SET stripe_checkout_actor_id=$2,
				stripe_checkout_identity_evidence_version=capture_promotion_identity_evidence($2),
				checkout_initializing_at=now(),checkout_subscription_id='sub_verified' WHERE team_id=$1`, teamID, actor); err != nil {
				t.Fatal(err)
			}
			// A verified subscription association is stronger than generation metadata.
			// Conversely, even matching generation metadata cannot override a different ID.
			subscriptionID, want := "sub_unrelated", "blocked"
			if matchingSubscription {
				subscriptionID, want = "sub_verified", "acquired"
			}
			var state string
			if err := testPool.QueryRow(ctx, `SELECT reserve_stripe_promotion_for_subscription_event_state(
				team_id,$2,'evt_verified_checkout',$3,CASE WHEN $4 THEN NULL ELSE checkout_initializing_at END,true)
				FROM team_billing_account WHERE team_id=$1`, teamID, actor, subscriptionID, matchingSubscription).Scan(&state); err != nil || state != want {
				t.Fatalf("verified association: state=%s want=%s err=%v", state, want, err)
			}
			if matchingSubscription {
				if _, err := testPool.Exec(ctx, `SELECT release_stripe_promotion_for_event($1,$2,'evt_verified_checkout')`, teamID, actor); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestIntegration_CanonicalStripeReservationRechecksCheckoutGeneration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	email := strings.ReplaceAll(uuid.NewString(), "-", "") + "@gmail.com"
	actor := canonicalStripeActor(t, email, true)
	teamID := canonicalStripeTeam(t)
	lease := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := testPool.Exec(ctx, `UPDATE team_billing_account SET stripe_checkout_actor_id=$2,
		stripe_checkout_identity_evidence_version=capture_promotion_identity_evidence($2),checkout_initializing_at=$3
		WHERE team_id=$1`, teamID, actor, lease); err != nil {
		t.Fatal(err)
	}
	blocker, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(context.Background())
	if _, err := blocker.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('promotion-identity:'||promotion_identity_key($1,$2,true))::bigint)`, actor, email); err != nil {
		t.Fatal(err)
	}
	conn, err := testPool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pid := conn.Conn().PgConn().PID()
	type result struct {
		state string
		err   error
	}
	done := make(chan result, 1)
	go func() {
		defer conn.Release()
		var got result
		got.err = conn.QueryRow(ctx, `SELECT reserve_stripe_promotion_for_subscription_event_state(
			$1,$2,'evt_generation_race','sub_generation_race',$3,true)`, teamID, actor, lease).Scan(&got.state)
		done <- got
	}()
	for {
		var waiting bool
		if err := testPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND NOT granted)`, pid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case got := <-done:
			t.Fatalf("reservation did not wait for the canonical lock: %s %v", got.state, got.err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(5 * time.Millisecond):
		}
	}
	// The same immutable evidence can legitimately belong to another generation.
	if _, err := testPool.Exec(ctx, `UPDATE team_billing_account SET checkout_initializing_at=$2 WHERE team_id=$1`, teamID, lease.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := blocker.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	got := <-done
	if got.err != nil || got.state != "blocked" {
		t.Fatalf("changed generation reused selected evidence: %s %v", got.state, got.err)
	}
}

func TestIntegration_CanonicalStripeDisabledUnknownGenerationRecordsPendingHistory(t *testing.T) {
	ctx := context.Background()
	email := strings.ReplaceAll(uuid.NewString(), "-", "") + "@gmail.com"
	actor := canonicalStripeActor(t, email, true)
	teamID := canonicalStripeTeam(t)
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `ALTER TABLE promotion_identity_enforcement DISABLE TRIGGER promotion_identity_enforcement_irreversible;
		UPDATE promotion_identity_enforcement SET enabled=false,enabled_at=NULL,readiness_reference=NULL WHERE singleton;
		ALTER TABLE promotion_identity_enforcement ENABLE TRIGGER promotion_identity_enforcement_irreversible;`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE team_billing_account SET stripe_checkout_actor_id=$2,
		stripe_checkout_identity_evidence_version=capture_promotion_identity_evidence($2),checkout_initializing_at=now()
		WHERE team_id=$1`, teamID, actor); err != nil {
		t.Fatal(err)
	}
	var state string
	if err := tx.QueryRow(ctx, `SELECT reserve_stripe_promotion_for_subscription_event_state(
		$1,$2,'evt_unknown_legacy_generation','sub_old',NULL,true)`, teamID, actor).Scan(&state); err != nil || state != "acquired" {
		t.Fatalf("disabled gate did not preserve legacy eligibility: %s %v", state, err)
	}
	if _, err := tx.Exec(ctx, `SELECT finalize_stripe_promotion($1,$2,'credit_unknown_legacy_generation')`, teamID, actor); err != nil {
		t.Fatal(err)
	}
	var quarantined bool
	if err := tx.QueryRow(ctx, `SELECT a.stripe_activation_identity_evidence_version IS NULL
		AND EXISTS(SELECT 1 FROM promotion_identity_history WHERE user_id=$2 AND team_id=$1
			AND promotion='stripe' AND status='pending' AND grant_state='granted' AND evidence_version IS NULL)
		AND NOT EXISTS(SELECT 1 FROM promotion_identity WHERE identity_key=promotion_identity_key($2,$3,true) AND stripe_redemption_at IS NOT NULL)
		FROM team_billing_account a WHERE a.team_id=$1`, teamID, actor, email).Scan(&quarantined); err != nil || !quarantined {
		t.Fatalf("unknown legacy generation borrowed replacement evidence: %v %v", quarantined, err)
	}
}

func TestIntegration_CanonicalStripeDisabledCapturesBothLegacyAliasGrants(t *testing.T) {
	ctx := context.Background()
	mailbox := "transition" + uuid.New().String()[:8]
	users := []uuid.UUID{canonicalStripeActor(t, mailbox+"@gmail.com", true), canonicalStripeActor(t, mailbox+"+alias@googlemail.com", true)}
	teams := []uuid.UUID{canonicalStripeTeam(t), canonicalStripeTeam(t)}
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `ALTER TABLE promotion_identity_enforcement DISABLE TRIGGER promotion_identity_enforcement_irreversible;
		UPDATE promotion_identity_enforcement SET enabled=false,enabled_at=NULL,readiness_reference=NULL WHERE singleton;
		ALTER TABLE promotion_identity_enforcement ENABLE TRIGGER promotion_identity_enforcement_irreversible;`); err != nil {
		t.Fatal(err)
	}
	for i := range users {
		var state string
		if err := tx.QueryRow(ctx, `SELECT reserve_stripe_promotion_for_event_state($1,$2,$3)`, teams[i], users[i], "evt_transition_"+teams[i].String()).Scan(&state); err != nil || state != "acquired" {
			t.Fatalf("disabled gate changed user-only eligibility: %s %v", state, err)
		}
	}
	for i := range users {
		if _, err := tx.Exec(ctx, `SELECT finalize_stripe_promotion($1,$2,$3)`, teams[i], users[i], "credit_transition_"+teams[i].String()); err != nil {
			t.Fatal(err)
		}
	}
	var captured int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM promotion_identity_history WHERE user_id=ANY($1::uuid[])
		AND promotion='stripe' AND status='reconciled' AND grant_state='granted' AND evidence_version IS NOT NULL`, users).Scan(&captured); err != nil || captured != 2 {
		t.Fatalf("legacy grants did not retain their captured authority: count=%d err=%v", captured, err)
	}
	var consumed bool
	if err := tx.QueryRow(ctx, `SELECT stripe_redemption_at IS NOT NULL FROM promotion_identity
		WHERE identity_key=promotion_identity_key($1,$2,true)`, users[0], mailbox+"@gmail.com").Scan(&consumed); err != nil || !consumed {
		t.Fatalf("transition did not consume canonical mailbox: %v %v", consumed, err)
	}
}

func TestIntegration_CanonicalStripeHistoricalReleasedAttemptDoesNotConsume(t *testing.T) {
	ctx := context.Background()
	email := "released" + uuid.NewString()[:8] + "@gmail.com"
	userID := canonicalStripeActor(t, email, true)
	teamID := canonicalStripeTeam(t)
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	rolloutExec(t, tx, `INSERT INTO user_promotion_entitlement(user_id,stripe_redemption_reserved_team_id,stripe_redemption_reserved_at,stripe_redemption_attempted_at)
		VALUES($1,$2,now(),now())`, userID, teamID)
	rolloutExec(t, tx, `UPDATE team_billing_account SET stripe_activation_user_id=$2,stripe_activation_credit_reserved_at=now(),
		stripe_activation_credit_reservation_event_id='evt_old_failure' WHERE team_id=$1`, teamID, userID)
	migration, err := os.ReadFile("../../supabase/migrations/20260924191922_canonical_stripe_promotion_fences.sql")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(migration), "-- Existing external attempts")
	end := strings.Index(string(migration), "CREATE OR REPLACE FUNCTION lock_stripe_promotion")
	if start < 0 || end <= start {
		t.Fatal("historical reservation migration segment missing")
	}
	rolloutExec(t, tx, string(migration[start:end]))
	// Other tests' live reservations are not historical evidence for this case.
	rolloutExec(t, tx, `DELETE FROM promotion_identity_history WHERE history_key <> 'stripe-user:'||$1::text`, userID)
	rolloutExec(t, tx, `SAVEPOINT still_pending`)
	_, err = tx.Exec(ctx, `SELECT reconcile_promotion_identity_history('stripe-user:'||$1::text,
		ARRAY[promotion_identity_key($1::uuid,$2,true)],'definitive failure evidence','released')`, userID, email)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "55000" {
		t.Fatalf("pending grant was reconciled prematurely: %v", err)
	}
	rolloutExec(t, tx, `ROLLBACK TO SAVEPOINT still_pending`)
	// Only the definite-failure recovery path may release an attempted fence.
	rolloutExec(t, tx, `SELECT release_stripe_promotion($1,$2)`, teamID, userID)
	rolloutExec(t, tx, `SELECT reconcile_promotion_identity_history('stripe-user:'||$1::text,
		ARRAY[promotion_identity_key($1::uuid,$2,true)],'verified definitive Stripe failure','released')`, userID, email)
	var eligible bool
	if err := tx.QueryRow(ctx, `SELECT stripe_promotion_eligible($1,$2)`, teamID, userID).Scan(&eligible); err != nil || !eligible {
		t.Fatalf("definitively ungranted attempt consumed entitlement: %t %v", eligible, err)
	}
}
