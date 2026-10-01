//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superserve-ai/sandbox/internal/db"
)

const publicationCheckoutPath = "/stripe/checkout-session/publication-decision"

type publicationCheckoutFixture struct {
	checkoutRecoveryFixture
	sign   func(string, uuid.UUID, map[string]any) string
	intent uuid.UUID
}

func newPublicationCheckoutFixture(t *testing.T) publicationCheckoutFixture {
	t.Helper()
	t.Setenv("SANDBOX_ID_REGION", "use")
	sign := promotionAssertionSigner(t)
	team, key, actor := seedTeamAndKeyWithRole(t, "team_owner")
	enableBillingExportForCheckoutActorTest(t, team)
	stripe := &recoveryCheckoutStripeClient{idempotentCheckoutStripeClient: &idempotentCheckoutStripeClient{
		fakeStripeClient: &fakeStripeClient{nextCustomerID: "cus_publication_" + team.String()},
	}}
	return publicationCheckoutFixture{checkoutRecoveryFixture{team: team, actor: actor, key: key,
		router: newBillingRouter(t, stripe), stripe: stripe}, sign, uuid.New()}
}

func (f publicationCheckoutFixture) body(decision string) map[string]any {
	return map[string]any{"operation_id": f.intent.String(), "home_region": "use", "decision": decision,
		"success_url": "https://app.superserve.test/billing/success", "cancel_url": "https://app.superserve.test/billing/cancel"}
}

func (f publicationCheckoutFixture) request(t *testing.T, body map[string]any, actor uuid.UUID, key string, mutate func(map[string]any)) *httptest.ResponseRecorder {
	t.Helper()
	claims := map[string]any{"team_id": f.team.String()}
	for k, v := range body {
		claims[k] = v
	}
	if mutate != nil {
		mutate(claims)
	}
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, publicationCheckoutPath, strings.NewReader(string(payload)))
	req.Header.Set("X-API-Key", key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Promotion-Account-Assertion", f.sign("checkout", actor, claims))
	return doRequest(f.router, req)
}

func TestIntegration_BillingCheckoutPublicationFailureRecovery(t *testing.T) {
	f := newPublicationCheckoutFixture(t)
	ctx := context.Background()
	// A previously accepted device must not override this generation's failure.
	rolloutExec(t, testPool, `SELECT register_promotion_signup_device($1,$2,$3,$4)`,
		f.actor, uuid.New(), "event-"+uuid.NewString(), "visitor-"+uuid.NewString())
	f.stripe.failures = map[int]error{1: context.DeadlineExceeded}
	f.stripe.afterCall = func(ctx context.Context, _ int) error {
		var committed bool
		err := testPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM stripe_checkout_publication_decision d
            JOIN team_billing_account a ON a.team_id=d.team_id AND a.checkout_initializing_at=d.checkout_generation
            WHERE d.team_id=$1 AND d.user_id=$2 AND d.operation_id=$3 AND d.decision='publication_failed'
              AND a.stripe_checkout_identity_evidence_version IS NULL)`, f.team, f.actor, f.intent).Scan(&committed)
		if err != nil || !committed {
			t.Fatalf("Stripe called before durable no-credit generation: %t %v", committed, err)
		}
		return nil
	}
	if w := f.request(t, f.body("publication_failed"), f.actor, f.key, nil); w.Code != http.StatusBadGateway {
		t.Fatalf("lost Stripe response: %d %s", w.Code, w.Body.String())
	}
	original, err := testQueries.GetTeamBillingCheckoutForRecovery(ctx, f.team)
	if err != nil {
		t.Fatal(err)
	}
	if w := f.request(t, f.body("standard"), f.actor, f.key, nil); w.Code != http.StatusConflict {
		t.Fatalf("changed decision: %d %s", w.Code, w.Body.String())
	}
	different := f.body("publication_failed")
	different["operation_id"] = uuid.NewString()
	if w := f.request(t, different, f.actor, f.key, nil); w.Code != http.StatusConflict {
		t.Fatalf("different intent replaced live lease: %d %s", w.Code, w.Body.String())
	}
	for _, field := range []string{"team_id", "home_region", "success_url", "cancel_url", "operation_id", "decision"} {
		w := f.request(t, f.body("publication_failed"), f.actor, f.key, func(claims map[string]any) { claims[field] = "changed" })
		if w.Code != http.StatusForbidden {
			t.Fatalf("unsigned %s mutation: %d %s", field, w.Code, w.Body.String())
		}
	}
	if w := f.request(t, f.body("publication_failed"), uuid.New(), f.key, nil); w.Code != http.StatusForbidden {
		t.Fatalf("actor spoof: %d %s", w.Code, w.Body.String())
	}
	// Reconstruct handlers over independent connections, renew the assertion,
	// and recover the response without a process-local intent store.
	pool, err := pgxpool.New(ctx, testPool.Config().ConnString())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	f.router = newBillingRouterWithPool(t, f.stripe, pool)
	if w := f.request(t, f.body("publication_failed"), f.actor, f.key, nil); w.Code != http.StatusOK {
		t.Fatalf("restart retry: %d %s", w.Code, w.Body.String())
	}
	after, err := testQueries.GetTeamBillingCheckoutForRecovery(ctx, f.team)
	if err != nil || after.CheckoutInitializingAt != original.CheckoutInitializingAt || after.StripeCheckoutActorID != original.StripeCheckoutActorID {
		t.Fatalf("generation/actor changed: %+v %v", after, err)
	}
	f.stripe.assertCalls(t, 2)
	f.assertRecovered(t, `{}`)
	if w := do(f.router, "POST", "/stripe/checkout-session", f.key, checkoutRegressionBody); w.Code == http.StatusOK {
		t.Fatal("legacy route resumed a trusted generation")
	}
	f.stripe.assertCalls(t, 2)
}

func TestIntegration_BillingCheckoutPublicationFailurePaidActivation(t *testing.T) {
	f := newPublicationCheckoutFixture(t)
	ctx := context.Background()
	rolloutExec(t, testPool, `SELECT register_promotion_signup_device($1,$2,$3,$4)`,
		f.actor, uuid.New(), "event-"+uuid.NewString(), "visitor-"+uuid.NewString())
	if w := f.request(t, f.body("publication_failed"), f.actor, f.key, nil); w.Code != http.StatusOK {
		t.Fatalf("checkout: %d %s", w.Code, w.Body.String())
	}
	account, err := testQueries.GetTeamBillingCheckoutForRecovery(ctx, f.team)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	subscription := "sub_" + f.team.String()
	metadata := map[string]string{"activation_user_id": f.actor.String(), "checkout_generation": account.CheckoutInitializingAt.Time.UTC().Format(time.RFC3339Nano)}
	send := func(payload []byte) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/stripe/webhook", strings.NewReader(string(payload)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Stripe-Signature", stripeSignature(t, payload, time.Now()))
		if w := doRequest(f.router, req); w.Code != http.StatusOK {
			t.Fatalf("webhook: %d %s", w.Code, w.Body.String())
		}
	}
	send(stripeInvoiceWebhookPayload(t, "evt_invoice_"+f.team.String(), "invoice.finalized",
		*account.StripeCustomerID, "sub_older_"+f.team.String(), "open", now))
	var invoiceBound bool
	if err := testPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM stripe_checkout_publication_subscription
		WHERE team_id=$1 AND subscription_id=$2)`, f.team, "sub_older_"+f.team.String()).Scan(&invoiceBound); err != nil || invoiceBound {
		t.Fatalf("invoice inferred generation ownership: %t %v", invoiceBound, err)
	}
	// A delayed invoice can project a previously unseen older subscription.
	// Neither it nor its replay proves ownership of the open generation.
	invoiceSubscription := "sub_older_" + f.team.String()
	activeWithoutGeneration := stripeSubscriptionWebhookPayloadWithMetadata(t, "evt_invoice_active_"+f.team.String(), "customer.subscription.updated", invoiceSubscription,
		*account.StripeCustomerID, "active", now, now, now.AddDate(0, 1, 0), map[string]string{"activation_user_id": f.actor.String()})
	send(activeWithoutGeneration)
	send(activeWithoutGeneration)
	if err := testPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM stripe_checkout_publication_subscription
		WHERE team_id=$1)`, f.team).Scan(&invoiceBound); err != nil || invoiceBound {
		t.Fatalf("ambiguous activation inferred generation ownership: %t %v", invoiceBound, err)
	}
	ambiguous, err := testQueries.GetTeamBillingCheckoutForRecovery(ctx, f.team)
	if err != nil || !ambiguous.TrialEndedAt.Valid || ambiguous.StripeActivationCreditReservedAt.Valid || ambiguous.StripeActivationCreditGrantedAt.Valid {
		t.Fatalf("ambiguous subscription did not retain paid-only access: %+v %v", ambiguous, err)
	}
	// An update can precede both creation and Checkout completion callbacks.
	active := stripeSubscriptionWebhookPayloadWithMetadata(t, "evt_paid_"+f.team.String(), "customer.subscription.updated", subscription,
		*account.StripeCustomerID, "active", now, now, now.AddDate(0, 1, 0), metadata)
	send(active)
	completion, err := json.Marshal(map[string]any{"id": "evt_complete_" + f.team.String(), "type": "checkout.session.completed", "created": now.Unix(),
		"data": map[string]any{"object": map[string]any{"id": *account.CheckoutSessionID, "customer": *account.StripeCustomerID,
			"subscription": subscription, "client_reference_id": f.team.String(), "metadata": metadata}}})
	if err != nil {
		t.Fatal(err)
	}
	send(completion)
	send(active)
	var associations int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM stripe_checkout_publication_subscription
		WHERE team_id=$1`, f.team).Scan(&associations); err != nil || associations != 1 {
		t.Fatalf("only verified subscription should be retained: %d %v", associations, err)
	}
	// Fresh evidence and a later event without generation metadata cannot upgrade
	// the retained subscription decision after the mutable lease is cleared.
	rolloutExec(t, testPool, `SELECT * FROM upsert_profile_with_promotion_identity($1,$2,true,clock_timestamp(),clock_timestamp())`, f.actor, f.actor.String()+"@example.com")
	send(stripeSubscriptionWebhookPayloadWithMetadata(t, "evt_later_"+f.team.String(), "customer.subscription.updated", subscription,
		*account.StripeCustomerID, "active", now.Add(time.Second), now, now.AddDate(0, 1, 0), map[string]string{"activation_user_id": f.actor.String()}))
	send(stripeSubscriptionWebhookPayloadWithMetadata(t, "evt_older_"+f.team.String(), "customer.subscription.created", subscription,
		*account.StripeCustomerID, "active", now.Add(-time.Second), now, now.AddDate(0, 1, 0), metadata))
	after, err := testQueries.GetTeamBillingCheckoutForRecovery(ctx, f.team)
	if err != nil || !after.TrialEndedAt.Valid || after.StripeActivationCreditReservedAt.Valid || after.StripeActivationCreditGrantedAt.Valid || after.CheckoutInitializingAt.Valid {
		t.Fatalf("paid-only activation did not finish safely: %+v %v", after, err)
	}
	if len(f.stripe.creditGrantCalls) != 0 {
		t.Fatal("publication failure created a Stripe credit grant")
	}
	var count int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM stripe_promotion_outcome WHERE team_id=$1 AND reason='authority_unavailable'`, f.team).Scan(&count); err != nil || count < 2 {
		t.Fatalf("durable denials: %d %v", count, err)
	}
	var preserved bool
	if err := testPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM promotion_signup_device_evidence WHERE user_id=$1)
        AND NOT EXISTS(SELECT 1 FROM promotion_device_grant WHERE user_id=$1 AND promotion='stripe')
        AND NOT EXISTS(SELECT 1 FROM user_promotion_entitlement WHERE user_id=$1 AND stripe_redemption_at IS NOT NULL)`, f.actor).Scan(&preserved); err != nil || !preserved {
		t.Fatalf("original evidence or consumption changed: %t %v", preserved, err)
	}
}

func TestIntegration_BillingCheckoutPublicationRequiresSubscriptionProof(t *testing.T) {
	f := newPublicationCheckoutFixture(t)
	ctx := context.Background()
	if w := f.request(t, f.body("standard"), f.actor, f.key, nil); w.Code != http.StatusOK {
		t.Fatalf("checkout: %d %s", w.Code, w.Body.String())
	}
	tx := localIdentityTransaction(t, false)
	queries := testQueries.WithTx(tx)
	reserve := func(subscription, event string) string {
		t.Helper()
		var state string
		if err := tx.QueryRow(ctx, `SELECT reserve_stripe_promotion_for_subscription_event_state($1,$2,$3,$4,NULL,false)`,
			f.team, f.actor, event, subscription).Scan(&state); err != nil {
			t.Fatal(err)
		}
		return state
	}
	for _, subscription := range []string{"sub_delayed_first", "sub_delayed_second"} {
		// Invoice projection and repeated reservation attempts cannot turn
		// customer ownership into immutable generation authority.
		rolloutExec(t, tx, `UPDATE team_billing_account SET stripe_subscription_id=$2 WHERE team_id=$1`, f.team, subscription)
		for i := 0; i < 2; i++ {
			if state := reserve(subscription, "evt_"+subscription); state != "authority_unavailable" {
				t.Fatalf("unproven subscription reservation: %s", state)
			}
		}
	}
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM stripe_checkout_publication_subscription WHERE team_id=$1`, f.team).Scan(&count); err != nil || count != 0 {
		t.Fatalf("projection created immutable associations: %d %v", count, err)
	}
	// The trusted completion path supplies the association before replay.
	subscription := "sub_verified_" + f.team.String()
	if err := queries.AssociateTeamBillingCheckoutSubscription(ctx, db.AssociateTeamBillingCheckoutSubscriptionParams{
		TeamID: f.team, SubscriptionID: &subscription,
	}); err != nil {
		t.Fatal(err)
	}
	event := "evt_verified_" + f.team.String()
	if state := reserve(subscription, event); state != "acquired" {
		t.Fatalf("verified standard generation lost eligibility: %s", state)
	}
	if _, err := queries.MarkStripePromotionAttempt(ctx, db.MarkStripePromotionAttemptParams{
		TeamID: pgtype.UUID{Bytes: f.team, Valid: true}, UserID: f.actor, EventID: &event,
	}); err != nil {
		t.Fatal(err)
	}
	if state := reserve("sub_delayed_first", "evt_delayed_again"); state != "blocked" {
		t.Fatalf("ambiguous event bypassed existing obligation: %s", state)
	}
	if state := reserve(subscription, event); state != "existing" {
		t.Fatalf("verified obligation cannot replay: %s", state)
	}
}

func TestIntegration_BillingCheckoutPublicationConcurrentAndClosedIntents(t *testing.T) {
	f := newPublicationCheckoutFixture(t)
	var wg sync.WaitGroup
	responses := make(chan *httptest.ResponseRecorder, 2)
	body := f.body("publication_failed")
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); responses <- f.request(t, body, f.actor, f.key, nil) }()
	}
	wg.Wait()
	close(responses)
	for w := range responses {
		if w.Code != http.StatusOK {
			t.Fatalf("concurrent retry: %d %s", w.Code, w.Body.String())
		}
	}
	f.stripe.assertCalls(t, 2)
	ctx := context.Background()
	account, err := testQueries.GetTeamBillingCheckoutForRecovery(ctx, f.team)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate the existing proven-expiration cleanup, retaining the decision.
	if err := testQueries.AbortTeamBillingCheckout(ctx, db.AbortTeamBillingCheckoutParams{TeamID: f.team, LeaseStartedAt: account.CheckoutInitializingAt}); err != nil {
		t.Fatal(err)
	}
	if w := f.request(t, body, f.actor, f.key, nil); w.Code != http.StatusConflict {
		t.Fatalf("closed intent allocated another generation: %d %s", w.Code, w.Body.String())
	}
	f.intent = uuid.New()
	if w := f.request(t, f.body("standard"), f.actor, f.key, nil); w.Code != http.StatusOK {
		t.Fatalf("fresh intent after closure: %d %s", w.Code, w.Body.String())
	}
	f.stripe.assertCounts(t, 3, 2)
	var decisions string
	if err := testPool.QueryRow(ctx, `SELECT string_agg(decision,',' ORDER BY checkout_generation) FROM stripe_checkout_publication_decision WHERE team_id=$1`, f.team).Scan(&decisions); err != nil || decisions != "publication_failed,standard" {
		t.Fatalf("generation history rewritten: %s %v", decisions, err)
	}
}

func TestIntegration_BillingCheckoutPublicationPreservesLegacyReservation(t *testing.T) {
	f := newPublicationCheckoutFixture(t)
	if w := do(f.router, "POST", "/stripe/checkout-session", f.key, checkoutRegressionBody); w.Code != http.StatusOK {
		t.Fatalf("legacy checkout: %d %s", w.Code, w.Body.String())
	}
	before := f.snapshot(t)
	if w := f.request(t, f.body("publication_failed"), f.actor, f.key, nil); w.Code != http.StatusConflict {
		t.Fatalf("legacy generation overwritten: %d %s", w.Code, w.Body.String())
	}
	if after := f.snapshot(t); after != before {
		t.Fatal("trusted request mutated legacy generation")
	}
	account, err := testQueries.GetTeamBillingCheckoutForRecovery(context.Background(), f.team)
	if err != nil {
		t.Fatal(err)
	}
	event := "evt_reservation_" + uuid.NewString()
	var state string
	if err := testPool.QueryRow(context.Background(), `SELECT reserve_stripe_promotion_for_subscription_event_state($1,$2,$3,$4,$5,true)`, f.team, f.actor, event, "sub_"+f.team.String(), account.CheckoutInitializingAt.Time).Scan(&state); err != nil || state != "acquired" {
		t.Fatalf("legacy reserve: %s %v", state, err)
	}
	if _, err := testQueries.MarkStripePromotionAttempt(context.Background(), db.MarkStripePromotionAttemptParams{
		TeamID: pgtype.UUID{Bytes: f.team, Valid: true}, UserID: f.actor, EventID: &event,
	}); err != nil {
		t.Fatal(err)
	}
	before = f.snapshot(t)
	if w := f.request(t, f.body("publication_failed"), f.actor, f.key, nil); w.Code != http.StatusConflict {
		t.Fatalf("reservation overwritten: %d %s", w.Code, w.Body.String())
	}
	if after := f.snapshot(t); after != before {
		t.Fatal("trusted request changed an existing reservation")
	}
	if state = canonicalStripeReserve(t, f.team, f.actor, event); state != "existing" {
		t.Fatalf("original reservation cannot recover: %s", state)
	}
}

func TestIntegration_BillingCheckoutPublicationDecisionPrivateAndImmutable(t *testing.T) {
	rolloutExec(t, testPool, `DO $$ DECLARE r text; BEGIN
        FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
            IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=r) THEN
                EXECUTE format('CREATE ROLE %I NOLOGIN',r);
            END IF;
        END LOOP;
    END $$`)
	f := newPublicationCheckoutFixture(t)
	if w := f.request(t, f.body("publication_failed"), f.actor, f.key, nil); w.Code != http.StatusOK {
		t.Fatalf("checkout: %d %s", w.Code, w.Body.String())
	}
	for _, table := range []string{"stripe_checkout_publication_decision", "stripe_checkout_publication_subscription"} {
		for _, role := range []string{"anon", "authenticated", "service_role"} {
			var allowed bool
			if err := testPool.QueryRow(context.Background(), `SELECT has_table_privilege($1,$2,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE')`, role, table).Scan(&allowed); err != nil || allowed {
				t.Fatalf("%s direct access to %s: %t %v", role, table, allowed, err)
			}
		}
	}
	for _, statement := range []string{
		`UPDATE stripe_checkout_publication_decision SET decision='standard' WHERE team_id=$1`,
		`DELETE FROM stripe_checkout_publication_decision WHERE team_id=$1`,
	} {
		if _, err := testPool.Exec(context.Background(), statement, f.team); err == nil {
			t.Fatal(fmt.Sprintf("immutable decision accepted %s", statement))
		}
	}
}

func TestIntegration_BillingCheckoutPublicationWithoutEvidence(t *testing.T) {
	for _, enforced := range []bool{false, true} {
		t.Run(fmt.Sprintf("canonical_%t", enforced), func(t *testing.T) {
			tx := localIdentityTransaction(t, enforced)
			actor, team, intent := uuid.New(), uuid.New(), uuid.New()
			rolloutExec(t, tx, `INSERT INTO profile(id,email) VALUES($1,$2)`, actor, actor.String()+"@example.com")
			rolloutExec(t, tx, `INSERT INTO team(id,name) VALUES($1,$2)`, team, "example-team-"+team.String())
			rolloutExec(t, tx, `INSERT INTO team_billing_account(team_id) VALUES($1)`, team)
			rolloutExec(t, tx, `SELECT begin_stripe_checkout_with_publication_decision($1,$2,$3,'use','request','publication_failed',$4)`, team, actor, intent, uuid.New())
			var generation time.Time
			if err := tx.QueryRow(context.Background(), `SELECT checkout_initializing_at FROM team_billing_account WHERE team_id=$1`, team).Scan(&generation); err != nil {
				t.Fatal(err)
			}
			var state string
			if err := tx.QueryRow(context.Background(), `SELECT reserve_stripe_promotion_for_subscription_event_state($1,$2,'event','subscription',$3,true)`, team, actor, generation).Scan(&state); err != nil || state != "authority_unavailable" {
				t.Fatalf("generation denial: %s %v", state, err)
			}
			if err := tx.QueryRow(context.Background(), `SELECT reserve_stripe_promotion_for_event_state($1,$2,'event')`, team, actor).Scan(&state); err != nil || state != "authority_unavailable" {
				t.Fatalf("legacy reservation denial: %s %v", state, err)
			}
			// Lease cleanup clears the mutable generation and subscription
			// projection, but the immutable publication history must still fence
			// event-only callbacks that carry no generation metadata.
			rolloutExec(t, tx, `UPDATE team_billing_account SET checkout_initializing_at=NULL, checkout_request_key=NULL, checkout_pending_attempt_ids='{}', checkout_may_exist=false, checkout_session_id=NULL, checkout_subscription_id=NULL, checkout_completed_at=NULL, stripe_checkout_actor_id=NULL, stripe_checkout_actor_claimed_at=NULL, stripe_checkout_identity_evidence_version=NULL, updated_at=now() WHERE team_id=$1`, team)
			if err := tx.QueryRow(context.Background(), `SELECT reserve_stripe_promotion_for_event_state($1,$2,'post-cleanup-event')`, team, actor).Scan(&state); err != nil || state != "authority_unavailable" {
				t.Fatalf("post-cleanup event-only callback bypassed history fence: %s %v", state, err)
			}
			rolloutExec(t, tx, `UPDATE team_billing_account SET stripe_subscription_status='active' WHERE team_id=$1`, team)
			rolloutExec(t, tx, `SELECT activate_team_billing($1,$2,'')`, team, actor)
			var paidOnly bool
			if err := tx.QueryRow(context.Background(), `SELECT trial_ended_at IS NOT NULL AND stripe_activation_credit_reserved_at IS NULL
                AND stripe_activation_credit_granted_at IS NULL AND stripe_checkout_identity_evidence_version IS NULL
                FROM team_billing_account WHERE team_id=$1`, team).Scan(&paidOnly); err != nil || !paidOnly {
				t.Fatalf("paid-only state: %t %v", paidOnly, err)
			}
		})
	}
}

func TestIntegration_BillingCheckoutPublicationRejectsExplicitUnmatchedGeneration(t *testing.T) {
	tx := localIdentityTransaction(t, false)
	defer tx.Rollback(context.Background())
	actor, team, intent := uuid.New(), uuid.New(), uuid.New()
	rolloutExec(t, tx, `INSERT INTO profile(id,email) VALUES($1,$2)`, actor, actor.String()+"@example.com")
	rolloutExec(t, tx, `INSERT INTO team(id,name) VALUES($1,$2)`, team, "example-team-"+team.String())
	rolloutExec(t, tx, `INSERT INTO team_billing_account(team_id) VALUES($1)`, team)
	rolloutExec(t, tx, `SELECT begin_stripe_checkout_with_publication_decision($1,$2,$3,'use','request','publication_failed',$4)`, team, actor, intent, uuid.New())
	var generation time.Time
	if err := tx.QueryRow(context.Background(), `SELECT checkout_initializing_at FROM team_billing_account WHERE team_id=$1`, team).Scan(&generation); err != nil {
		t.Fatal(err)
	}
	var state string
	if err := tx.QueryRow(context.Background(), `SELECT reserve_stripe_promotion_for_subscription_event_state($1,$2,'unmatched-generation','subscription',$3,true)`, team, actor, generation.Add(time.Second)).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "authority_unavailable" {
		t.Fatalf("explicit unmatched generation fell through to legacy credit lookup: %s", state)
	}
}

func TestIntegration_BillingCheckoutPublicationCrossActorReservationFence(t *testing.T) {
	ctx := context.Background()
	setup := localIdentityTransaction(t, false)
	actorA, actorB, team := uuid.New(), uuid.New(), uuid.New()
	for _, actor := range []uuid.UUID{actorA, actorB} {
		rolloutExec(t, setup, `INSERT INTO profile(id,email) VALUES($1,$2)`, actor, actor.String()+"@example.com")
	}
	rolloutExec(t, setup, `INSERT INTO team(id,name) VALUES($1,$2)`, team, "cross-actor-"+team.String())
	rolloutExec(t, setup, `INSERT INTO team_billing_account(team_id) VALUES($1)`, team)
	if err := setup.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	// Hold the policy row so actor A pauses after the wrapper's initial history
	// inspection, inside promotion_device_decision. Actor B can still commit a
	// publication decision because it takes the team account lock later.
	blocker, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(ctx)
	var policyLocked bool
	if err := blocker.QueryRow(ctx, `SELECT singleton FROM promotion_device_policy WHERE singleton FOR UPDATE`).Scan(&policyLocked); err != nil || !policyLocked {
		t.Fatalf("policy barrier: %v", err)
	}
	blockerPID := blocker.Conn().PgConn().PID()

	actorConn, err := testPool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer actorConn.Release()
	callCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	type reservationResult struct {
		state string
		err   error
	}
	resultCh := make(chan reservationResult, 1)
	actorPID := actorConn.Conn().PgConn().PID()
	go func() {
		var result reservationResult
		result.err = actorConn.QueryRow(callCtx,
			`SELECT reserve_stripe_promotion_for_event_state($1,$2,$3)`, team, actorA, "event-cross-actor").Scan(&result.state)
		resultCh <- result
	}()

	deadline := time.Now().Add(5 * time.Second)
	for {
		var blocked bool
		if err := testPool.QueryRow(ctx, `SELECT $1::int = ANY(pg_blocking_pids($2::int))`, blockerPID, actorPID).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		select {
		case result := <-resultCh:
			t.Fatalf("actor A did not pause in promotion_device_decision: %q %v", result.state, result.err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("actor A did not reach the policy-row barrier")
		}
		time.Sleep(5 * time.Millisecond)
	}

	writer, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Exec(ctx,
		`SELECT begin_stripe_checkout_with_publication_decision($1,$2,$3,'use','cross-actor-request','publication_failed',$4)`,
		team, actorB, uuid.New(), uuid.New()); err != nil {
		writer.Rollback(ctx)
		t.Fatalf("actor B publication decision: %v", err)
	}
	if err := writer.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var historyCount int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM stripe_checkout_publication_decision WHERE team_id=$1`, team).Scan(&historyCount); err != nil || historyCount != 1 {
		t.Fatalf("actor B decision did not commit: %d %v", historyCount, err)
	}
	if err := blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	result := <-resultCh
	if result.err != nil || result.state != "authority_unavailable" {
		t.Fatalf("actor A acquired credit after actor B publication failure: %q %v", result.state, result.err)
	}
	var noReservation bool
	if err := testPool.QueryRow(ctx, `SELECT
		stripe_activation_credit_reserved_at IS NULL
		AND stripe_activation_user_id IS NULL
		AND stripe_activation_identity_key IS NULL
		AND stripe_activation_identity_evidence_version IS NULL
		AND stripe_activation_credit_reservation_event_id IS NULL
		AND NOT EXISTS (SELECT 1 FROM user_promotion_entitlement WHERE user_id=$2 AND stripe_redemption_reserved_team_id=$1)
		AND NOT EXISTS (SELECT 1 FROM promotion_identity WHERE identity_key='legacy:'||$2::text AND stripe_reserved_team_id=$1)
		FROM team_billing_account WHERE team_id=$1`, team, actorA).Scan(&noReservation); err != nil || !noReservation {
		t.Fatalf("denied callback left reservation state: %t %v", noReservation, err)
	}

	// Lease cleanup plus a mutable prior subscription projection does not create
	// immutable generation ownership. Both metadata-free callback forms remain
	// fenced by the retained publication history.
	rolloutExec(t, testPool, `UPDATE team_billing_account SET
		checkout_initializing_at=NULL, checkout_request_key=NULL, checkout_pending_attempt_ids='{}',
		checkout_may_exist=false, checkout_session_id=NULL, checkout_subscription_id=NULL,
		checkout_completed_at=NULL, stripe_checkout_actor_id=NULL,
		stripe_checkout_actor_claimed_at=NULL, stripe_checkout_identity_evidence_version=NULL,
		stripe_subscription_id='sub_prior_projection', stripe_subscription_status='active', updated_at=now()
		WHERE team_id=$1`, team)
	var state string
	if err := testPool.QueryRow(ctx, `SELECT reserve_stripe_promotion_for_subscription_event_state($1,$2,$3,$4,NULL,false)`,
		team, actorA, "event-prior-subscription", "sub_prior_projection").Scan(&state); err != nil || state != "authority_unavailable" {
		t.Fatalf("prior subscription projection bypassed retained history: %s %v", state, err)
	}
	if err := testPool.QueryRow(ctx, `SELECT reserve_stripe_promotion_for_event_state($1,$2,$3)`, team, actorA, "event-after-cleanup").Scan(&state); err != nil || state != "authority_unavailable" {
		t.Fatalf("event-only callback bypassed retained history: %s %v", state, err)
	}

	// Controls: without retained history, legacy acquisition remains valid;
	// matching replay remains the sole existing-reservation authority, while
	// changed events and actors cannot reuse it.
	legacyTeam, legacyActor, otherActor := uuid.New(), uuid.New(), uuid.New()
	for _, actor := range []uuid.UUID{legacyActor, otherActor} {
		rolloutExec(t, testPool, `INSERT INTO profile(id,email) VALUES($1,$2)`, actor, actor.String()+"@example.com")
	}
	rolloutExec(t, testPool, `INSERT INTO team(id,name) VALUES($1,$2)`, legacyTeam, "legacy-control-"+legacyTeam.String())
	rolloutExec(t, testPool, `INSERT INTO team_billing_account(team_id) VALUES($1)`, legacyTeam)
	if err := testPool.QueryRow(ctx, `SELECT reserve_stripe_promotion_for_event_state($1,$2,$3)`, legacyTeam, legacyActor, "legacy-event").Scan(&state); err != nil || state != "acquired" {
		t.Fatalf("legacy acquisition unexpectedly fenced: %s %v", state, err)
	}
	if err := testPool.QueryRow(ctx, `SELECT reserve_stripe_promotion_for_event_state($1,$2,$3)`, legacyTeam, legacyActor, "legacy-event").Scan(&state); err != nil || state != "existing" {
		t.Fatalf("matching reservation replay changed authority: %s %v", state, err)
	}
	if err := testPool.QueryRow(ctx, `SELECT reserve_stripe_promotion_for_event_state($1,$2,$3)`, legacyTeam, legacyActor, "legacy-other-event").Scan(&state); err != nil || state != "blocked" {
		t.Fatalf("mismatched event replay was accepted: %s %v", state, err)
	}
	if err := testPool.QueryRow(ctx, `SELECT reserve_stripe_promotion_for_event_state($1,$2,$3)`, legacyTeam, otherActor, "legacy-event").Scan(&state); err != nil || state != "blocked" {
		t.Fatalf("mismatched actor replay was accepted: %s %v", state, err)
	}
}
