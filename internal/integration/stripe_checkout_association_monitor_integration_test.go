//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/db"
)

func TestIntegration_StripeAssociationMonitorPreservesSignedPendingCheckout(t *testing.T) {
	ctx := context.Background()
	teamID, _, _ := seedTeamAndKeyWithRole(t, "team_owner")
	customerID := "cus_" + teamID.String()
	subscriptionID := "sub_" + teamID.String()
	eventID := "evt_pending_" + teamID.String()
	createdAt := time.Now().UTC().Truncate(time.Second)
	if _, err := testPool.Exec(ctx, `INSERT INTO team_billing_account
		(team_id, stripe_customer_id, checkout_initializing_at, checkout_session_id)
		VALUES ($1, $2, $3, 'cs_test_123')`, teamID, customerID, createdAt.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	stripe := &fakeStripeClient{}
	router := newBillingRouter(t, stripe)
	deliver := func(payload []byte) int {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/stripe/webhook", strings.NewReader(string(payload)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Stripe-Signature", stripeSignature(t, payload, time.Now().UTC()))
		return doRequest(router, req).Code
	}
	subscription := stripeSubscriptionWebhookPayload(t, eventID, "customer.subscription.created",
		subscriptionID, customerID, "active", createdAt, createdAt, createdAt.AddDate(0, 1, 0))
	if status := deliver(subscription); status != http.StatusInternalServerError {
		t.Fatalf("pending subscription delivery = %d, want 500", status)
	}

	var receivedAt time.Time
	var processedAt *time.Time
	var lastError string
	if err := testPool.QueryRow(ctx, `SELECT received_at, processed_at, last_error
		FROM stripe_webhook_event WHERE event_id = $1`, eventID).Scan(&receivedAt, &processedAt, &lastError); err != nil {
		t.Fatal(err)
	}
	if processedAt != nil || lastError != db.StripeCheckoutAssociationPendingError {
		t.Fatalf("pending receipt: processed=%v error=%q", processedAt, lastError)
	}
	var accountBefore, creditsBefore string
	if err := testPool.QueryRow(ctx, `SELECT to_jsonb(a)::text FROM team_billing_account a WHERE team_id = $1`, teamID).Scan(&accountBefore); err != nil {
		t.Fatal(err)
	}
	if err := testPool.QueryRow(ctx, `SELECT coalesce(jsonb_agg(to_jsonb(g) ORDER BY g.id), '[]'::jsonb)::text
		FROM team_credit_grant g WHERE team_id = $1`, teamID).Scan(&creditsBefore); err != nil {
		t.Fatal(err)
	}
	h := api.NewHandlers(nil, testQueries, nil)
	h.Pool = testPool
	h.Stripe = stripe
	var alerts []api.StripeAssociationAlert
	report := func(a api.StripeAssociationAlert) error {
		alerts = append(alerts, a)
		return nil
	}
	tick := func(at time.Time) {
		t.Helper()
		if _, err := h.StripeCheckoutAssociationTick(ctx, at, db.StripeCheckoutAssociationCursor{}, report); err != nil {
			t.Fatal(err)
		}
	}
	tick(receivedAt.Add(5 * time.Minute))
	tick(receivedAt.Add(6 * time.Minute))
	tick(receivedAt.Add(35 * time.Minute))
	if len(alerts) != 2 || alerts[0].EventID != eventID || alerts[1].EventID != eventID {
		t.Fatalf("overdue and repeated alerts = %+v", alerts)
	}
	var accountAfter, creditsAfter string
	if err := testPool.QueryRow(ctx, `SELECT to_jsonb(a)::text FROM team_billing_account a WHERE team_id = $1`, teamID).Scan(&accountAfter); err != nil {
		t.Fatal(err)
	}
	if err := testPool.QueryRow(ctx, `SELECT coalesce(jsonb_agg(to_jsonb(g) ORDER BY g.id), '[]'::jsonb)::text
		FROM team_credit_grant g WHERE team_id = $1`, teamID).Scan(&creditsAfter); err != nil {
		t.Fatal(err)
	}
	var retainedAt time.Time
	if err := testPool.QueryRow(ctx, `SELECT received_at, processed_at, last_error
		FROM stripe_webhook_event WHERE event_id = $1`, eventID).Scan(&retainedAt, &processedAt, &lastError); err != nil {
		t.Fatal(err)
	}
	if !retainedAt.Equal(receivedAt) || processedAt != nil || lastError != db.StripeCheckoutAssociationPendingError ||
		accountAfter != accountBefore || creditsAfter != creditsBefore {
		t.Fatalf("monitor changed billing state: receipt=%s processed=%v error=%q accountChanged=%v creditsChanged=%v",
			retainedAt, processedAt, lastError, accountAfter != accountBefore, creditsAfter != creditsBefore)
	}
	stripe.mu.Lock()
	monitorCalls := len(stripe.customerCalls) + len(stripe.checkoutCalls) + len(stripe.portalCalls) +
		len(stripe.creditGrantCalls) + len(stripe.reportCalls)
	stripe.mu.Unlock()
	if monitorCalls != 0 {
		t.Fatalf("monitor made %d Stripe calls", monitorCalls)
	}

	checkout := stripeCheckoutWebhookPayload(t, "evt_checkout_"+teamID.String(), teamID.String(), customerID, subscriptionID, createdAt.Add(time.Second))
	if status := deliver(checkout); status != http.StatusOK {
		t.Fatalf("checkout completion = %d, want 200", status)
	}
	if status := deliver(subscription); status != http.StatusOK {
		t.Fatalf("pending event redelivery = %d, want 200", status)
	}
	if err := testPool.QueryRow(ctx, `SELECT received_at, processed_at FROM stripe_webhook_event WHERE event_id = $1`, eventID).Scan(&retainedAt, &processedAt); err != nil {
		t.Fatal(err)
	}
	if !retainedAt.Equal(receivedAt) || processedAt == nil {
		t.Fatalf("recovered receipt: received=%s processed=%v", retainedAt, processedAt)
	}
	account, err := testQueries.GetTeamBillingAccount(ctx, teamID)
	if err != nil {
		t.Fatal(err)
	}
	if derefString(account.StripeSubscriptionID) != subscriptionID || !account.TrialEndedAt.Valid ||
		!account.StripeActivationCreditGrantedAt.Valid || account.StripeActivationCreditGrantID == nil {
		t.Fatalf("checkout did not activate subscription: %+v", account)
	}
	tick(receivedAt.Add(65 * time.Minute))
	if len(alerts) != 2 || len(stripe.creditGrantCalls) != 1 {
		t.Fatalf("recovered checkout: alerts=%d activation grants=%d", len(alerts), len(stripe.creditGrantCalls))
	}
}

func TestIntegration_StripeAssociationMonitorEmissionAndState(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	team, err := testQueries.CreateTeam(ctx, "example-team-"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	customerID := "cus_" + uuid.NewString()
	subscriptionID := "sub_" + uuid.NewString()
	checkoutID := "cs_" + uuid.NewString()
	if _, err := testPool.Exec(ctx, `INSERT INTO team_billing_account
        (team_id, stripe_customer_id, checkout_initializing_at, checkout_session_id)
        VALUES ($1, $2, $3, $4)`, team.ID, customerID, now.Add(-7*time.Minute), checkoutID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), `DELETE FROM team WHERE id = $1`, team.ID)
	})
	h := api.NewHandlers(nil, testQueries, nil)
	h.Pool = testPool

	insert := func(receivedAt time.Time) db.StripeCheckoutAssociationCandidate {
		t.Helper()
		eventID := "evt_" + uuid.NewString()
		eventType := "customer.subscription.created"
		payload, err := json.Marshal(map[string]any{
			"id": eventID, "type": eventType, "created": now.Unix(),
			"data": map[string]any{"object": map[string]any{"id": subscriptionID, "customer": customerID, "status": "active"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := testPool.Exec(ctx, `INSERT INTO stripe_webhook_event(event_id, event_type, payload, received_at, last_error)
            VALUES ($1, $2, $3, $4, $5)`, eventID, eventType, payload, receivedAt, db.StripeCheckoutAssociationPendingError); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = testPool.Exec(context.Background(), `DELETE FROM stripe_webhook_event WHERE event_id = $1`, eventID)
		})
		return db.StripeCheckoutAssociationCandidate{EventID: eventID, EventType: eventType, Payload: payload, ReceivedAt: receivedAt}
	}
	tick := func(at time.Time, report func(api.StripeAssociationAlert) error) {
		t.Helper()
		if _, err := h.StripeCheckoutAssociationTick(ctx, at, db.StripeCheckoutAssociationCursor{}, report); err != nil {
			t.Fatal(err)
		}
	}
	alerts := make([]api.StripeAssociationAlert, 0)
	report := func(a api.StripeAssociationAlert) error {
		alerts = append(alerts, a)
		return nil
	}
	first := insert(now.Add(-5 * time.Minute))
	// A scheduled scan finds a retained event without another webhook delivery.
	tick(now.Add(-time.Microsecond), report)
	if len(alerts) != 0 {
		t.Fatalf("alert before grace: %v", alerts)
	}
	tick(now, report)
	if len(alerts) != 1 || alerts[0].EventID != first.EventID ||
		alerts[0].EventType != first.EventType || alerts[0].TeamID != team.ID.String() ||
		alerts[0].CustomerID != customerID || alerts[0].SubscriptionID != subscriptionID ||
		alerts[0].CheckoutSessionID != checkoutID || alerts[0].Age != 5*time.Minute || !alerts[0].ReceivedAt.Equal(first.ReceivedAt) {
		t.Fatalf("overdue alert context = %+v", alerts)
	}
	tick(now.Add(time.Minute), report)
	if len(alerts) != 1 {
		t.Fatalf("cooldown emitted duplicate alert: %v", alerts)
	}
	tick(now.Add(30*time.Minute), report)
	if len(alerts) != 2 {
		t.Fatalf("new monitor did not repeat after cooldown: %v", alerts)
	}
	var processed bool
	if err := testPool.QueryRow(ctx, `SELECT processed_at IS NOT NULL FROM stripe_webhook_event WHERE event_id = $1`, first.EventID).Scan(&processed); err != nil || processed {
		t.Fatalf("monitor changed processing state: processed=%v err=%v", processed, err)
	}

	// Failed emission releases the claim for a later tick.
	failed := insert(now.Add(-6 * time.Minute))
	if _, err := h.StripeCheckoutAssociationTick(ctx, now, db.StripeCheckoutAssociationCursor{}, func(api.StripeAssociationAlert) error { return errors.New("reporter unavailable") }); err != nil {
		t.Fatal(err)
	}
	var leaseUntil *time.Time
	var nextCheck time.Time
	var lastAlert *time.Time
	if err := testPool.QueryRow(ctx, `SELECT lease_until, next_check_at, last_alert_at
        FROM stripe_checkout_association_alert WHERE event_id = $1`, failed.EventID).Scan(&leaseUntil, &nextCheck, &lastAlert); err != nil {
		t.Fatal(err)
	}
	if leaseUntil != nil || !nextCheck.Equal(now.Add(30*time.Minute)) || lastAlert != nil {
		t.Fatalf("failed report state: lease=%v next=%s last_alert=%v", leaseUntil, nextCheck, lastAlert)
	}
	restarted := api.NewHandlers(nil, testQueries, nil)
	restarted.Pool = testPool
	if _, err := restarted.StripeCheckoutAssociationTick(ctx, now.Add(time.Minute), db.StripeCheckoutAssociationCursor{}, report); err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 2 {
		t.Fatalf("failed report retried during backoff: %v", alerts)
	}
	if _, err := restarted.StripeCheckoutAssociationTick(ctx, now.Add(30*time.Minute), db.StripeCheckoutAssociationCursor{}, report); err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 3 || alerts[2].EventID != failed.EventID {
		t.Fatalf("failed report was not retried: %v", alerts)
	}

	// Current association and processed state override a stale pending error.
	recovered := insert(now.Add(-6 * time.Minute))
	if _, err := testPool.Exec(ctx, `UPDATE team_billing_account SET stripe_subscription_id = $2 WHERE team_id = $1`, team.ID, subscriptionID); err != nil {
		t.Fatal(err)
	}
	tick(now, report)
	if len(alerts) != 3 {
		t.Fatalf("recovered association alerted: %v", alerts)
	}
	if _, err := testPool.Exec(ctx, `UPDATE team_billing_account SET stripe_subscription_id = NULL WHERE team_id = $1`, team.ID); err != nil {
		t.Fatal(err)
	}
	processedEvent := insert(now.Add(-6 * time.Minute))
	if _, err := testPool.Exec(ctx, `UPDATE stripe_webhook_event SET processed_at = $2 WHERE event_id = $1`, processedEvent.EventID, now); err != nil {
		t.Fatal(err)
	}
	tick(now, report)
	if len(alerts) != 3 {
		t.Fatalf("processed event alerted: %v", alerts)
	}
	// A different current subscription proves this event obsolete.
	obsolete := insert(now.Add(-6 * time.Minute))
	if _, err := testPool.Exec(ctx, `UPDATE team_billing_account SET checkout_initializing_at = NULL, stripe_subscription_id = 'sub_other' WHERE team_id = $1`, team.ID); err != nil {
		t.Fatal(err)
	}
	tick(now, report)
	if len(alerts) != 3 {
		t.Fatalf("obsolete event alerted: %v", alerts)
	}
	for _, candidate := range []db.StripeCheckoutAssociationCandidate{first, failed, recovered, obsolete} {
		var lastError *string
		if err := testPool.QueryRow(ctx, `SELECT processed_at IS NOT NULL, last_error FROM stripe_webhook_event WHERE event_id = $1`, candidate.EventID).Scan(&processed, &lastError); err != nil || processed || lastError == nil || *lastError != db.StripeCheckoutAssociationPendingError {
			t.Fatalf("monitor changed retained event %s: processed=%v last_error=%v err=%v", candidate.EventID, processed, lastError, err)
		}
	}
	var grantAt *time.Time
	var grantID *string
	if err := testPool.QueryRow(ctx, `SELECT stripe_activation_credit_granted_at, stripe_activation_credit_grant_id
        FROM team_billing_account WHERE team_id = $1`, team.ID).Scan(&grantAt, &grantID); err != nil || grantAt != nil || grantID != nil {
		t.Fatalf("monitor changed activation credit: granted_at=%v grant_id=%v err=%v", grantAt, grantID, err)
	}
}

func TestIntegration_StripeAssociationMonitorIgnoresPreviousCheckoutAttempt(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	team, err := testQueries.CreateTeam(ctx, "example-team-"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), `DELETE FROM team WHERE id = $1`, team.ID)
	})
	customerID := "cus_" + uuid.NewString()
	oldSessionID := "cs_" + uuid.NewString()
	newSessionID := "cs_" + uuid.NewString()
	if _, err := testPool.Exec(ctx, `INSERT INTO team_billing_account
        (team_id, stripe_customer_id, checkout_initializing_at, checkout_session_id)
        VALUES ($1, $2, $3, $4)`, team.ID, customerID, now.Add(-26*time.Hour), oldSessionID); err != nil {
		t.Fatal(err)
	}
	insertPending := func(subscriptionID string, receivedAt time.Time) db.StripeCheckoutAssociationCandidate {
		t.Helper()
		eventID := "evt_" + uuid.NewString()
		payload, err := json.Marshal(map[string]any{
			"id": eventID, "type": "customer.subscription.created",
			"data": map[string]any{"object": map[string]any{"id": subscriptionID, "customer": customerID}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := testPool.Exec(ctx, `INSERT INTO stripe_webhook_event(event_id, event_type, payload, received_at, last_error)
            VALUES ($1, 'customer.subscription.created', $2, $3, $4)`, eventID, payload, receivedAt, db.StripeCheckoutAssociationPendingError); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = testPool.Exec(context.Background(), `DELETE FROM stripe_webhook_event WHERE event_id = $1`, eventID)
		})
		return db.StripeCheckoutAssociationCandidate{EventID: eventID, EventType: "customer.subscription.created", Payload: payload, ReceivedAt: receivedAt}
	}
	oldEvent := insertPending("sub_"+uuid.NewString(), now.Add(-25*time.Hour))
	// Expiry leaves the old session ID for classification until another checkout starts.
	if _, err := testPool.Exec(ctx, `UPDATE team_billing_account SET checkout_initializing_at = NULL WHERE team_id = $1`, team.ID); err != nil {
		t.Fatal(err)
	}
	h := api.NewHandlers(nil, testQueries, nil)
	h.Pool = testPool
	var alerts []api.StripeAssociationAlert
	report := func(a api.StripeAssociationAlert) error {
		alerts = append(alerts, a)
		return nil
	}
	if err := h.InspectStripeCheckoutAssociation(ctx, now.Add(-24*time.Hour), oldEvent, report); err != nil {
		t.Fatal(err)
	}
	var nextCheck time.Time
	if err := testPool.QueryRow(ctx, `SELECT next_check_at FROM stripe_checkout_association_alert WHERE event_id = $1`, oldEvent.EventID).Scan(&nextCheck); err != nil {
		t.Fatal(err)
	}
	if !nextCheck.Equal(now) || len(alerts) != 0 {
		t.Fatalf("expired checkout suppression: next_check=%s alerts=%v", nextCheck, alerts)
	}
	if _, err := testPool.Exec(ctx, `UPDATE team_billing_account SET checkout_initializing_at = $2, checkout_session_id = $3 WHERE team_id = $1`,
		team.ID, now.Add(-10*time.Minute), newSessionID); err != nil {
		t.Fatal(err)
	}
	newEvent := insertPending("sub_"+uuid.NewString(), now.Add(-6*time.Minute))
	if _, err := h.StripeCheckoutAssociationTick(ctx, now, db.StripeCheckoutAssociationCursor{}, report); err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || alerts[0].EventID != newEvent.EventID || alerts[0].CheckoutSessionID != newSessionID {
		t.Fatalf("alerts after checkout replacement = %+v", alerts)
	}
}

func TestIntegration_StripeAssociationMonitorConcurrentClaims(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	eventID := "evt_" + uuid.NewString()
	payload, err := json.Marshal(map[string]any{
		"id": eventID, "type": "customer.subscription.created",
		"data": map[string]any{"object": map[string]any{"id": "sub_" + uuid.NewString(), "customer": "cus_" + uuid.NewString()}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `INSERT INTO stripe_webhook_event(event_id, event_type, payload, received_at, last_error)
        VALUES ($1, 'customer.subscription.created', $2, $3, $4)`, eventID, payload, now.Add(-6*time.Minute), db.StripeCheckoutAssociationPendingError); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), `DELETE FROM stripe_webhook_event WHERE event_id = $1`, eventID)
	})
	candidate := db.StripeCheckoutAssociationCandidate{EventID: eventID, EventType: "customer.subscription.created", Payload: payload, ReceivedAt: now.Add(-6 * time.Minute)}
	first := api.NewHandlers(nil, testQueries, nil)
	first.Pool = testPool
	second := api.NewHandlers(nil, testQueries, nil)
	second.Pool = testPool
	reportStarted := make(chan api.StripeAssociationAlert, 1)
	releaseReport := make(chan struct{})
	var releaseOnce sync.Once
	firstDone := make(chan error, 1)
	go func() {
		_, err := first.StripeCheckoutAssociationTick(ctx, now, db.StripeCheckoutAssociationCursor{}, func(a api.StripeAssociationAlert) error {
			reportStarted <- a
			<-releaseReport
			return nil
		})
		firstDone <- err
	}()
	defer releaseOnce.Do(func() { close(releaseReport) })
	select {
	case alert := <-reportStarted:
		if alert.EventID != candidate.EventID {
			t.Fatalf("first tick reported %s, want %s", alert.EventID, candidate.EventID)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first tick did not reach reporter")
	}
	var secondAlerts []api.StripeAssociationAlert
	secondCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := second.StripeCheckoutAssociationTick(secondCtx, now, db.StripeCheckoutAssociationCursor{}, func(a api.StripeAssociationAlert) error {
		secondAlerts = append(secondAlerts, a)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(secondAlerts) != 0 {
		t.Fatalf("second tick reported claimed event: %+v", secondAlerts)
	}
	releaseOnce.Do(func() { close(releaseReport) })
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
}

func TestIntegration_StripeAssociationMonitorRecoveryBeforeClaim(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	team, err := testQueries.CreateTeam(ctx, "example-team-"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), `DELETE FROM team WHERE id = $1`, team.ID)
	})
	customerID := "cus_" + uuid.NewString()
	subscriptionID := "sub_" + uuid.NewString()
	eventID := "evt_" + uuid.NewString()
	if _, err := testPool.Exec(ctx, `INSERT INTO team_billing_account
        (team_id, stripe_customer_id, checkout_initializing_at)
        VALUES ($1, $2, $3)`, team.ID, customerID, now.Add(-10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{
		"id": eventID, "type": "customer.subscription.created",
		"data": map[string]any{"object": map[string]any{"id": subscriptionID, "customer": customerID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `INSERT INTO stripe_webhook_event(event_id, event_type, payload, received_at, last_error)
        VALUES ($1, 'customer.subscription.created', $2, $3, $4)`, eventID, payload, now.Add(-6*time.Minute), db.StripeCheckoutAssociationPendingError); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), `DELETE FROM stripe_webhook_event WHERE event_id = $1`, eventID)
	})

	// Hold the account lock while two ticks discover the event. Recovery commits
	// before either worker can revalidate or claim it.
	tx, err := testPool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `UPDATE team_billing_account SET stripe_subscription_id = $2 WHERE team_id = $1`, team.ID, subscriptionID); err != nil {
		t.Fatal(err)
	}
	h := api.NewHandlers(nil, testQueries, nil)
	h.Pool = testPool
	var wg sync.WaitGroup
	results := make(chan error, 2)
	alerts := make(chan api.StripeAssociationAlert, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := h.StripeCheckoutAssociationTick(ctx, now, db.StripeCheckoutAssociationCursor{}, func(a api.StripeAssociationAlert) error { alerts <- a; return nil })
			results <- err
		}()
	}
	deadline := time.Now().Add(5 * time.Second)
	blocked := false
	for time.Now().Before(deadline) {
		var waiting int
		err := testPool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity
            WHERE pid <> pg_backend_pid() AND wait_event_type = 'Lock'
              AND query LIKE '%FROM team_billing_account%WHERE stripe_customer_id%'`).Scan(&waiting)
		if err != nil {
			break
		}
		if waiting >= 2 {
			blocked = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	if !blocked {
		t.Fatal("monitor workers did not reach the account lock before recovery committed")
	}
	if len(alerts) != 0 {
		t.Fatalf("recovered event emitted %d alerts", len(alerts))
	}
}

func TestIntegration_StripeAssociationMonitorRecoveryBeforeFinalRevalidation(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	team, err := testQueries.CreateTeam(ctx, "example-team-"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), `DELETE FROM team WHERE id = $1`, team.ID)
	})
	customerID := "cus_" + uuid.NewString()
	subscriptionID := "sub_" + uuid.NewString()
	eventID := "evt_" + uuid.NewString()
	if _, err := testPool.Exec(ctx, `INSERT INTO team_billing_account
        (team_id, stripe_customer_id, checkout_initializing_at)
        VALUES ($1, $2, $3)`, team.ID, customerID, now.Add(-10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{
		"id": eventID, "type": "customer.subscription.created",
		"data": map[string]any{"object": map[string]any{"id": subscriptionID, "customer": customerID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `INSERT INTO stripe_webhook_event(event_id, event_type, payload, received_at, last_error)
        VALUES ($1, 'customer.subscription.created', $2, $3, $4)`, eventID, payload, now.Add(-6*time.Minute), db.StripeCheckoutAssociationPendingError); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), `DELETE FROM stripe_webhook_event WHERE event_id = $1`, eventID)
	})

	claimed := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	var gated atomic.Bool
	config := testPool.Config()
	config.MaxConns = 1
	config.MinConns = 0
	config.AfterRelease = func(*pgx.Conn) bool {
		var lease time.Time
		if err := testPool.QueryRow(ctx, `SELECT lease_until FROM stripe_checkout_association_alert WHERE event_id = $1`, eventID).Scan(&lease); err == nil && gated.CompareAndSwap(false, true) {
			close(claimed)
			<-release
		}
		return true
	}
	monitorPool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		releaseOnce.Do(func() { close(release) })
		monitorPool.Close()
	}()
	h := api.NewHandlers(nil, testQueries, nil)
	h.Pool = monitorPool
	monitorCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	reported := make(chan api.StripeAssociationAlert, 1)
	go func() {
		_, err := h.StripeCheckoutAssociationTick(monitorCtx, now, db.StripeCheckoutAssociationCursor{}, func(a api.StripeAssociationAlert) error {
			reported <- a
			return nil
		})
		done <- err
	}()
	select {
	case <-claimed:
	case err := <-done:
		t.Fatalf("monitor ended before claim: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("monitor did not commit its claim")
	}
	if _, err := testPool.Exec(ctx, `UPDATE team_billing_account SET stripe_subscription_id = $2 WHERE team_id = $1`, team.ID, subscriptionID); err != nil {
		t.Fatal(err)
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("monitor did not finish after recovery")
	}
	if len(reported) != 0 {
		t.Fatalf("recovered event reported after final revalidation: %+v", <-reported)
	}
	var leaseUntil, lastAlert *time.Time
	if err := testPool.QueryRow(ctx, `SELECT lease_until, last_alert_at FROM stripe_checkout_association_alert WHERE event_id = $1`, eventID).Scan(&leaseUntil, &lastAlert); err != nil || leaseUntil != nil || lastAlert != nil {
		t.Fatalf("recovered claim state: lease=%v last_alert=%v err=%v", leaseUntil, lastAlert, err)
	}
	var processed bool
	var lastError string
	if err := testPool.QueryRow(ctx, `SELECT processed_at IS NOT NULL, last_error FROM stripe_webhook_event WHERE event_id = $1`, eventID).Scan(&processed, &lastError); err != nil || processed || lastError != db.StripeCheckoutAssociationPendingError {
		t.Fatalf("monitor changed retained event: processed=%v last_error=%q err=%v", processed, lastError, err)
	}
	var grantAt *time.Time
	var grantID *string
	if err := testPool.QueryRow(ctx, `SELECT stripe_activation_credit_granted_at, stripe_activation_credit_grant_id
        FROM team_billing_account WHERE team_id = $1`, team.ID).Scan(&grantAt, &grantID); err != nil || grantAt != nil || grantID != nil {
		t.Fatalf("monitor changed activation credit: granted_at=%v grant_id=%v err=%v", grantAt, grantID, err)
	}
}

func TestIntegration_StripeAssociationInspectionFailureBackoff(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	badID := "evt_" + uuid.NewString()
	goodID := "evt_" + uuid.NewString()
	for _, event := range []struct {
		id         string
		payload    string
		receivedAt time.Time
	}{
		{badID, `{"data":{"object":"invalid subscription"}}`, now.Add(-7 * time.Minute)},
		{goodID, `{"data":{"object":{"id":"sub_example","customer":"cus_example"}}}`, now.Add(-6 * time.Minute)},
	} {
		if _, err := testPool.Exec(ctx, `INSERT INTO stripe_webhook_event(event_id, event_type, payload, received_at, last_error)
            VALUES ($1, 'customer.subscription.created', $2, $3, $4)`, event.id, event.payload, event.receivedAt, db.StripeCheckoutAssociationPendingError); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = testPool.Exec(context.Background(), `DELETE FROM stripe_webhook_event WHERE event_id = $1`, event.id)
		})
	}
	h := api.NewHandlers(nil, testQueries, nil)
	h.Pool = testPool
	var reported []string
	report := func(a api.StripeAssociationAlert) error {
		reported = append(reported, a.EventID)
		return nil
	}
	if _, err := h.StripeCheckoutAssociationTick(ctx, now, db.StripeCheckoutAssociationCursor{}, report); err != nil {
		t.Fatal(err)
	}
	if len(reported) != 1 || reported[0] != goodID {
		t.Fatalf("malformed event blocked later candidate: %v", reported)
	}
	var next time.Time
	if err := testPool.QueryRow(ctx, `SELECT next_check_at FROM stripe_checkout_association_alert WHERE event_id = $1`, badID).Scan(&next); err != nil {
		t.Fatal(err)
	}
	if !next.Equal(now.Add(30 * time.Minute)) {
		t.Fatalf("failure retry due at %s", next)
	}
	for _, at := range []time.Time{now.Add(time.Minute), now.Add(29 * time.Minute)} {
		candidates, err := db.ListStripeCheckoutAssociationCandidates(ctx, testPool, at, 5*time.Minute, db.StripeCheckoutAssociationCursor{}, 100)
		if err != nil {
			t.Fatal(err)
		}
		for _, candidate := range candidates {
			if candidate.EventID == badID {
				t.Fatalf("failed event due during backoff at %s", at)
			}
		}
	}
	if claimed, err := db.DeferStripeCheckoutAssociationInspectionFailure(ctx, testPool, badID, now.Add(time.Minute), now.Add(31*time.Minute)); err != nil || claimed {
		t.Fatalf("second replica claimed failure during backoff: claimed=%v err=%v", claimed, err)
	}
	if claimed, err := db.DeferStripeCheckoutAssociationInspectionFailure(ctx, testPool, badID, now.Add(30*time.Minute), now.Add(60*time.Minute)); err != nil || !claimed {
		t.Fatalf("failure did not become due after backoff: claimed=%v err=%v", claimed, err)
	}
}

func TestIntegration_StripeAssociationCursorRevisitsOlderDueEvents(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	h := api.NewHandlers(nil, testQueries, nil)
	h.Pool = testPool
	insert := func(receivedAt time.Time, valid bool) string {
		t.Helper()
		eventID := "evt_" + uuid.NewString()
		payload := `{"data":{"object":"invalid subscription"}}`
		if valid {
			payload = `{"data":{"object":{"id":"sub_example","customer":"cus_example"}}}`
		}
		if _, err := testPool.Exec(ctx, `INSERT INTO stripe_webhook_event(event_id, event_type, payload, received_at, last_error)
            VALUES ($1, 'customer.subscription.created', $2, $3, $4)`, eventID, payload, receivedAt, db.StripeCheckoutAssociationPendingError); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = testPool.Exec(context.Background(), `DELETE FROM stripe_webhook_event WHERE event_id = $1`, eventID)
		})
		return eventID
	}
	failedID := insert(now.Add(-7*time.Minute), false)
	leasedID := insert(now.Add(-6*time.Minute), true)
	tx, err := testPool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := db.ClaimStripeCheckoutAssociationAlert(ctx, tx, leasedID, now, now.Add(2*time.Minute))
	if err != nil || !claimed {
		_ = tx.Rollback(ctx)
		t.Fatalf("claim older event: claimed=%v err=%v", claimed, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	var cursor db.StripeCheckoutAssociationCursor
	var leasedReports int
	report := func(a api.StripeAssociationAlert) error {
		if a.EventID == leasedID {
			leasedReports++
		}
		return nil
	}
	for minute := range 31 {
		at := now.Add(time.Duration(minute) * time.Minute)
		newID := insert(at.Add(-5*time.Minute), true)
		cursor, err = h.StripeCheckoutAssociationTick(ctx, at, cursor, report)
		if err != nil {
			t.Fatal(err)
		}
		if cursor.EventID != newID {
			t.Fatalf("minute %d cursor = %s, want newest event %s", minute, cursor.EventID, newID)
		}
		if minute == 1 && leasedReports != 0 || minute == 2 && leasedReports != 1 {
			t.Fatalf("minute %d older lease reports = %d", minute, leasedReports)
		}
	}
	if leasedReports != 1 {
		t.Fatalf("older lease expiry reported %d times, want once", leasedReports)
	}
	var next time.Time
	if err := testPool.QueryRow(ctx, `SELECT next_check_at FROM stripe_checkout_association_alert WHERE event_id = $1`, failedID).Scan(&next); err != nil {
		t.Fatal(err)
	}
	if !next.Equal(now.Add(60 * time.Minute)) {
		t.Fatalf("older inspection failure was not revisited after cooldown: next_check_at=%s", next)
	}
}

func TestIntegration_StripeAssociationNewReceiptsAdvancePastDueBacklog(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	prefix := "evt_scan_" + uuid.NewString() + "_"
	oldAt := now.Add(-7 * time.Minute)
	newAt := now.Add(-6 * time.Minute)
	if _, err := testPool.Exec(ctx, `
INSERT INTO stripe_webhook_event(event_id, event_type, payload, received_at, last_error)
SELECT $1 || lpad(n::text, 3, '0'), 'customer.subscription.created',
       '{"data":{"object":{"id":"sub_example","customer":"cus_example"}}}'::jsonb,
       $2, $3
FROM generate_series(1, 101) AS n`, prefix, oldAt, db.StripeCheckoutAssociationPendingError); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), `DELETE FROM stripe_webhook_event WHERE event_id LIKE $1`, prefix+"%")
	})
	if _, err := testPool.Exec(ctx, `
INSERT INTO stripe_checkout_association_alert(event_id, next_check_at)
SELECT event_id, CASE WHEN event_id = $1 || '101' THEN $3::timestamptz - interval '31 minutes' ELSE $3 END
FROM stripe_webhook_event WHERE event_id LIKE $2`, prefix, prefix+"%", now); err != nil {
		t.Fatal(err)
	}
	newID := prefix + "new"
	if _, err := testPool.Exec(ctx, `
INSERT INTO stripe_webhook_event(event_id, event_type, payload, received_at, last_error)
VALUES ($1, 'customer.subscription.created',
        '{"data":{"object":{"id":"sub_example","customer":"cus_example"}}}'::jsonb,
        $2, $3)`, newID, newAt, db.StripeCheckoutAssociationPendingError); err != nil {
		t.Fatal(err)
	}
	candidates, err := db.ListStripeCheckoutAssociationCandidates(ctx, testPool, now, 5*time.Minute,
		db.StripeCheckoutAssociationCursor{ReceivedAt: oldAt, EventID: prefix + "zzz"}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 100 {
		t.Fatalf("candidate count = %d, want 100", len(candidates))
	}
	if candidates[0].EventID != newID {
		t.Fatalf("new overdue receipt hidden by due backlog: first=%s", candidates[0].EventID)
	}
	if candidates[1].EventID != prefix+"101" {
		t.Fatalf("uninspected due row hidden by repeating backlog: second=%s", candidates[1].EventID)
	}
}

func TestIntegration_StripeAssociationCursorDoesNotPassFailedDeferral(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	eventID := "evt_" + uuid.NewString()
	payload, err := json.Marshal(map[string]any{"data": map[string]any{"object": map[string]any{
		"id": "sub_" + uuid.NewString(), "customer": "cus_" + uuid.NewString(),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `INSERT INTO stripe_webhook_event(event_id, event_type, payload, received_at, last_error)
        VALUES ($1, 'customer.subscription.created', $2, $3, $4)`, eventID, payload, now.Add(-6*time.Minute), db.StripeCheckoutAssociationPendingError); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), `DELETE FROM stripe_webhook_event WHERE event_id = $1`, eventID)
	})
	h := api.NewHandlers(nil, testQueries, nil)
	h.Pool = testPool
	canceledCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cursor, err := h.StripeCheckoutAssociationTick(canceledCtx, now, db.StripeCheckoutAssociationCursor{}, func(api.StripeAssociationAlert) error {
		cancel()
		return errors.New("reporter interrupted")
	})
	if err == nil {
		t.Fatal("expected failed inspection deferral")
	}
	if cursor.EventID != "" || !cursor.ReceivedAt.IsZero() {
		t.Fatalf("cursor advanced past failed deferral: %+v", cursor)
	}
	var reported []string
	_, err = h.StripeCheckoutAssociationTick(ctx, now.Add(2*time.Minute), cursor, func(a api.StripeAssociationAlert) error {
		reported = append(reported, a.EventID)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(reported) != 1 || reported[0] != eventID {
		t.Fatalf("event not retried after lease expiry: %v", reported)
	}
}

func TestIntegration_StripeAssociationCandidateGraceAndClaims(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	eventID := "evt_monitor_" + uuid.NewString()
	payload, err := json.Marshal(map[string]any{
		"id": eventID, "type": "customer.subscription.deleted", "created": now.Unix(),
		"data": map[string]any{"object": map[string]any{"id": "sub_example", "customer": "cus_example", "status": "canceled"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `INSERT INTO stripe_webhook_event(event_id, event_type, payload, received_at, last_error)
VALUES ($1, 'customer.subscription.deleted', $2, $3, $4)`, eventID, payload, now.Add(-5*time.Minute), db.StripeCheckoutAssociationPendingError); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), `DELETE FROM stripe_webhook_event WHERE event_id = $1`, eventID)
	})

	list := func(at time.Time) []db.StripeCheckoutAssociationCandidate {
		t.Helper()
		candidates, err := db.ListStripeCheckoutAssociationCandidates(ctx, testPool, at, 5*time.Minute, db.StripeCheckoutAssociationCursor{}, 100)
		if err != nil {
			t.Fatal(err)
		}
		var matches []db.StripeCheckoutAssociationCandidate
		for _, c := range candidates {
			if c.EventID == eventID {
				matches = append(matches, c)
			}
		}
		return matches
	}
	// A retry persists the pending error near the deadline without moving receipt time.
	retriedAt := now.Add(-time.Minute)
	var receivedAt, updatedAt time.Time
	if err := testPool.QueryRow(ctx, `UPDATE stripe_webhook_event
SET last_error = $2, updated_at = $3 WHERE event_id = $1
RETURNING received_at, updated_at`, eventID, db.StripeCheckoutAssociationPendingError, retriedAt).Scan(&receivedAt, &updatedAt); err != nil {
		t.Fatal(err)
	}
	if !receivedAt.Equal(now.Add(-5*time.Minute)) || !updatedAt.Equal(retriedAt) {
		t.Fatalf("retry changed receipt clock: received_at=%s updated_at=%s", receivedAt, updatedAt)
	}
	if got := list(now.Add(-time.Microsecond)); len(got) != 0 {
		t.Fatalf("candidate before grace = %v", got)
	}
	if got := list(now); len(got) != 1 {
		t.Fatalf("candidate at grace = %v", got)
	}
	if after, err := db.ListStripeCheckoutAssociationCandidates(ctx, testPool, now, 5*time.Minute,
		db.StripeCheckoutAssociationCursor{ReceivedAt: now.Add(-5 * time.Minute), EventID: eventID}, 100); err != nil {
		t.Fatal(err)
	} else {
		for _, candidate := range after {
			if candidate.EventID == eventID {
				t.Fatal("keyset scan revisited the cursor event")
			}
		}
	}

	claim := func(at time.Time) bool {
		t.Helper()
		tx, err := testPool.BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		claimed, err := db.ClaimStripeCheckoutAssociationAlert(ctx, tx, eventID, at, at.Add(2*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		return claimed
	}
	if !claim(now) || claim(now) {
		t.Fatal("claim must exclude a second worker")
	}
	if len(list(now)) != 0 {
		t.Fatal("leased event remained due")
	}
	if !claim(now.Add(2 * time.Minute)) {
		t.Fatal("abandoned claim was not reclaimed")
	}
	lease := now.Add(4 * time.Minute)
	if err := db.FinishStripeCheckoutAssociationAlert(ctx, testPool, eventID, lease, now.Add(32*time.Minute), true, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if claim(now.Add(3 * time.Minute)) {
		t.Fatal("cooldown did not survive a new worker")
	}
	if !claim(now.Add(32 * time.Minute)) {
		t.Fatal("event did not become due after cooldown")
	}
	// Processing wins even if an old last_error remains.
	if _, err := testPool.Exec(ctx, `UPDATE stripe_webhook_event SET processed_at = $2 WHERE event_id = $1`, eventID, now); err != nil {
		t.Fatal(err)
	}
	if got := list(now.Add(40 * time.Minute)); len(got) != 0 {
		t.Fatalf("processed event remained alertable: %v", got)
	}
}
