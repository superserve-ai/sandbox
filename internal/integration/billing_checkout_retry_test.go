//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
)

type idempotentCheckoutStripeClient struct {
	*fakeStripeClient
	requests   map[string]api.StripeCreateCheckoutSessionParams
	sessions   map[string]api.StripeCheckoutSession
	failures   map[int]error
	mismatches int
	afterCall  func(context.Context, int) error
}

func (s *idempotentCheckoutStripeClient) CreateCheckoutSession(ctx context.Context, params api.StripeCreateCheckoutSessionParams) (api.StripeCheckoutSession, error) {
	s.mu.Lock()
	s.checkoutCalls = append(s.checkoutCalls, params)
	call := len(s.checkoutCalls)
	if s.requests == nil {
		s.requests = make(map[string]api.StripeCreateCheckoutSessionParams)
		s.sessions = make(map[string]api.StripeCheckoutSession)
	}
	if previous, ok := s.requests[params.IdempotencyKey]; ok && !reflect.DeepEqual(previous, params) {
		s.mismatches++
		s.mu.Unlock()
		return api.StripeCheckoutSession{}, errors.New("Stripe returned 400: idempotency key reused with different parameters")
	}
	err := s.failures[call]
	definitiveFailure := err != nil && strings.Contains(strings.ToLower(err.Error()), " returned 4")
	if _, ok := s.sessions[params.IdempotencyKey]; !ok && !definitiveFailure {
		s.requests[params.IdempotencyKey] = params
		s.sessions[params.IdempotencyKey] = api.StripeCheckoutSession{
			ID: fmt.Sprintf("cs_retry_%d", len(s.sessions)+1), URL: "https://checkout.stripe.test/retry",
		}
	}
	session := s.sessions[params.IdempotencyKey]
	s.mu.Unlock()
	if s.afterCall != nil {
		if hookErr := s.afterCall(ctx, call); hookErr != nil {
			return api.StripeCheckoutSession{}, hookErr
		}
	}
	return session, err
}

func (s *idempotentCheckoutStripeClient) assertCalls(t *testing.T, want int) {
	t.Helper()
	s.assertCounts(t, want, 1)
}

func (s *idempotentCheckoutStripeClient) assertCounts(t *testing.T, wantCalls, wantSessions int) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.checkoutCalls) != wantCalls || len(s.sessions) != wantSessions || s.mismatches != 0 {
		t.Fatalf("checkout calls=%d sessions=%d parameter mismatches=%d, want %d/%d/0", len(s.checkoutCalls), len(s.sessions), s.mismatches, wantCalls, wantSessions)
	}
}

func failCheckoutSessionPersistence(t *testing.T, teamID uuid.UUID) func() {
	t.Helper()
	ctx := context.Background()
	_, err := testPool.Exec(ctx, `CREATE FUNCTION test_fail_checkout_session_write() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.team_id::text = TG_ARGV[0] AND NEW.checkout_session_id IS NOT NULL THEN
				RAISE EXCEPTION 'forced checkout session persistence failure';
			END IF;
			RETURN NEW;
		END;
	$$;`)
	if err != nil {
		t.Fatal(err)
	}
	remove := func() {
		t.Helper()
		if _, err := testPool.Exec(ctx, `DROP TRIGGER IF EXISTS test_fail_checkout_session_write ON team_billing_account;
			DROP FUNCTION IF EXISTS test_fail_checkout_session_write();`); err != nil {
			t.Errorf("remove checkout persistence failure trigger: %v", err)
		}
	}
	t.Cleanup(remove)
	if _, err := testPool.Exec(ctx, fmt.Sprintf(`CREATE TRIGGER test_fail_checkout_session_write BEFORE UPDATE ON team_billing_account
		FOR EACH ROW EXECUTE FUNCTION test_fail_checkout_session_write('%s')`, teamID)); err != nil {
		t.Fatal(err)
	}
	return remove
}

func TestIntegration_CheckoutRetryPersistsOriginalSession(t *testing.T) {
	ctx := context.Background()
	teamID, key, actorID := seedTeamAndKeyWithRole(t, "team_owner")
	otherKey := seedKeyForExistingTeamWithRole(t, teamID, "team_owner")
	stripe := &idempotentCheckoutStripeClient{fakeStripeClient: &fakeStripeClient{nextCustomerID: "cus_retry_" + teamID.String()}}
	router := newBillingRouter(t, stripe)
	removeFailure := failCheckoutSessionPersistence(t, teamID)
	if w := do(router, "POST", "/stripe/checkout-session", key, checkoutRegressionBody); w.Code != http.StatusInternalServerError {
		t.Fatalf("checkout with failed session write: %d %s", w.Code, w.Body.String())
	}
	first, err := testQueries.GetTeamBillingAccount(ctx, teamID)
	if err != nil || !first.CheckoutInitializingAt.Valid || first.CheckoutSessionID != nil || !first.StripeCheckoutActorID.Valid {
		t.Fatalf("failed session write did not retain checkout generation: %+v %v", first, err)
	}
	stripe.assertCalls(t, 1)
	removeFailure()
	for _, request := range []struct{ name, key, body string }{
		{"other_actor", otherKey, checkoutRegressionBody},
		{"changed_redirect", key, `{"success_url":"https://app.superserve.test/billing/other","cancel_url":"https://app.superserve.test/billing/cancel"}`},
	} {
		if w := do(router, "POST", "/stripe/checkout-session", request.key, request.body); w.Code != http.StatusConflict {
			t.Fatalf("%s retry: %d %s", request.name, w.Code, w.Body.String())
		}
	}
	changedPrices := newBillingRouterWithPool(t, stripe, testPool, config.BillingResourceConfig{
		ResourceKey: "vcpu", Billable: true, CheckoutEnabled: true, StripePriceID: "price_cpu_replacement",
	})
	if w := do(changedPrices, "POST", "/stripe/checkout-session", key, checkoutRegressionBody); w.Code != http.StatusConflict {
		t.Fatalf("changed price retry: %d %s", w.Code, w.Body.String())
	}
	stripe.assertCalls(t, 1)
	w := do(router, "POST", "/stripe/checkout-session", key, checkoutRegressionBody)
	if w.Code != http.StatusOK {
		t.Fatalf("matching retry: %d %s", w.Code, w.Body.String())
	}
	var session api.StripeCheckoutSession
	if err := json.Unmarshal(w.Body.Bytes(), &session); err != nil || session.ID != "cs_retry_1" || session.URL == "" {
		t.Fatalf("retry did not return original session: %+v %v", session, err)
	}
	after, err := testQueries.GetTeamBillingAccount(ctx, teamID)
	if err != nil || !after.CheckoutInitializingAt.Time.Equal(first.CheckoutInitializingAt.Time) || after.StripeCheckoutActorID != first.StripeCheckoutActorID || derefString(after.CheckoutSessionID) != session.ID {
		t.Fatalf("retry changed generation/actor or failed to persist session: %+v %v", after, err)
	}
	stripe.assertCalls(t, 2)
	if stripe.checkoutCalls[1].Metadata["activation_user_id"] != actorID.String() {
		t.Fatalf("retry changed activation actor: %+v", stripe.checkoutCalls[1].Metadata)
	}
	if w := do(router, "POST", "/stripe/checkout-session", otherKey, checkoutRegressionBody); w.Code != http.StatusConflict {
		t.Fatalf("persisted checkout allowed another writer: %d %s", w.Code, w.Body.String())
	}
	stripe.assertCalls(t, 2)
}

func TestIntegration_CheckoutRetryFailurePreservesAmbiguousLease(t *testing.T) {
	for _, retryError := range []string{"Stripe returned 400: invalid request", "Stripe returned 409: request in progress", "Stripe returned 429: rate limited", "connection reset by peer"} {
		t.Run(retryError, func(t *testing.T) {
			ctx := context.Background()
			teamID, key, _ := seedTeamAndKeyWithRole(t, "team_owner")
			otherKey := seedKeyForExistingTeamWithRole(t, teamID, "team_owner")
			stripe := &idempotentCheckoutStripeClient{
				fakeStripeClient: &fakeStripeClient{nextCustomerID: "cus_ambiguous_retry_" + teamID.String()},
				failures:         map[int]error{1: context.DeadlineExceeded, 2: errors.New(retryError)},
			}
			router := newBillingRouter(t, stripe)
			if w := do(router, "POST", "/stripe/checkout-session", key, checkoutRegressionBody); w.Code != http.StatusBadGateway {
				t.Fatalf("ambiguous initial checkout: %d %s", w.Code, w.Body.String())
			}
			first, err := testQueries.GetTeamBillingAccount(ctx, teamID)
			if err != nil || !first.CheckoutInitializingAt.Valid {
				t.Fatalf("missing ambiguous checkout lease: %+v %v", first, err)
			}
			if w := do(router, "POST", "/stripe/checkout-session", key, checkoutRegressionBody); w.Code != http.StatusBadGateway {
				t.Fatalf("failed retry: %d %s", w.Code, w.Body.String())
			}
			after, err := testQueries.GetTeamBillingAccount(ctx, teamID)
			if err != nil || !after.CheckoutInitializingAt.Valid || !after.CheckoutInitializingAt.Time.Equal(first.CheckoutInitializingAt.Time) || after.StripeCheckoutActorID != first.StripeCheckoutActorID {
				t.Fatalf("failed retry released ambiguous fence: %+v %v", after, err)
			}
			if w := do(router, "POST", "/stripe/checkout-session", otherKey, checkoutRegressionBody); w.Code != http.StatusConflict {
				t.Fatalf("failed retry exposed checkout to another writer: %d %s", w.Code, w.Body.String())
			}
			stripe.assertCalls(t, 2)
			if w := do(router, "POST", "/stripe/checkout-session", key, checkoutRegressionBody); w.Code != http.StatusOK {
				t.Fatalf("subsequent successful retry: %d %s", w.Code, w.Body.String())
			}
			stripe.assertCalls(t, 3)
		})
	}
}

func TestIntegration_CheckoutInitialDefinitiveErrorReleasesLease(t *testing.T) {
	for _, initialError := range []string{"Stripe returned 409: request in progress", "Stripe returned 429: rate limited"} {
		t.Run(initialError, func(t *testing.T) {
			teamID, key, _ := seedTeamAndKeyWithRole(t, "team_owner")
			otherKey := seedKeyForExistingTeamWithRole(t, teamID, "team_owner")
			stripe := &idempotentCheckoutStripeClient{
				fakeStripeClient: &fakeStripeClient{nextCustomerID: "cus_retryable_" + teamID.String()},
				failures:         map[int]error{1: errors.New(initialError)},
			}
			router := newBillingRouter(t, stripe)
			if w := do(router, "POST", "/stripe/checkout-session", key, checkoutRegressionBody); w.Code != http.StatusBadGateway {
				t.Fatalf("initial checkout: %d %s", w.Code, w.Body.String())
			}
			account, err := testQueries.GetTeamBillingAccount(context.Background(), teamID)
			if err != nil || account.CheckoutInitializingAt.Valid || account.StripeCheckoutActorID.Valid {
				t.Fatalf("definitive failure retained checkout generation: %+v %v", account, err)
			}
			stripe.assertCounts(t, 1, 0)
			if w := do(router, "POST", "/stripe/checkout-session", otherKey, checkoutRegressionBody); w.Code != http.StatusOK {
				t.Fatalf("new writer after definitive failure: %d %s", w.Code, w.Body.String())
			}
			stripe.assertCalls(t, 2)
		})
	}
}

func TestIntegration_CheckoutRetryDoesNotReplayNearExpiry(t *testing.T) {
	ctx := context.Background()
	teamID, key, _ := seedTeamAndKeyWithRole(t, "team_owner")
	stripe := &idempotentCheckoutStripeClient{
		fakeStripeClient: &fakeStripeClient{nextCustomerID: "cus_old_retry_" + teamID.String()},
		failures:         map[int]error{1: context.DeadlineExceeded},
	}
	router := newBillingRouter(t, stripe)
	if w := do(router, "POST", "/stripe/checkout-session", key, checkoutRegressionBody); w.Code != http.StatusBadGateway {
		t.Fatalf("ambiguous initial checkout: %d %s", w.Code, w.Body.String())
	}
	for _, age := range []time.Duration{23 * time.Hour, 25 * time.Hour} {
		// The replay lease compares database timestamps; use that same clock.
		if _, err := testPool.Exec(ctx, `UPDATE team_billing_account SET checkout_initializing_at=now()-$2::double precision*interval '1 second' WHERE team_id=$1`, teamID, age.Seconds()); err != nil {
			t.Fatal(err)
		}
		if w := do(router, "POST", "/stripe/checkout-session", key, checkoutRegressionBody); w.Code != http.StatusConflict {
			t.Fatalf("%s-old checkout was replayed: %d %s", age, w.Code, w.Body.String())
		}
		stripe.assertCalls(t, 1)
	}
}

func TestIntegration_CheckoutConcurrentRetriesReuseOneSession(t *testing.T) {
	teamID, key, _ := seedTeamAndKeyWithRole(t, "team_owner")
	arrived, release := make(chan struct{}, 2), make(chan struct{})
	stripe := &idempotentCheckoutStripeClient{
		fakeStripeClient: &fakeStripeClient{nextCustomerID: "cus_concurrent_retry_" + teamID.String()},
		failures:         map[int]error{1: context.DeadlineExceeded},
		afterCall: func(ctx context.Context, call int) error {
			if call > 1 {
				arrived <- struct{}{}
				select {
				case <-release:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return nil
		},
	}
	router := newBillingRouter(t, stripe)
	if w := do(router, "POST", "/stripe/checkout-session", key, checkoutRegressionBody); w.Code != http.StatusBadGateway {
		t.Fatalf("ambiguous initial checkout: %d %s", w.Code, w.Body.String())
	}
	responses := make(chan *httptest.ResponseRecorder, 2)
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	var workers sync.WaitGroup
	defer func() {
		unblock()
		workers.Wait()
	}()
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			responses <- do(router, "POST", "/stripe/checkout-session", key, checkoutRegressionBody)
		}()
	}
	for range 2 {
		select {
		case <-arrived:
		case <-time.After(5 * time.Second):
			t.Fatal("concurrent checkout retries did not both reach the idempotent Stripe request")
		}
	}
	unblock()
	for range 2 {
		select {
		case w := <-responses:
			if w.Code != http.StatusOK {
				t.Fatalf("concurrent retry: %d %s", w.Code, w.Body.String())
			}
		case <-time.After(5 * time.Second):
			t.Fatal("concurrent checkout retry did not finish")
		}
	}
	stripe.assertCalls(t, 3)
}

func TestIntegration_CheckoutExpirationRecoversUnpersistedSession(t *testing.T) {
	ctx := context.Background()
	teamID, firstKey, firstActor := seedTeamAndKeyWithRole(t, "team_owner")
	secondKey := seedKeyForExistingTeamWithRole(t, teamID, "team_owner")
	stripe := &idempotentCheckoutStripeClient{fakeStripeClient: &fakeStripeClient{nextCustomerID: "cus_unsaved_" + teamID.String()}}
	router := newBillingRouter(t, stripe)
	removeFailure := failCheckoutSessionPersistence(t, teamID)
	if w := do(router, "POST", "/stripe/checkout-session", firstKey, checkoutRegressionBody); w.Code != http.StatusInternalServerError {
		t.Fatalf("checkout with failed session write: %d %s", w.Code, w.Body.String())
	}
	removeFailure()
	oldStart := time.Now().UTC().Add(-25 * time.Hour).Truncate(time.Microsecond)
	if _, err := testPool.Exec(ctx, `UPDATE team_billing_account SET checkout_initializing_at=$2 WHERE team_id=$1`, teamID, oldStart); err != nil {
		t.Fatal(err)
	}
	if w := do(router, "POST", "/stripe/checkout-session", firstKey, checkoutRegressionBody); w.Code != http.StatusConflict {
		t.Fatalf("old unpersisted session allowed replay: %d %s", w.Code, w.Body.String())
	}
	stripe.assertCalls(t, 1)
	generation := oldStart.Format(time.RFC3339Nano)
	eventNumber := 0
	sendExpiration := func(sessionID, customerID, checkoutGeneration string) {
		t.Helper()
		eventNumber++
		now := time.Now().UTC().Truncate(time.Second)
		payload, err := json.Marshal(map[string]any{
			"id": fmt.Sprintf("evt_unsaved_%s_%d", teamID, eventNumber), "type": "checkout.session.expired", "created": now.Unix(),
			"data": map[string]any{"object": map[string]any{
				"id": sessionID, "client_reference_id": teamID.String(), "customer": customerID,
				"metadata": map[string]string{"checkout_generation": checkoutGeneration},
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(payload)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Stripe-Signature", stripeSignature(t, payload, now))
		if w := doRequest(router, req); w.Code != http.StatusOK {
			t.Fatalf("expiration: %d %s", w.Code, w.Body.String())
		}
	}
	for _, event := range []struct{ name, session, customer, generation string }{
		{"missing_session", "", stripe.nextCustomerID, generation},
		{"wrong_customer", "cs_retry_1", "cus_other", generation},
		{"missing_generation", "cs_retry_1", stripe.nextCustomerID, ""},
		{"wrong_generation", "cs_retry_1", stripe.nextCustomerID, oldStart.Add(-time.Second).Format(time.RFC3339Nano)},
	} {
		sendExpiration(event.session, event.customer, event.generation)
		account, err := testQueries.GetTeamBillingAccount(ctx, teamID)
		if err != nil || !account.CheckoutInitializingAt.Valid || !account.CheckoutInitializingAt.Time.Equal(oldStart) || account.CheckoutSessionID != nil || !account.StripeCheckoutActorID.Valid {
			t.Fatalf("%s expiration cleared unpersisted session fence: %+v %v", event.name, account, err)
		}
	}
	sendExpiration("cs_retry_1", stripe.nextCustomerID, generation)
	account, err := testQueries.GetTeamBillingAccount(ctx, teamID)
	if err != nil || account.CheckoutInitializingAt.Valid || account.StripeCheckoutActorID.Valid {
		t.Fatalf("matching generation did not release expired session: %+v %v", account, err)
	}
	if w := do(router, "POST", "/stripe/checkout-session", secondKey, checkoutRegressionBody); w.Code != http.StatusOK {
		t.Fatalf("new writer could not start checkout after expiration: %d %s", w.Code, w.Body.String())
	}
	replacement, err := testQueries.GetTeamBillingAccount(ctx, teamID)
	if err != nil || derefString(replacement.CheckoutSessionID) != "cs_retry_2" || uuid.UUID(replacement.StripeCheckoutActorID.Bytes) == firstActor {
		t.Fatalf("replacement session/actor not established: %+v %v", replacement, err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE team_billing_account SET checkout_session_id=NULL WHERE team_id=$1`, teamID); err != nil {
		t.Fatal(err)
	}
	sendExpiration("cs_retry_1", stripe.nextCustomerID, generation)
	account, err = testQueries.GetTeamBillingAccount(ctx, teamID)
	if err != nil || !account.CheckoutInitializingAt.Valid || !account.CheckoutInitializingAt.Time.Equal(replacement.CheckoutInitializingAt.Time) || account.StripeCheckoutActorID != replacement.StripeCheckoutActorID {
		t.Fatalf("stale generation cleared newer unpersisted session: %+v %v", account, err)
	}
}

func TestIntegration_CheckoutInitialFailureCannotReleaseSuccessfulRetry(t *testing.T) {
	ctx := context.Background()
	teamID, key, _ := seedTeamAndKeyWithRole(t, "team_owner")
	otherKey := seedKeyForExistingTeamWithRole(t, teamID, "team_owner")
	arrived, release := make(chan struct{}), make(chan struct{})
	stripe := &idempotentCheckoutStripeClient{
		fakeStripeClient: &fakeStripeClient{nextCustomerID: "cus_initial_failure_" + teamID.String()},
		failures:         map[int]error{1: errors.New("Stripe returned 401: unauthorized")},
		afterCall: func(ctx context.Context, call int) error {
			if call == 1 {
				close(arrived)
				select {
				case <-release:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return nil
		},
	}
	router := newBillingRouter(t, stripe)
	initialResponse := make(chan *httptest.ResponseRecorder, 1)
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	var worker sync.WaitGroup
	worker.Add(1)
	defer func() {
		unblock()
		worker.Wait()
	}()
	go func() {
		defer worker.Done()
		initialResponse <- do(router, "POST", "/stripe/checkout-session", key, checkoutRegressionBody)
	}()
	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("initial checkout did not reach Stripe")
	}
	if w := do(router, "POST", "/stripe/checkout-session", key, checkoutRegressionBody); w.Code != http.StatusOK {
		t.Fatalf("concurrent retry: %d %s", w.Code, w.Body.String())
	}
	completed, err := testQueries.GetTeamBillingAccount(ctx, teamID)
	if err != nil || !completed.CheckoutInitializingAt.Valid || derefString(completed.CheckoutSessionID) != "cs_retry_1" {
		t.Fatalf("retry did not persist original generation: %+v %v", completed, err)
	}
	unblock()
	select {
	case w := <-initialResponse:
		if w.Code != http.StatusBadGateway {
			t.Fatalf("initial definitive failure: %d %s", w.Code, w.Body.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("initial checkout did not finish")
	}
	after, err := testQueries.GetTeamBillingAccount(ctx, teamID)
	if err != nil || !after.CheckoutInitializingAt.Valid || !after.CheckoutInitializingAt.Time.Equal(completed.CheckoutInitializingAt.Time) || after.StripeCheckoutActorID != completed.StripeCheckoutActorID || derefString(after.CheckoutSessionID) != "cs_retry_1" {
		t.Fatalf("initial failure released successful retry fence: %+v %v", after, err)
	}
	if w := do(router, "POST", "/stripe/checkout-session", otherKey, checkoutRegressionBody); w.Code != http.StatusConflict {
		t.Fatalf("initial failure permitted another checkout: %d %s", w.Code, w.Body.String())
	}
	stripe.assertCalls(t, 2)
}

func TestIntegration_CheckoutOverlappingDefinitiveFailuresReleaseLease(t *testing.T) {
	for _, statuses := range [][2]int{{401, 401}, {401, 400}, {400, 401}, {401, 409}, {409, 401}} {
		t.Run(fmt.Sprintf("initial_%d_retry_%d", statuses[0], statuses[1]), func(t *testing.T) {
			ctx := context.Background()
			teamID, key, firstActor := seedTeamAndKeyWithRole(t, "team_owner")
			otherKey := seedKeyForExistingTeamWithRole(t, teamID, "team_owner")
			arrived, release := make(chan struct{}), make(chan struct{})
			stripe := &idempotentCheckoutStripeClient{
				fakeStripeClient: &fakeStripeClient{nextCustomerID: "cus_definitive_" + teamID.String()},
				failures: map[int]error{
					1: fmt.Errorf("Stripe returned %d: request rejected", statuses[0]),
					2: fmt.Errorf("Stripe returned %d: request rejected", statuses[1]),
				},
				afterCall: func(ctx context.Context, call int) error {
					if call == 1 {
						close(arrived)
						select {
						case <-release:
						case <-ctx.Done():
							return ctx.Err()
						}
					}
					return nil
				},
			}
			router := newBillingRouter(t, stripe)
			initialResponse := make(chan *httptest.ResponseRecorder, 1)
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			var worker sync.WaitGroup
			worker.Add(1)
			defer func() {
				unblock()
				worker.Wait()
			}()
			go func() {
				defer worker.Done()
				initialResponse <- do(router, "POST", "/stripe/checkout-session", key, checkoutRegressionBody)
			}()
			select {
			case <-arrived:
			case <-time.After(5 * time.Second):
				t.Fatal("initial checkout did not reach Stripe")
			}
			first, err := testQueries.GetTeamBillingAccount(ctx, teamID)
			if err != nil || !first.CheckoutInitializingAt.Valid {
				t.Fatalf("initial checkout has no generation: %+v %v", first, err)
			}
			if w := do(router, "POST", "/stripe/checkout-session", key, checkoutRegressionBody); w.Code != http.StatusBadGateway {
				t.Fatalf("overlapping rejected retry: %d %s", w.Code, w.Body.String())
			}
			if w := do(router, "POST", "/stripe/checkout-session", otherKey, checkoutRegressionBody); w.Code != http.StatusConflict {
				t.Fatalf("retry released still-pending initial attempt: %d %s", w.Code, w.Body.String())
			}
			stripe.assertCounts(t, 2, 0)
			unblock()
			select {
			case w := <-initialResponse:
				if w.Code != http.StatusBadGateway {
					t.Fatalf("rejected initial request: %d %s", w.Code, w.Body.String())
				}
			case <-time.After(5 * time.Second):
				t.Fatal("initial checkout did not finish")
			}
			after, err := testQueries.GetTeamBillingAccount(ctx, teamID)
			if err != nil || after.CheckoutInitializingAt.Valid || after.StripeCheckoutActorID.Valid || after.CheckoutSessionID != nil {
				t.Fatalf("all rejected attempts retained checkout generation: %+v %v", after, err)
			}
			if w := do(router, "POST", "/stripe/checkout-session", otherKey, checkoutRegressionBody); w.Code != http.StatusOK {
				t.Fatalf("new writer could not start a fresh generation: %d %s", w.Code, w.Body.String())
			}
			replacement, err := testQueries.GetTeamBillingAccount(ctx, teamID)
			if err != nil || !replacement.CheckoutInitializingAt.Valid || replacement.CheckoutInitializingAt.Time.Equal(first.CheckoutInitializingAt.Time) || uuid.UUID(replacement.StripeCheckoutActorID.Bytes) == firstActor {
				t.Fatalf("new writer reused rejected checkout generation/actor: %+v %v", replacement, err)
			}
			stripe.assertCalls(t, 3)
			if stripe.checkoutCalls[2].IdempotencyKey == stripe.checkoutCalls[0].IdempotencyKey {
				t.Fatal("replacement checkout reused definitively rejected generation key")
			}
		})
	}
}

func TestIntegration_CheckoutRetryReturnsPersistedSession(t *testing.T) {
	ctx := context.Background()
	teamID, key, actorID := seedTeamAndKeyWithRole(t, "team_owner")
	otherKey := seedKeyForExistingTeamWithRole(t, teamID, "team_owner")
	stripe := &idempotentCheckoutStripeClient{fakeStripeClient: &fakeStripeClient{nextCustomerID: "cus_lost_response_" + teamID.String()}}
	router := newBillingRouter(t, stripe)
	firstResponse := do(router, "POST", "/stripe/checkout-session", key, checkoutRegressionBody)
	if firstResponse.Code != http.StatusOK {
		t.Fatalf("initial checkout: %d %s", firstResponse.Code, firstResponse.Body.String())
	}
	first, err := testQueries.GetTeamBillingAccount(ctx, teamID)
	if err != nil || derefString(first.CheckoutSessionID) != "cs_retry_1" {
		t.Fatalf("initial checkout session not persisted: %+v %v", first, err)
	}
	for _, request := range []struct{ name, key, body string }{
		{"other_actor", otherKey, checkoutRegressionBody},
		{"changed_redirect", key, `{"success_url":"https://app.superserve.test/billing/other","cancel_url":"https://app.superserve.test/billing/cancel"}`},
	} {
		if w := do(router, "POST", "/stripe/checkout-session", request.key, request.body); w.Code != http.StatusConflict {
			t.Fatalf("%s retry: %d %s", request.name, w.Code, w.Body.String())
		}
	}
	changedPrices := newBillingRouterWithPool(t, stripe, testPool, config.BillingResourceConfig{
		ResourceKey: "vcpu", Billable: true, CheckoutEnabled: true, StripePriceID: "price_cpu_replacement",
	})
	if w := do(changedPrices, "POST", "/stripe/checkout-session", key, checkoutRegressionBody); w.Code != http.StatusConflict {
		t.Fatalf("changed price retry: %d %s", w.Code, w.Body.String())
	}
	stripe.assertCalls(t, 1)
	retry := do(router, "POST", "/stripe/checkout-session", key, checkoutRegressionBody)
	if retry.Code != http.StatusOK || retry.Body.String() != firstResponse.Body.String() {
		t.Fatalf("lost-response retry did not return original session: %d %s; want %s", retry.Code, retry.Body.String(), firstResponse.Body.String())
	}
	after, err := testQueries.GetTeamBillingAccount(ctx, teamID)
	if err != nil || !after.CheckoutInitializingAt.Valid || !after.CheckoutInitializingAt.Time.Equal(first.CheckoutInitializingAt.Time) || after.StripeCheckoutActorID != first.StripeCheckoutActorID || derefString(after.CheckoutSessionID) != "cs_retry_1" {
		t.Fatalf("lost-response retry changed checkout state: %+v %v", after, err)
	}
	stripe.assertCalls(t, 2)
	if stripe.checkoutCalls[1].Metadata["activation_user_id"] != actorID.String() {
		t.Fatal("lost-response retry changed activation actor")
	}
}

func TestIntegration_CheckoutRetriesFailedAttemptSettlement(t *testing.T) {
	ctx := context.Background()
	teamID, key, _ := seedTeamAndKeyWithRole(t, "team_owner")
	otherKey := seedKeyForExistingTeamWithRole(t, teamID, "team_owner")
	stripe := &idempotentCheckoutStripeClient{
		fakeStripeClient: &fakeStripeClient{nextCustomerID: "cus_settlement_retry_" + teamID.String()},
		failures:         map[int]error{1: errors.New("Stripe returned 400: invalid request")},
	}
	router := newBillingRouter(t, stripe)
	_, err := testPool.Exec(ctx, `
		CREATE SEQUENCE test_checkout_settlement_calls;
		CREATE FUNCTION test_fail_first_checkout_settlement() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.team_id::text = TG_ARGV[0]
			   AND cardinality(NEW.checkout_pending_attempt_ids) < cardinality(OLD.checkout_pending_attempt_ids) THEN
				IF nextval('test_checkout_settlement_calls') = 1 THEN
					RAISE EXCEPTION 'forced first checkout settlement failure';
				END IF;
			END IF;
			RETURN NEW;
		END;
		$$;
	`)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := testPool.Exec(ctx, `
			DROP TRIGGER IF EXISTS test_fail_first_checkout_settlement ON team_billing_account;
			DROP FUNCTION IF EXISTS test_fail_first_checkout_settlement();
			DROP SEQUENCE IF EXISTS test_checkout_settlement_calls;
		`); err != nil {
			t.Errorf("remove checkout settlement fault: %v", err)
		}
	})
	if _, err := testPool.Exec(ctx, fmt.Sprintf(`CREATE TRIGGER test_fail_first_checkout_settlement
		BEFORE UPDATE ON team_billing_account FOR EACH ROW
		EXECUTE FUNCTION test_fail_first_checkout_settlement('%s')`, teamID)); err != nil {
		t.Fatal(err)
	}
	if w := do(router, "POST", "/stripe/checkout-session", key, checkoutRegressionBody); w.Code != http.StatusBadGateway {
		t.Fatalf("rejected checkout: %d %s", w.Code, w.Body.String())
	}
	var settlementCalls int64
	if err := testPool.QueryRow(ctx, `SELECT last_value FROM test_checkout_settlement_calls`).Scan(&settlementCalls); err != nil || settlementCalls != 2 {
		t.Fatalf("checkout settlement calls=%d, want 2: %v", settlementCalls, err)
	}
	account, err := testQueries.GetTeamBillingAccount(ctx, teamID)
	if err != nil || account.CheckoutInitializingAt.Valid || account.StripeCheckoutActorID.Valid || account.CheckoutSessionID != nil {
		t.Fatalf("settlement retry retained rejected generation: %+v %v", account, err)
	}
	stripe.assertCounts(t, 1, 0)
	if w := do(router, "POST", "/stripe/checkout-session", otherKey, checkoutRegressionBody); w.Code != http.StatusOK {
		t.Fatalf("new writer blocked after retried settlement: %d %s", w.Code, w.Body.String())
	}
	stripe.assertCalls(t, 2)
}

func TestIntegration_CheckoutAttemptSettlementReplayIsIdempotent(t *testing.T) {
	ctx := context.Background()
	teamID, _, actorID := seedTeamAndKeyWithRole(t, "team_owner")
	if _, err := testPool.Exec(ctx, `INSERT INTO team_billing_account(team_id,stripe_customer_id) VALUES($1,$2)`, teamID, "cus_settlement_replay_"+teamID.String()); err != nil {
		t.Fatal(err)
	}
	firstAttempt, secondAttempt := uuid.New(), uuid.New()
	actor := pgtype.UUID{Bytes: actorID, Valid: true}
	requestKey := "checkout-settlement-replay"
	first, err := testQueries.BeginTeamBillingCheckout(ctx, db.BeginTeamBillingCheckoutParams{
		TeamID: teamID, ActorID: actor, RequestKey: &requestKey, AttemptID: firstAttempt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testQueries.ResumeTeamBillingCheckout(ctx, db.ResumeTeamBillingCheckoutParams{
		TeamID: teamID, ActorID: actor, RequestKey: &requestKey, AttemptID: secondAttempt,
	}); err != nil {
		t.Fatal(err)
	}
	firstSettlement := db.FinishFailedTeamBillingCheckoutAttemptParams{
		TeamID: teamID, LeaseStartedAt: first.CheckoutInitializingAt, AttemptID: firstAttempt, MayExist: false,
	}
	for replay := range 2 {
		if err := testQueries.FinishFailedTeamBillingCheckoutAttempt(ctx, firstSettlement); err != nil {
			t.Fatal(err)
		}
		var onlySecondPending bool
		if err := testPool.QueryRow(ctx, `SELECT checkout_pending_attempt_ids = ARRAY[$2::uuid]
			FROM team_billing_account WHERE team_id=$1`, teamID, secondAttempt).Scan(&onlySecondPending); err != nil || !onlySecondPending {
			t.Fatalf("settlement replay %d removed another pending attempt: onlySecondPending=%v err=%v", replay, onlySecondPending, err)
		}
		account, err := testQueries.GetTeamBillingAccount(ctx, teamID)
		if err != nil || !account.CheckoutInitializingAt.Valid || !account.CheckoutInitializingAt.Time.Equal(first.CheckoutInitializingAt.Time) || account.StripeCheckoutActorID != actor {
			t.Fatalf("settlement replay %d released pending generation: %+v %v", replay, account, err)
		}
	}
	if err := testQueries.FinishFailedTeamBillingCheckoutAttempt(ctx, db.FinishFailedTeamBillingCheckoutAttemptParams{
		TeamID: teamID, LeaseStartedAt: first.CheckoutInitializingAt, AttemptID: secondAttempt, MayExist: false,
	}); err != nil {
		t.Fatal(err)
	}
	account, err := testQueries.GetTeamBillingAccount(ctx, teamID)
	if err != nil || account.CheckoutInitializingAt.Valid || account.StripeCheckoutActorID.Valid {
		t.Fatalf("final rejected attempt did not release generation: %+v %v", account, err)
	}
	var noPending bool
	if err := testPool.QueryRow(ctx, `SELECT cardinality(checkout_pending_attempt_ids)=0
		FROM team_billing_account WHERE team_id=$1`, teamID).Scan(&noPending); err != nil || !noPending {
		t.Fatalf("settled generation retained pending attempts: empty=%v err=%v", noPending, err)
	}
}
