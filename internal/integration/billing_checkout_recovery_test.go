//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/db"
)

const checkoutRecoveryPath = "/stripe/checkout-session/recover"

type recoveryCheckoutStripeClient struct {
	*idempotentCheckoutStripeClient
	retrievedIDs []string
	retrieveErr  error
	mutate       func(*api.StripeRetrievedCheckoutSession)
	afterGet     func(context.Context) error
}

func (s *recoveryCheckoutStripeClient) RetrieveCheckoutSession(ctx context.Context, id string) (api.StripeRetrievedCheckoutSession, error) {
	s.mu.Lock()
	s.retrievedIDs = append(s.retrievedIDs, id)
	var found api.StripeRetrievedCheckoutSession
	for key, session := range s.sessions {
		if session.ID != id {
			continue
		}
		params := s.requests[key]
		metadata := make(map[string]string, len(params.Metadata))
		for key, value := range params.Metadata {
			metadata[key] = value
		}
		found = api.StripeRetrievedCheckoutSession{
			ID: session.ID, URL: session.URL, CustomerID: params.CustomerID,
			ClientReferenceID: params.ClientReferenceID, Status: "open", Mode: "subscription",
			ExpiresAt: params.ExpiresAt.Unix(), Metadata: metadata,
		}
	}
	err := s.retrieveErr
	if s.mutate != nil {
		s.mutate(&found)
	}
	s.mu.Unlock()
	if s.afterGet != nil {
		if hookErr := s.afterGet(ctx); hookErr != nil {
			return api.StripeRetrievedCheckoutSession{}, hookErr
		}
	}
	if found.ID == "" && err == nil {
		err = api.ErrStripeCheckoutSessionNotFound
	}
	return found, err
}

type recoveryCreateCounts struct{ customers, sessions, grants, externalSessions, mismatches int }

func (s *recoveryCheckoutStripeClient) createCounts() recoveryCreateCounts {
	s.mu.Lock()
	defer s.mu.Unlock()
	return recoveryCreateCounts{len(s.customerCalls), len(s.checkoutCalls), len(s.creditGrantCalls), len(s.sessions), s.mismatches}
}

func (s *recoveryCheckoutStripeClient) assertNoCreates(t *testing.T, before recoveryCreateCounts) {
	t.Helper()
	if after := s.createCounts(); after != before {
		t.Fatalf("recovery performed create side effects: before=%+v after=%+v", before, after)
	}
}

type checkoutRecoveryFixture struct {
	team, actor uuid.UUID
	key         string
	router      *gin.Engine
	stripe      *recoveryCheckoutStripeClient
}

func newCheckoutRecoveryFixture(t *testing.T) checkoutRecoveryFixture {
	t.Helper()
	team, key, actor := seedTeamAndKeyWithRole(t, "team_owner")
	enableBillingExportForCheckoutActorTest(t, team)
	stripe := &recoveryCheckoutStripeClient{idempotentCheckoutStripeClient: &idempotentCheckoutStripeClient{
		fakeStripeClient: &fakeStripeClient{nextCustomerID: "cus_recovery_" + team.String()},
	}}
	router := newBillingRouter(t, stripe)
	if w := do(router, "POST", "/stripe/checkout-session", key, checkoutRegressionBody); w.Code != http.StatusOK {
		t.Fatalf("initial checkout: %d %s", w.Code, w.Body.String())
	}
	return checkoutRecoveryFixture{team: team, actor: actor, key: key, router: router, stripe: stripe}
}

func (f checkoutRecoveryFixture) snapshot(t *testing.T) string {
	t.Helper()
	var snapshot string
	if err := testPool.QueryRow(context.Background(), `SELECT jsonb_build_object(
		'account',(SELECT to_jsonb(a) FROM team_billing_account a WHERE team_id=$1),
		'entitlement',(SELECT to_jsonb(e) FROM user_promotion_entitlement e WHERE user_id=$2),
		'grants',(SELECT jsonb_agg(to_jsonb(g) ORDER BY g.id) FROM team_credit_grant g WHERE team_id=$1),
		'identities',(SELECT jsonb_agg(to_jsonb(i) ORDER BY i.identity_key) FROM promotion_identity i
			WHERE i.identity_key IN (SELECT identity_key FROM promotion_identity_binding WHERE user_id=$2))
		)::text`, f.team, f.actor).Scan(&snapshot); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func (f checkoutRecoveryFixture) assertUnchanged(t *testing.T, snapshot string, counts recoveryCreateCounts) {
	t.Helper()
	if after := f.snapshot(t); after != snapshot {
		t.Fatalf("recovery changed billing state or promotion entitlements:\nbefore %s\nafter  %s", snapshot, after)
	}
	f.stripe.assertNoCreates(t, counts)
}

func assertCheckoutRecoveryError(t *testing.T, w *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	var response struct {
		Error struct{ Code string } `json:"error"`
		URL   string                `json:"url"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || w.Code != status || response.Error.Code != code || response.URL != "" {
		t.Fatalf("recovery: %d %s, want %d %s without URL (decode %v)", w.Code, w.Body.String(), status, code, err)
	}
}

func (f checkoutRecoveryFixture) assertRecovered(t *testing.T, body string) {
	t.Helper()
	before, counts := f.snapshot(t), f.stripe.createCounts()
	account, err := testQueries.GetTeamBillingAccount(context.Background(), f.team)
	if err != nil {
		t.Fatal(err)
	}
	w := do(f.router, "POST", checkoutRecoveryPath, f.key, body)
	var response struct {
		Outcome            string `json:"outcome"`
		ID                 string `json:"id"`
		URL                string `json:"url"`
		CheckoutGeneration string `json:"checkout_generation"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || w.Code != http.StatusOK || response.Outcome != "recovered" || response.ID != derefString(account.CheckoutSessionID) || response.URL != "https://checkout.stripe.test/retry" || response.CheckoutGeneration != account.CheckoutInitializingAt.Time.UTC().Format(time.RFC3339Nano) {
		t.Fatalf("recovery did not return the original generation: %d %s (decode %v)", w.Code, w.Body.String(), err)
	}
	f.assertUnchanged(t, before, counts)
}

func TestIntegration_CheckoutRecoveryUsesAgedPinnedEvidenceAfterRefreshFailure(t *testing.T) {
	ctx := context.Background()
	f := newCheckoutRecoveryFixture(t)
	version := uuid.New()
	// Reconstruct an already-open generation whose evidence was captured while
	// fresh. Neither a stale current observation nor a failed refresh invalidates it.
	if _, err := testPool.Exec(ctx, `INSERT INTO promotion_identity_evidence
		(evidence_version,user_id,email,email_verified,auth_updated_at,observed_at)
		VALUES($1,$2,$3,true,now()-interval '2 hours',now()-interval '2 hours')`, version, f.actor, "original"+f.actor.String()+"@gmail.com"); err != nil {
		t.Fatal(err)
	}
	var generation time.Time
	if err := testPool.QueryRow(ctx, `UPDATE team_billing_account
		SET stripe_checkout_identity_evidence_version=$2,checkout_initializing_at=now()-interval '2 hours',
		stripe_checkout_actor_claimed_at=now()-interval '2 hours'
		WHERE team_id=$1 RETURNING checkout_initializing_at`, f.team, version).Scan(&generation); err != nil {
		t.Fatal(err)
	}
	f.stripe.mu.Lock()
	for key, params := range f.stripe.requests {
		params.Metadata["checkout_generation"] = generation.UTC().Format(time.RFC3339Nano)
		expires := generation.Add(24*time.Hour - time.Minute)
		params.ExpiresAt = &expires
		f.stripe.requests[key] = params
	}
	f.stripe.mu.Unlock()
	if _, err := testPool.Exec(ctx, `UPDATE promotion_identity_current SET evidence_version=$2 WHERE user_id=$1`, f.actor, version); err != nil {
		t.Fatal(err)
	}
	_, err := testPool.Exec(ctx, `SELECT capture_promotion_identity_evidence($1)`, f.actor)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "55000" {
		t.Fatalf("fresh creation must reject stale evidence: %v", err)
	}
	f.assertRecovered(t, `{}`)
	if _, err := testPool.Exec(ctx, `DELETE FROM promotion_identity_current WHERE user_id=$1`, f.actor); err != nil {
		t.Fatal(err)
	}
	f.assertRecovered(t, "")
	f.assertRecovered(t, fmt.Sprintf(`{"checkout_generation":%q}`, generation.UTC().Format(time.RFC3339Nano)))
	f.stripe.mu.Lock()
	defer f.stripe.mu.Unlock()
	if len(f.stripe.retrievedIDs) != 3 || len(f.stripe.sessions) != 1 {
		t.Fatalf("recovery did not use GET-only for the existing session: gets=%v sessions=%d", f.stripe.retrievedIDs, len(f.stripe.sessions))
	}
}

func TestIntegration_CheckoutRecoveryAllowsKnownUnverifiedPin(t *testing.T) {
	f := newCheckoutRecoveryFixture(t)
	version := uuid.New()
	if _, err := testPool.Exec(context.Background(), `INSERT INTO promotion_identity_evidence
		(evidence_version,user_id,email,email_verified,auth_updated_at,observed_at)
		VALUES($1,$2,'unverified@example.com',false,now(),now());`, version, f.actor); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(context.Background(), `UPDATE team_billing_account SET stripe_checkout_identity_evidence_version=$2 WHERE team_id=$1`, f.team, version); err != nil {
		t.Fatal(err)
	}
	f.assertRecovered(t, `{}`)
}

func TestIntegration_CheckoutRecoveryRejectsInvalidPins(t *testing.T) {
	for _, missing := range []bool{true, false} {
		t.Run(fmt.Sprintf("missing_%t", missing), func(t *testing.T) {
			f := newCheckoutRecoveryFixture(t)
			var version any
			if !missing {
				other := canonicalStripeActor(t, uuid.NewString()+"@example.com", true)
				var evidence uuid.UUID
				if err := testPool.QueryRow(context.Background(), `SELECT evidence_version FROM promotion_identity_current WHERE user_id=$1`, other).Scan(&evidence); err != nil {
					t.Fatal(err)
				}
				version = evidence
			}
			if _, err := testPool.Exec(context.Background(), `UPDATE team_billing_account SET stripe_checkout_identity_evidence_version=$2 WHERE team_id=$1`, f.team, version); err != nil {
				t.Fatal(err)
			}
			before, counts := f.snapshot(t), f.stripe.createCounts()
			w := do(f.router, "POST", checkoutRecoveryPath, f.key, `{}`)
			assertCheckoutRecoveryError(t, w, http.StatusServiceUnavailable, "service_unavailable")
			f.assertUnchanged(t, before, counts)
		})
	}
}

func TestIntegration_CheckoutRecoveryEnforcementOffAllowsLegacyNullPin(t *testing.T) {
	ctx := context.Background()
	f := newCheckoutRecoveryFixture(t)
	var enabled bool
	var enabledAt pgtype.Timestamptz
	var readiness *string
	if err := testPool.QueryRow(ctx, `SELECT enabled,enabled_at,readiness_reference FROM promotion_identity_enforcement WHERE singleton`).Scan(&enabled, &enabledAt, &readiness); err != nil {
		t.Fatal(err)
	}
	setGate := func(enabled bool, at pgtype.Timestamptz, reference *string) {
		t.Helper()
		tx, err := testPool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err := tx.Exec(ctx, `ALTER TABLE promotion_identity_enforcement DISABLE TRIGGER promotion_identity_enforcement_irreversible`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `UPDATE promotion_identity_enforcement SET enabled=$1,enabled_at=$2,readiness_reference=$3`, enabled, at, reference); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `ALTER TABLE promotion_identity_enforcement ENABLE TRIGGER promotion_identity_enforcement_irreversible`); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { setGate(enabled, enabledAt, readiness) })
	setGate(false, pgtype.Timestamptz{}, nil)
	if _, err := testPool.Exec(ctx, `UPDATE team_billing_account SET stripe_checkout_identity_evidence_version=NULL WHERE team_id=$1`, f.team); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `DELETE FROM promotion_identity_current WHERE user_id=$1`, f.actor); err != nil {
		t.Fatal(err)
	}
	f.assertRecovered(t, `{}`)
}

func TestIntegration_CheckoutRecoveryRejectsActorGenerationAndMalformedInput(t *testing.T) {
	f := newCheckoutRecoveryFixture(t)
	otherKey := seedKeyForExistingTeamWithRole(t, f.team, "team_owner")
	viewer := seedKeyForExistingTeamWithRole(t, f.team, "viewer")
	for _, tc := range []struct {
		name, key, body, code string
		status                int
	}{
		{"other_actor", otherKey, `{}`, "checkout_recovery_unavailable", http.StatusConflict},
		{"other_generation", f.key, `{"checkout_generation":"2000-01-01T00:00:00Z"}`, "checkout_recovery_unavailable", http.StatusConflict},
		{"unauthenticated", "", `{}`, "auth_failed", http.StatusUnauthorized},
		{"viewer", viewer, `{}`, "forbidden", http.StatusForbidden},
		{"invalid_generation", f.key, `{"checkout_generation":"not-a-timestamp"}`, "bad_request", http.StatusBadRequest},
		{"unknown_field", f.key, `{"recovery_only":true}`, "bad_request", http.StatusBadRequest},
		{"wrong_type", f.key, `{"checkout_generation":123}`, "bad_request", http.StatusBadRequest},
		{"multiple_objects", f.key, `{} {}`, "bad_request", http.StatusBadRequest},
		{"array", f.key, `[]`, "bad_request", http.StatusBadRequest},
		{"null", f.key, `null`, "bad_request", http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before, counts := f.snapshot(t), f.stripe.createCounts()
			w := do(f.router, "POST", checkoutRecoveryPath, tc.key, tc.body)
			assertCheckoutRecoveryError(t, w, tc.status, tc.code)
			f.assertUnchanged(t, before, counts)
		})
	}
	f.stripe.mu.Lock()
	defer f.stripe.mu.Unlock()
	if len(f.stripe.retrievedIDs) != 0 {
		t.Fatalf("invalid requests reached provider: %v", f.stripe.retrievedIDs)
	}
}

func TestIntegration_CheckoutRecoveryPreservesBillingRolloutGate(t *testing.T) {
	f := newCheckoutRecoveryFixture(t)
	if _, err := testPool.Exec(context.Background(), `UPDATE team_feature_flag SET enabled=false WHERE team_id=$1 AND key='billing_export_enabled'`, f.team); err != nil {
		t.Fatal(err)
	}
	before, counts := f.snapshot(t), f.stripe.createCounts()
	w := do(f.router, "POST", checkoutRecoveryPath, f.key, `{}`)
	assertCheckoutRecoveryError(t, w, http.StatusForbidden, "forbidden")
	f.assertUnchanged(t, before, counts)
	if len(f.stripe.retrievedIDs) != 0 {
		t.Fatal("shadow billing recovery reached Stripe")
	}
}

func TestIntegration_CheckoutRecoveryProviderFailuresDoNotCreate(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		status     int
		err        error
		mutate     func(*api.StripeRetrievedCheckoutSession)
	}{
		{name: "missing", code: "checkout_recovery_unavailable", status: http.StatusConflict, err: api.ErrStripeCheckoutSessionNotFound},
		{name: "timeout", code: "bad_gateway", status: http.StatusBadGateway, err: context.DeadlineExceeded},
		{name: "completed", mutate: func(s *api.StripeRetrievedCheckoutSession) { s.Status = "complete" }},
		{name: "expired", mutate: func(s *api.StripeRetrievedCheckoutSession) { s.Status = "expired" }},
		{name: "past_expiry", mutate: func(s *api.StripeRetrievedCheckoutSession) { s.ExpiresAt = time.Now().Add(-time.Minute).Unix() }},
		{name: "other_customer", mutate: func(s *api.StripeRetrievedCheckoutSession) { s.CustomerID = "cus_other" }},
		{name: "other_team", mutate: func(s *api.StripeRetrievedCheckoutSession) { s.ClientReferenceID = uuid.NewString() }},
		{name: "other_actor", mutate: func(s *api.StripeRetrievedCheckoutSession) { s.Metadata["activation_user_id"] = uuid.NewString() }},
		{name: "other_generation", mutate: func(s *api.StripeRetrievedCheckoutSession) {
			s.Metadata["checkout_generation"] = "2000-01-01T00:00:00Z"
		}},
		{name: "missing_generation", mutate: func(s *api.StripeRetrievedCheckoutSession) { delete(s.Metadata, "checkout_generation") }},
		{name: "other_session", mutate: func(s *api.StripeRetrievedCheckoutSession) { s.ID = "cs_other" }},
		{name: "payment_mode", mutate: func(s *api.StripeRetrievedCheckoutSession) { s.Mode = "payment" }},
		{name: "missing_url", mutate: func(s *api.StripeRetrievedCheckoutSession) { s.URL = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCheckoutRecoveryFixture(t)
			f.stripe.retrieveErr, f.stripe.mutate = tc.err, tc.mutate
			before, counts := f.snapshot(t), f.stripe.createCounts()
			w := do(f.router, "POST", checkoutRecoveryPath, f.key, `{}`)
			status, code := tc.status, tc.code
			if status == 0 {
				status, code = http.StatusConflict, "checkout_recovery_unavailable"
			}
			assertCheckoutRecoveryError(t, w, status, code)
			f.assertUnchanged(t, before, counts)
		})
	}
}

func TestIntegration_CheckoutRecoveryUnavailableDoesNotStartGeneration(t *testing.T) {
	for _, ambiguous := range []bool{false, true} {
		t.Run(fmt.Sprintf("ambiguous_%t", ambiguous), func(t *testing.T) {
			team, key, actor := seedTeamAndKeyWithRole(t, "team_owner")
			enableBillingExportForCheckoutActorTest(t, team)
			stripe := &recoveryCheckoutStripeClient{idempotentCheckoutStripeClient: &idempotentCheckoutStripeClient{
				fakeStripeClient: &fakeStripeClient{nextCustomerID: "cus_unknown_" + team.String()},
				failures:         map[int]error{1: context.DeadlineExceeded},
			}}
			f := checkoutRecoveryFixture{team: team, actor: actor, key: key, stripe: stripe, router: newBillingRouter(t, stripe)}
			if ambiguous {
				if w := do(f.router, "POST", "/stripe/checkout-session", key, checkoutRegressionBody); w.Code != http.StatusBadGateway {
					t.Fatalf("ambiguous initial checkout: %d %s", w.Code, w.Body.String())
				}
			} else if _, err := testPool.Exec(context.Background(), `DELETE FROM team_billing_account WHERE team_id=$1`, team); err != nil {
				t.Fatal(err)
			}
			before, counts := f.snapshot(t), stripe.createCounts()
			w := do(f.router, "POST", checkoutRecoveryPath, key, `{}`)
			assertCheckoutRecoveryError(t, w, http.StatusConflict, "checkout_recovery_unavailable")
			f.assertUnchanged(t, before, counts)
			if len(stripe.retrievedIDs) != 0 {
				t.Fatalf("missing persisted session reached provider: %v", stripe.retrievedIDs)
			}
		})
	}
}

func (f checkoutRecoveryFixture) webhook(t *testing.T, eventType string) {
	t.Helper()
	account, err := testQueries.GetTeamBillingAccount(context.Background(), f.team)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	subscription := ""
	if eventType == "checkout.session.completed" {
		subscription = "sub_completed_" + f.team.String()
	}
	payload := checkoutExpiryWebhookPayload(t, "evt_recovery_"+uuid.NewString(), eventType, derefString(account.CheckoutSessionID), f.team.String(), derefString(account.StripeCustomerID), subscription, now)
	req := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Stripe-Signature", stripeSignature(t, payload, now))
	if w := doRequest(f.router, req); w.Code != http.StatusOK {
		t.Fatalf("concurrent %s: %d %s", eventType, w.Code, w.Body.String())
	}
}

func (f checkoutRecoveryFixture) blockRetrieval(t *testing.T) (<-chan struct{}, func()) {
	t.Helper()
	arrived, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	f.stripe.afterGet = func(ctx context.Context) error {
		close(arrived)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return arrived, unblock
}

func waitCheckoutRecoveryResult(t *testing.T, result <-chan *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	t.Helper()
	select {
	case w := <-result:
		return w
	case <-time.After(10 * time.Second):
		t.Fatal("recovery did not finish")
		return nil
	}
}

func (f checkoutRecoveryFixture) startBlockedRecovery(t *testing.T) (<-chan *httptest.ResponseRecorder, func()) {
	t.Helper()
	arrived, unblock := f.blockRetrieval(t)
	result := make(chan *httptest.ResponseRecorder, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		result <- do(f.router, "POST", checkoutRecoveryPath, f.key, `{}`)
	}()
	t.Cleanup(func() {
		unblock()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("recovery request remained active after test cleanup")
		}
	})
	select {
	case <-arrived:
	case w := <-result:
		t.Fatalf("recovery returned before provider GET: %d %s", w.Code, w.Body.String())
	case <-time.After(10 * time.Second):
		t.Fatal("recovery did not reach provider GET")
	}
	return result, unblock
}

func TestIntegration_CheckoutRecoveryCannotCrossConcurrentTransitions(t *testing.T) {
	for _, transition := range []string{"completed", "abandoned", "expired", "replaced", "actor_changed", "customer_changed", "session_changed", "evidence_changed"} {
		t.Run(transition, func(t *testing.T) {
			ctx := context.Background()
			f := newCheckoutRecoveryFixture(t)
			account, err := testQueries.GetTeamBillingAccount(ctx, f.team)
			if err != nil {
				t.Fatal(err)
			}
			result, unblock := f.startBlockedRecovery(t)
			switch transition {
			case "completed":
				f.webhook(t, "checkout.session.completed")
			case "expired":
				f.webhook(t, "checkout.session.expired")
			case "abandoned", "replaced":
				if err := testQueries.AbortTeamBillingCheckout(ctx, db.AbortTeamBillingCheckoutParams{TeamID: f.team, LeaseStartedAt: account.CheckoutInitializingAt}); err != nil {
					t.Fatal(err)
				}
				if transition == "replaced" {
					if w := do(f.router, "POST", "/stripe/checkout-session", f.key, checkoutRegressionBody); w.Code != http.StatusOK {
						t.Fatalf("replacement checkout: %d %s", w.Code, w.Body.String())
					}
				}
			case "actor_changed":
				other := canonicalStripeActor(t, uuid.NewString()+"@example.com", true)
				_, err = testPool.Exec(ctx, `UPDATE team_billing_account SET stripe_checkout_actor_id=$2 WHERE team_id=$1`, f.team, other)
			case "customer_changed":
				_, err = testPool.Exec(ctx, `UPDATE team_billing_account SET stripe_customer_id=$2 WHERE team_id=$1`, f.team, "cus_replaced_"+f.team.String())
			case "session_changed":
				_, err = testPool.Exec(ctx, `UPDATE team_billing_account SET checkout_session_id='cs_replaced' WHERE team_id=$1`, f.team)
			case "evidence_changed":
				var version uuid.UUID
				err = testPool.QueryRow(ctx, `SELECT evidence_version FROM upsert_profile_with_promotion_identity($1,$2,true,clock_timestamp(),clock_timestamp())`, f.actor, uuid.NewString()+"@example.com").Scan(&version)
				if err == nil {
					_, err = testPool.Exec(ctx, `UPDATE team_billing_account SET stripe_checkout_identity_evidence_version=$2 WHERE team_id=$1`, f.team, version)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			before, counts := f.snapshot(t), f.stripe.createCounts()
			unblock()
			w := waitCheckoutRecoveryResult(t, result)
			assertCheckoutRecoveryError(t, w, http.StatusConflict, "checkout_recovery_unavailable")
			f.assertUnchanged(t, before, counts)
		})
	}
}

func TestIntegration_CheckoutRecoveryRevalidatesAfterAccountLockWait(t *testing.T) {
	ctx := context.Background()
	f := newCheckoutRecoveryFixture(t)
	result, unblock := f.startBlockedRecovery(t)
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	var lockerPID int
	if err := tx.QueryRow(ctx, `SELECT pg_backend_pid() FROM team_billing_account WHERE team_id=$1 FOR UPDATE`, f.team).Scan(&lockerPID); err != nil {
		t.Fatal(err)
	}
	unblock()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var blocked bool
		if err := testPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))`, lockerPID).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		select {
		case w := <-result:
			t.Fatalf("recovery bypassed the account lock: %d %s", w.Code, w.Body.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("recovery never waited for the authoritative account lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := tx.Exec(ctx, `UPDATE team_billing_account SET checkout_completed_at=now() WHERE team_id=$1`, f.team); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	before, counts := f.snapshot(t), f.stripe.createCounts()
	w := waitCheckoutRecoveryResult(t, result)
	assertCheckoutRecoveryError(t, w, http.StatusConflict, "checkout_recovery_unavailable")
	f.assertUnchanged(t, before, counts)
}
