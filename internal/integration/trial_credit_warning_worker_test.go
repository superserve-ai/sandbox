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
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/db"
)

func seedWarningWorkerTeam(t *testing.T) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	team := mustCreateTeam(t, ctx, "warning-worker-"+uuid.NewString()[:8])
	sandbox := seedPrivatePreviewSandbox(t, team, testDefaultHostID, "warning-worker")
	// Keep positive authoritative credit with enough recent spend to warn.
	for _, sql := range []string{
		`UPDATE team_credit_grant SET amount_usd = 1, remaining_usd = 1, created_at = now()-interval '3 hours' WHERE team_id = $1 AND reason = 'signup trial credit'`,
		`INSERT INTO sandbox_compute_billing_interval (sandbox_id, team_id, vcpu_count, memory_mib, started_at, ended_at, end_reason) VALUES ($2,$1,2,1024,now()-interval '2 hours',now()-interval '1 minute','paused')`,
	} {
		var err error
		if strings.Contains(sql, "$2") {
			_, err = testPool.Exec(ctx, sql, team, sandbox)
		} else {
			_, err = testPool.Exec(ctx, sql, team)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	return team
}

func warningStatus(t *testing.T, team uuid.UUID) string {
	t.Helper()
	var status string
	var sent bool
	if err := testPool.QueryRow(context.Background(), `SELECT status, sent_at IS NOT NULL FROM trial_credit_warning_state WHERE team_id=$1`, team).Scan(&status, &sent); err != nil {
		if err == pgx.ErrNoRows {
			return "absent"
		}
		t.Fatal(err)
	}
	if sent != (status == "sent") {
		t.Errorf("warning status = %s, sent_at populated = %t", status, sent)
	}
	return status
}

func TestTrialWarningWorkerProviderRetryAndCompletion(t *testing.T) {
	ctx := context.Background()
	team := seedWarningWorkerTeam(t)
	owner := seedRBACProfile(t)
	seedMembership(t, ctx, team, owner)
	seedTeamRoleAssignment(t, ctx, owner, mustRoleID(t, ctx, "team_owner"), team)
	balance, err := testQueries.GetTeamTrialBalance(ctx, team)
	if err != nil {
		t.Fatal(err)
	}
	remaining, err := balance.RemainingUsd.Float64Value()
	if err != nil || !remaining.Valid || !balance.Eligible {
		t.Fatalf("invalid fixture balance: %+v, %v", balance, err)
	}
	teamRow, err := testQueries.GetTeam(ctx, team)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	responses := []int{http.StatusTooManyRequests, http.StatusServiceUnavailable, http.StatusAccepted}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if got := warningStatus(t, team); got != "claimed" {
			t.Errorf("status at submission = %s, want claimed", got)
		}
		var body struct{ From, To, Subject, HTML string }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		for _, want := range []string{teamRow.Name, fmt.Sprintf("$%.2f", remaining.Float64), "within the next 24 hours"} {
			if !strings.Contains(body.HTML, want) {
				t.Errorf("email missing %q: %s", want, body.HTML)
			}
		}
		if body.To != "user-"+owner.String()[:8]+"@example.com" || body.From != "team@example.com" || body.Subject == "" {
			t.Errorf("unexpected envelope: %+v", body)
		}
		if r.Header.Get("Authorization") != "Bearer test-key" || r.Header.Get("Idempotency-Key") == "" {
			t.Error("missing provider authentication or idempotency key")
		}
		if calls > len(responses) {
			t.Error("unexpected provider call after acceptance")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(responses[calls-1])
	}))
	defer server.Close()
	h := &api.Handlers{DB: testQueries, TrialWarningSender: api.NewTrialCreditWarningSenderForTest(testQueries, server.URL, server.Client())}
	for _, rejection := range responses[:2] {
		api.ProcessTrialCreditWarningForTest(h, ctx, team)
		if got := warningStatus(t, team); got != "pending" {
			t.Fatalf("status after provider rejection %d = %s, want pending", rejection, got)
		}
	}
	api.ProcessTrialCreditWarningForTest(h, ctx, team)
	if got := warningStatus(t, team); got != "sent" {
		t.Fatalf("status after acceptance = %s", got)
	}
	api.ProcessTrialCreditWarningForTest(h, ctx, team)
	if calls != len(responses) {
		t.Fatalf("provider calls = %d, want %d (two rejections and one acceptance)", calls, len(responses))
	}
}

func TestTrialWarningWorkerPartialDeliveryRetry(t *testing.T) {
	ctx := context.Background()
	team := seedWarningWorkerTeam(t)
	for i := 0; i < 3; i++ {
		owner := seedRBACProfile(t)
		seedMembership(t, ctx, team, owner)
		seedTeamRoleAssignment(t, ctx, owner, mustRoleID(t, ctx, "team_owner"), team)
	}
	calls := 0
	accepted := map[string]int{}
	var firstRecipient, firstKey, retryKey string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var body struct{ To string }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if calls == 1 {
			firstRecipient, firstKey = body.To, r.Header.Get("Idempotency-Key")
		}
		if calls == 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if calls == 3 {
			retryKey = r.Header.Get("Idempotency-Key")
		}
		accepted[body.To]++
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	newHandler := func() *api.Handlers {
		return &api.Handlers{DB: testQueries, TrialWarningSender: api.NewTrialCreditWarningSenderForTest(testQueries, server.URL, server.Client())}
	}
	api.ProcessTrialCreditWarningForTest(newHandler(), ctx, team)
	if got := warningStatus(t, team); got != "pending" {
		t.Fatalf("partial delivery status = %s, want pending", got)
	}
	delivered, err := testQueries.ListTrialCreditWarningDeliveries(ctx, team)
	if err != nil || len(delivered) != 1 || delivered[0] != firstRecipient {
		t.Fatalf("persisted recipients = %v, error = %v", delivered, err)
	}
	var releasedToken pgtype.UUID
	if err := testPool.QueryRow(ctx, `SELECT claim_token FROM trial_credit_warning_state WHERE team_id=$1`, team).Scan(&releasedToken); err != nil {
		t.Fatal(err)
	}
	// A new sender and claim must retain progress from the earlier attempt.
	api.ProcessTrialCreditWarningForTest(newHandler(), ctx, team)
	if got := warningStatus(t, team); got != "sent" {
		t.Fatalf("retry status = %s, want sent", got)
	}
	var completedToken pgtype.UUID
	if err := testPool.QueryRow(ctx, `SELECT claim_token FROM trial_credit_warning_state WHERE team_id=$1`, team).Scan(&completedToken); err != nil {
		t.Fatal(err)
	}
	if !releasedToken.Valid || !completedToken.Valid || releasedToken == completedToken {
		t.Fatal("retry must succeed with a different durable claim token")
	}
	api.ProcessTrialCreditWarningForTest(newHandler(), ctx, team)
	if calls != 4 || len(accepted) != 3 || firstKey == "" || retryKey == "" || firstKey == retryKey {
		t.Fatalf("calls=%d accepted=%v first key=%q retry key=%q", calls, accepted, firstKey, retryKey)
	}
	for recipient, count := range accepted {
		if count != 1 {
			t.Errorf("recipient %s accepted %d messages, want 1", recipient, count)
		}
	}
	delivered, err = testQueries.ListTrialCreditWarningDeliveries(ctx, team)
	if err != nil || len(delivered) != 3 {
		t.Fatalf("completed recipients = %v, error = %v", delivered, err)
	}
}

func TestTrialWarningWorkerDeliveryPersistenceFailureIsNotRetried(t *testing.T) {
	ctx := context.Background()
	team := seedWarningWorkerTeam(t)
	owner := seedRBACProfile(t)
	seedMembership(t, ctx, team, owner)
	seedTeamRoleAssignment(t, ctx, owner, mustRoleID(t, ctx, "team_owner"), team)
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	q := db.New(warningDeliveryWriteFailure{testPool})
	h := &api.Handlers{DB: q, TrialWarningSender: api.NewTrialCreditWarningSenderForTest(q, server.URL, server.Client())}
	api.ProcessTrialCreditWarningForTest(h, ctx, team)
	if got := warningStatus(t, team); got != "unknown" {
		t.Fatalf("unrecorded acceptance status = %s, want unknown", got)
	}
	// Restore database writes before retrying to prove the durable team state
	// suppresses duplication after the original persistence failure is gone.
	h = &api.Handlers{DB: testQueries, TrialWarningSender: api.NewTrialCreditWarningSenderForTest(testQueries, server.URL, server.Client())}
	api.ProcessTrialCreditWarningForTest(h, ctx, team)
	if calls != 1 {
		t.Fatalf("unrecorded acceptance retried: %d calls", calls)
	}
}

type warningDeliveryWriteFailure struct{ *pgxpool.Pool }

func (q warningDeliveryWriteFailure) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if strings.Contains(sql, "-- name: RecordTrialCreditWarningDelivery") {
		return pgconn.CommandTag{}, fmt.Errorf("delivery persistence unavailable")
	}
	return q.Pool.Exec(ctx, sql, args...)
}

type warningSenderFunc func(context.Context, uuid.UUID, float64) error

func (f warningSenderFunc) SendTrialCreditWarning(ctx context.Context, team uuid.UUID, remaining float64) error {
	return f(ctx, team, remaining)
}

// Interpose only after the real atomic claim, so the next balance query must
// observe a balance or lifecycle change that happened after forecasting.
type warningClaimHook struct {
	*pgxpool.Pool
	afterClaim func()
}

func (q warningClaimHook) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	row := q.Pool.QueryRow(ctx, sql, args...)
	if strings.Contains(sql, "-- name: ClaimTrialCreditWarning") {
		return warningClaimRow{Row: row, after: q.afterClaim}
	}
	return row
}

type warningClaimRow struct {
	pgx.Row
	after func()
}

func (r warningClaimRow) Scan(dest ...any) error {
	if err := r.Row.Scan(dest...); err != nil {
		return err
	}
	r.after()
	return nil
}

func TestTrialWarningWorkerRechecksLifecycleAfterClaim(t *testing.T) {
	for _, tc := range []struct{ name, sql string }{
		{"missing", `DELETE FROM team_credit_grant WHERE team_id=$1`},
		{"expired", `UPDATE team_credit_grant SET expires_at=now()-interval '1 second' WHERE team_id=$1`},
		{"exhausted", `UPDATE team_credit_grant SET amount_usd=0.000001, remaining_usd=0 WHERE team_id=$1`},
		{"stripe", `INSERT INTO team_billing_account(team_id, trial_ended_at) VALUES($1,now()) ON CONFLICT(team_id) DO UPDATE SET trial_ended_at=now()`},
		{"topped_up", `UPDATE team_credit_grant SET amount_usd=100, remaining_usd=100 WHERE team_id=$1`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			team := seedWarningWorkerTeam(t)
			changed := false
			q := db.New(warningClaimHook{Pool: testPool, afterClaim: func() {
				changed = true
				if _, err := testPool.Exec(context.Background(), tc.sql, team); err != nil {
					t.Fatal(err)
				}
			}})
			calls := 0
			h := &api.Handlers{DB: q, TrialWarningSender: warningSenderFunc(func(context.Context, uuid.UUID, float64) error { calls++; return nil })}
			api.ProcessTrialCreditWarningForTest(h, context.Background(), team)
			if !changed {
				t.Fatal("fixture did not reach the claim")
			}
			if calls != 0 {
				t.Fatalf("sent %d warnings after eligibility changed", calls)
			}
			if got := warningStatus(t, team); got != "pending" {
				t.Fatalf("suppressed claim status = %s", got)
			}
			if tc.name == "topped_up" {
				if _, err := testPool.Exec(context.Background(), `UPDATE team_credit_grant SET amount_usd=1, remaining_usd=1 WHERE team_id=$1`, team); err != nil {
					t.Fatal(err)
				}
				h.DB = testQueries
				api.ProcessTrialCreditWarningForTest(h, context.Background(), team)
				if got := warningStatus(t, team); calls != 1 || got != "sent" {
					t.Fatalf("later eligible pass: calls=%d status=%s, want 1/sent", calls, got)
				}
			}
		})
	}
}

func TestTrialWarningDispatchDoesNotBlockEligibilityRefresh(t *testing.T) {
	team := seedWarningWorkerTeam(t)
	entered, release := make(chan struct{}), make(chan struct{})
	h := &api.Handlers{DB: db.New(warningDispatchScope{Pool: testPool, team: team}), TrialWarningSender: warningSenderFunc(func(ctx context.Context, id uuid.UUID, _ float64) error {
		if id == team {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return fmt.Errorf("provider unavailable")
	})}
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer h.WaitAsyncBookkeeping()
	defer unblock()
	done := make(chan struct{})
	go func() { api.RefreshActiveTrialEligibilityForTest(h, context.Background()); close(done) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("warning never reached provider")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("eligibility refresh blocked on provider")
	}
	if got := warningStatus(t, team); got != "claimed" {
		t.Fatalf("blocked send status = %s", got)
	}
	var eligible bool
	if err := testPool.QueryRow(context.Background(), `SELECT eligible FROM team_trial_eligibility_cache WHERE team_id=$1`, team).Scan(&eligible); err != nil {
		t.Fatal(err)
	}
	if !eligible {
		t.Fatal("warning processing changed trial eligibility")
	}
	unblock()
	h.WaitAsyncBookkeeping()
	if got := warningStatus(t, team); got != "pending" {
		t.Fatalf("failed background send status = %s", got)
	}
	if err := testPool.QueryRow(context.Background(), `SELECT eligible FROM team_trial_eligibility_cache WHERE team_id=$1`, team).Scan(&eligible); err != nil {
		t.Fatal(err)
	}
	if !eligible {
		t.Fatal("provider failure changed trial eligibility")
	}
}

func TestTrialWarningWorkerUnknownProviderOutcomeIsNotRetried(t *testing.T) {
	team := seedWarningWorkerTeam(t)
	owner := seedRBACProfile(t)
	ctx := context.Background()
	seedMembership(t, ctx, team, owner)
	seedTeamRoleAssignment(t, ctx, owner, mustRoleID(t, ctx, "team_owner"), team)
	calls := 0
	client := &http.Client{Transport: warningTransportFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, fmt.Errorf("connection lost after submission")
	})}
	h := &api.Handlers{DB: testQueries, TrialWarningSender: api.NewTrialCreditWarningSenderForTest(testQueries, "https://example.com/emails", client)}
	api.ProcessTrialCreditWarningForTest(h, ctx, team)
	if got := warningStatus(t, team); got != "unknown" {
		t.Fatalf("ambiguous outcome status = %s", got)
	}
	api.ProcessTrialCreditWarningForTest(h, ctx, team)
	if calls != 1 {
		t.Fatalf("ambiguous delivery retried: %d calls", calls)
	}
}

type warningTransportFunc func(*http.Request) (*http.Response, error)

func (f warningTransportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Keep the reconciliation test independent of active sandboxes left by other
// harness tests, while executing the real discovery and eligibility queries.
type warningDispatchScope struct {
	*pgxpool.Pool
	team uuid.UUID
}

func (q warningDispatchScope) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	if strings.Contains(sql, "-- name: ListTeamsWithActiveTrialSandboxes") || strings.Contains(sql, "-- name: ListTeamsWithActiveIneligibleSandboxes") {
		sql = strings.ReplaceAll(sql, "WHERE s.destroyed_at IS NULL", "WHERE s.team_id = '"+q.team.String()+"'::uuid AND s.destroyed_at IS NULL")
	}
	return q.Pool.Query(ctx, sql, args...)
}

func TestTrialWarningWorkerPermanentRejectionDoesNotBlockRecipients(t *testing.T) {
	for _, allRejected := range []bool{false, true} {
		t.Run(fmt.Sprintf("all_rejected=%t", allRejected), func(t *testing.T) {
			ctx := context.Background()
			team := seedWarningWorkerTeam(t)
			for i := 0; i < 3; i++ {
				owner := seedRBACProfile(t)
				seedMembership(t, ctx, team, owner)
				seedTeamRoleAssignment(t, ctx, owner, mustRoleID(t, ctx, "team_owner"), team)
			}
			calls := map[string]int{}
			total := 0
			var rejectedRecipient string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body struct{ To string }
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				total++
				calls[body.To]++
				if total == 1 {
					rejectedRecipient = body.To
				}
				if allRejected || body.To == rejectedRecipient {
					w.WriteHeader(http.StatusUnprocessableEntity)
					_, _ = fmt.Fprint(w, `{"name":"validation_error"}`)
					return
				}
				if total == 3 {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				w.WriteHeader(http.StatusAccepted)
			}))
			defer server.Close()
			run := func() {
				h := &api.Handlers{DB: testQueries, TrialWarningSender: api.NewTrialCreditWarningSenderForTest(testQueries, server.URL, server.Client())}
				api.ProcessTrialCreditWarningForTest(h, ctx, team)
			}
			run()
			wantStatus, wantSent, wantRejected := "pending", 1, 1
			if allRejected {
				wantStatus, wantSent, wantRejected = "suppressed", 0, 3
			}
			if total != 3 || warningStatus(t, team) != wantStatus {
				t.Fatalf("first pass: calls=%d status=%s", total, warningStatus(t, team))
			}
			assertOutcomes := func(sentCount, rejectedCount int) {
				t.Helper()
				sent, err := testQueries.ListTrialCreditWarningDeliveries(ctx, team)
				if err != nil || len(sent) != sentCount {
					t.Fatalf("sent=%v err=%v, want %d", sent, err, sentCount)
				}
				rejected, err := testQueries.ListTrialCreditWarningRejections(ctx, team)
				if err != nil || len(rejected) != rejectedCount {
					t.Fatalf("rejected=%v err=%v, want %d", rejected, err, rejectedCount)
				}
				for _, recipient := range sent {
					if recipient == rejectedRecipient {
						t.Fatal("rejected recipient marked sent")
					}
				}
			}
			assertOutcomes(wantSent, wantRejected)
			run()
			if got := warningStatus(t, team); got != "suppressed" {
				t.Fatalf("final status=%s, want suppressed", got)
			}
			wantCalls := 3
			if !allRejected {
				wantCalls, wantSent = 4, 2
			}
			run()
			if total != wantCalls || calls[rejectedRecipient] != 1 {
				t.Fatalf("unexpected retries: total=%d by recipient=%v", total, calls)
			}
			assertOutcomes(wantSent, wantRejected)
		})
	}
}
