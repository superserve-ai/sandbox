package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/superserve-ai/sandbox/internal/db"
)

func TestTrialCreditWarningAdmissionReservesDatabaseCapacity(t *testing.T) {
	for _, tc := range []struct {
		name          string
		max, acquired int32
		want          int32
	}{
		{"unknown capacity", 0, 0, 0},
		{"single connection", 1, 0, 0},
		{"two connections", 2, 0, 1},
		{"three connections", 3, 0, 1},
		{"four connections", 4, 0, 2},
		{"large pool", 64, 0, 2},
		{"saturated pool", 4, 4, 0},
		{"last spare connection", 4, 3, 0},
		{"two spare connections", 4, 2, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var admission trialCreditWarningAdmission
			var admitted atomic.Int32
			var wg sync.WaitGroup
			for i := 0; i < 32; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if admission.tryAcquire(tc.max, tc.acquired) {
						admitted.Add(1)
					}
				}()
			}
			wg.Wait()
			if got := admitted.Load(); got != tc.want {
				t.Fatalf("admitted %d jobs, want %d", got, tc.want)
			}
			for i := int32(0); i < tc.want; i++ {
				admission.release()
			}
			if got := admission.tryAcquire(tc.max, tc.acquired); got != (tc.want > 0) {
				t.Fatalf("admission after release = %v", got)
			}
		})
	}
}

func TestTrialCreditWarningWorkerUsesPoolCapacity(t *testing.T) {
	for _, maxConns := range []int32{0, 1, 2} {
		t.Run(fmt.Sprint(maxConns), func(t *testing.T) {
			reads := 0
			h := &Handlers{DB: db.New(&mockDBTX{queryRowFn: func(context.Context, string, ...any) pgx.Row {
				reads++
				return &mockRow{scanFn: func(...any) error { return pgx.ErrNoRows }}
			}}), TrialWarningSender: &recordingTrialWarningSender{}}
			if maxConns > 0 {
				config, err := pgxpool.ParseConfig("postgres://localhost/example?sslmode=disable")
				if err != nil {
					t.Fatal(err)
				}
				config.MaxConns = maxConns
				config.MinConns = 0
				h.Pool, err = pgxpool.NewWithConfig(context.Background(), config)
				if err != nil {
					t.Fatal(err)
				}
				defer h.Pool.Close()
			}
			for i := 0; i < 2; i++ {
				h.processTrialCreditWarningWithCapacity(context.Background(), uuid.New())
			}
			want := 0
			if maxConns == 2 {
				want = 2 // A failed query must release admission for the next job.
			}
			if reads != want {
				t.Fatalf("database reads = %d, want %d", reads, want)
			}
		})
	}
}

func TestTrialCreditWarningWithoutSenderSkipsDatabase(t *testing.T) {
	// A query through this unconnected database would panic.
	h := &Handlers{DB: db.New(nil)}
	h.processTrialCreditWarning(context.Background(), uuid.New())
}

func TestTrialCreditWarningCancellationReleasesClaimForRetry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	teamID := uuid.New()
	claimToken := pgtype.UUID{Bytes: uuid.New(), Valid: true}
	status := "pending"
	balanceReads, releases := 0, 0
	now := time.Now()
	queries := &mockDBTX{
		queryRowFn: func(queryCtx context.Context, sql string, args ...any) pgx.Row {
			return &mockRow{scanFn: func(dest ...any) error {
				switch {
				case strings.Contains(sql, "-- name: GetTeamTrialBalance"):
					balanceReads++
					if balanceReads == 2 {
						cancel()
						return queryCtx.Err()
					}
					*dest[2].(*pgtype.Numeric) = pgtype.Numeric{Int: big.NewInt(1), Valid: true}
					*dest[3].(*string) = "active"
					*dest[4].(*bool) = true
				case strings.Contains(sql, "-- name: GetRecentTrialBurnSample"):
					*dest[0].(*pgtype.Numeric) = pgtype.Numeric{Int: big.NewInt(10), Valid: true}
					*dest[1].(*any) = now.Add(-time.Hour)
					*dest[2].(*any) = now
					*dest[3].(*pgtype.Numeric) = pgtype.Numeric{Int: big.NewInt(3600), Valid: true}
				case strings.Contains(sql, "-- name: ClaimTrialCreditWarning"):
					if status != "pending" {
						return pgx.ErrNoRows
					}
					status = "claimed"
					*dest[0].(*pgtype.UUID) = claimToken
				default:
					t.Fatalf("unexpected query: %s", sql)
				}
				return nil
			}}
		},
		execFn: func(cleanupCtx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
			if err := cleanupCtx.Err(); err != nil {
				return pgconn.CommandTag{}, err
			}
			if args[0] != teamID || args[1] != claimToken || status != "claimed" {
				t.Fatalf("unexpected claim mutation: args=%v status=%s", args, status)
			}
			switch {
			case strings.Contains(sql, "-- name: ReleaseTrialCreditWarning"):
				deadline, ok := cleanupCtx.Deadline()
				if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 5*time.Second {
					t.Fatal("claim release requires a fresh bounded context")
				}
				releases++
				status = "pending"
			case strings.Contains(sql, "-- name: CompleteTrialCreditWarning"):
				status = "sent"
			default:
				t.Fatalf("unexpected execution: %s", sql)
			}
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}
	sender := &recordingTrialWarningSender{}
	h := &Handlers{DB: db.New(queries), TrialWarningSender: sender}
	h.processTrialCreditWarning(ctx, teamID)
	if status != "pending" || releases != 1 || sender.teamID != uuid.Nil {
		t.Fatalf("canceled pass: status=%s releases=%d sent team=%v", status, releases, sender.teamID)
	}
	h.processTrialCreditWarning(context.Background(), teamID)
	if status != "sent" || sender.teamID != teamID || sender.remaining != 1 {
		t.Fatalf("retry: status=%s sender=%+v", status, sender)
	}
}

func TestTrialCreditWarningRechecksForecastAfterClaim(t *testing.T) {
	for _, tc := range []struct {
		name      string
		remaining int64
		wantSend  bool
	}{
		{"top up beyond 24 hours", 25, false},
		{"top up to exactly 24 hours", 24, false},
		{"top up still below 24 hours", 23, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			teamID := uuid.New()
			claimToken := pgtype.UUID{Bytes: uuid.New(), Valid: true}
			status := "pending"
			balanceReads, releases := 0, 0
			now := time.Now()
			queries := &mockDBTX{
				queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
					return &mockRow{scanFn: func(dest ...any) error {
						switch {
						case strings.Contains(sql, "-- name: GetTeamTrialBalance"):
							balanceReads++
							remaining := int64(1)
							if balanceReads == 2 {
								remaining = tc.remaining
							}
							*dest[2].(*pgtype.Numeric) = pgtype.Numeric{Int: big.NewInt(remaining), Valid: true}
							*dest[3].(*string) = "active"
							*dest[4].(*bool) = true
						case strings.Contains(sql, "-- name: GetRecentTrialBurnSample"):
							*dest[0].(*pgtype.Numeric) = pgtype.Numeric{Int: big.NewInt(1), Valid: true}
							*dest[1].(*any) = now.Add(-time.Hour)
							*dest[2].(*any) = now
							*dest[3].(*pgtype.Numeric) = pgtype.Numeric{Int: big.NewInt(3600), Valid: true}
						case strings.Contains(sql, "-- name: ClaimTrialCreditWarning"):
							if status != "pending" {
								return pgx.ErrNoRows
							}
							status = "claimed"
							*dest[0].(*pgtype.UUID) = claimToken
						default:
							t.Fatalf("unexpected query: %s", sql)
						}
						return nil
					}}
				},
				execFn: func(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
					if args[0] != teamID || args[1] != claimToken || status != "claimed" {
						t.Fatalf("unexpected claim mutation: args=%v status=%s", args, status)
					}
					switch {
					case strings.Contains(sql, "-- name: ReleaseTrialCreditWarning"):
						releases++
						status = "pending"
					case strings.Contains(sql, "-- name: CompleteTrialCreditWarning"):
						status = "sent"
					default:
						t.Fatalf("unexpected execution: %s", sql)
					}
					return pgconn.NewCommandTag("UPDATE 1"), nil
				},
			}
			sender := &recordingTrialWarningSender{}
			h := &Handlers{DB: db.New(queries), TrialWarningSender: sender}
			h.processTrialCreditWarning(context.Background(), teamID)
			if balanceReads != 2 {
				t.Fatalf("balance reads = %d, want 2", balanceReads)
			}
			if tc.wantSend {
				if status != "sent" || releases != 0 || sender.teamID != teamID || sender.remaining != float64(tc.remaining) {
					t.Fatalf("eligible refreshed balance: status=%s releases=%d sender=%+v", status, releases, sender)
				}
				return
			}
			if status != "pending" || releases != 1 || sender.teamID != uuid.Nil {
				t.Fatalf("suppressed warning: status=%s releases=%d sender=%+v", status, releases, sender)
			}
			h.processTrialCreditWarning(context.Background(), teamID)
			if status != "sent" || sender.teamID != teamID || sender.remaining != 1 {
				t.Fatalf("retry after balance drops: status=%s sender=%+v", status, sender)
			}
		})
	}
}

type recordingTrialWarningSender struct {
	teamID    uuid.UUID
	remaining float64
	err       error
}

func (s *recordingTrialWarningSender) SendTrialCreditWarning(_ context.Context, teamID uuid.UUID, remaining float64) error {
	s.teamID, s.remaining = teamID, remaining
	return s.err
}

func TestTrialCreditWarningSenderAcceptsContentInputs(t *testing.T) {
	teamID := uuid.New()
	sender := &recordingTrialWarningSender{}
	if err := sender.SendTrialCreditWarning(context.Background(), teamID, 3.21); err != nil {
		t.Fatalf("accepted send returned error: %v", err)
	}
	if sender.teamID != teamID || sender.remaining != 3.21 {
		t.Fatalf("sender inputs = %v, $%.2f; want %v, $3.21", sender.teamID, sender.remaining, teamID)
	}
}

func TestTrialCreditWarningSenderReturnsRecoverableFailure(t *testing.T) {
	want := errors.New("provider temporarily unavailable")
	sender := &recordingTrialWarningSender{err: want}
	if err := sender.SendTrialCreditWarning(context.Background(), uuid.New(), 1); !errors.Is(err, want) {
		t.Fatalf("sender error = %v, want %v", err, want)
	}
}

func TestResendTrialCreditWarningRequiresProviderConfiguration(t *testing.T) {
	sender := NewResendTrialCreditWarningSender("", "", nil)
	if err := sender.SendTrialCreditWarning(context.Background(), uuid.New(), 1); err == nil {
		t.Fatal("missing provider configuration must not be treated as a successful send")
	}
}

func TestResendTrialCreditWarningProviderAcceptance(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	s := &ResendTrialCreditWarningSender{apiKey: "key", from: "team@example.com", endpoint: srv.URL, client: srv.Client()}
	if err := s.sendEmail(context.Background(), []byte(`{"html":"Less than 24 hours","remaining":"$1.23"}`)); err != nil {
		t.Fatalf("accepted provider response returned error: %v", err)
	}
	if !strings.Contains(gotBody, "Less than 24 hours") || !strings.Contains(gotBody, "$1.23") {
		t.Fatalf("provider received unexpected content: %s", gotBody)
	}
}

func TestResendTrialCreditWarningSenderIncludesAuthoritativeBalanceAndCoarseCopy(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	s := &ResendTrialCreditWarningSender{apiKey: "key", from: "team@example.com", endpoint: srv.URL, client: srv.Client()}
	body := []byte(trialCreditWarningHTML("example-team", 1.234))
	if err := s.sendEmail(context.Background(), body); err != nil {
		t.Fatalf("warning send returned error: %v", err)
	}
	for _, want := range []string{"example-team", "$1.23", "Less than 24 hours", "within the next 24 hours"} {
		if !strings.Contains(gotBody, want) {
			t.Fatalf("provider body missing %q: %s", want, gotBody)
		}
	}
	if strings.Contains(gotBody, "exhaustion timestamp") || strings.Contains(gotBody, "hours remaining: 1") {
		t.Fatalf("provider body exposed a precise forecast: %s", gotBody)
	}
}

func TestResendTrialCreditWarningProviderFailureIsRetryable(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	s := &ResendTrialCreditWarningSender{apiKey: "key", from: "team@example.com", endpoint: srv.URL, client: srv.Client()}
	if err := s.sendEmail(context.Background(), []byte(`{}`)); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("provider failure = %v, want retryable status error", err)
	}
	if err := s.sendEmail(context.Background(), []byte(`{}`)); err != nil {
		t.Fatalf("retry after provider failure returned error: %v", err)
	}
	if calls != 2 {
		t.Fatalf("provider calls = %d, want 2 after retry", calls)
	}
}

func TestUnknownTrialCreditWarningErrorPreservesOutcome(t *testing.T) {
	want := errors.New("connection reset after submit")
	err := &unknownTrialCreditWarningError{err: want}
	var unknown UnknownTrialCreditWarningOutcome
	if !errors.As(err, &unknown) || !unknown.UnknownTrialCreditWarning() {
		t.Fatal("transport failure must be classified as an unknown provider outcome")
	}
	if !errors.Is(err, want) {
		t.Fatal("unknown outcome must preserve the underlying transport error")
	}
}

func TestTrialCreditWarningRecipientsAreDeduplicated(t *testing.T) {
	got := dedupeWarningRecipients([]string{"a@example.com", "", "a@example.com", "b@example.com"})
	want := []string{"a@example.com", "b@example.com"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("dedupeWarningRecipients() = %#v, want %#v", got, want)
	}
}

func TestTrialCreditWarningEmailUsesCoarseCopyAndAuthoritativeBalance(t *testing.T) {
	body := trialCreditWarningHTML("example-team", 1.234)
	for _, want := range []string{"example-team", "$1.23", "Less than 24 hours", "within the next 24 hours"} {
		if !strings.Contains(body, want) {
			t.Fatalf("warning email missing %q: %s", want, body)
		}
	}
	if strings.Contains(body, "hours remaining: 1") || strings.Contains(body, "exhaustion timestamp") {
		t.Fatalf("warning email exposed a precise forecast: %s", body)
	}
}

func TestTrialCreditWarningEmailEscapesTeamName(t *testing.T) {
	teamName := `<a href="https://example.com">pilot & 'team'</a><img src="https://example.com/image.png">`
	body := trialCreditWarningHTML(teamName, 1.234)
	want := `<p>Team: &lt;a href=&#34;https://example.com&#34;&gt;pilot &amp; &#39;team&#39;&lt;/a&gt;&lt;img src=&#34;https://example.com/image.png&#34;&gt;</p>`
	if !strings.Contains(body, want) || strings.Contains(body, teamName) {
		t.Fatalf("warning email must render the team name as escaped text: %s", body)
	}
}

func TestNumericFloatPreservesDecimalScale(t *testing.T) {
	got, err := numericFloat(pgtype.Numeric{Int: big.NewInt(12345), Exp: -3, Valid: true})
	if err != nil || got != 12.345 {
		t.Fatalf("numericFloat() = %v, %v; want 12.345", got, err)
	}
}

func TestTrialCreditWarningUsesWallClockAndStrictBoundary(t *testing.T) {
	now := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)
	if !trialCreditWarningEligible(10, now, trialBurnSample{SpentUSD: 11, Started: now.Add(-time.Hour), Ended: now}) {
		t.Fatal("expected high burn rate to trigger")
	}
	if trialCreditWarningEligible(10, now, trialBurnSample{SpentUSD: 10, Started: now.Add(-24 * time.Hour), Ended: now}) {
		t.Fatal("exactly 24 hours must not trigger")
	}
	// The query also returns a duration, but overlapping concurrent intervals
	// must be forecast from their wall-clock bounds rather than summed runtime.
	if trialCreditWarningEligible(10, now, trialBurnSample{SpentUSD: 10, Started: now.Add(-24 * time.Hour), Ended: now, ElapsedSeconds: 60}) {
		t.Fatal("summed runtime must not override wall-clock elapsed time")
	}
}

func TestTrialCreditWarningAllowsFastMeaningfulSamples(t *testing.T) {
	now := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)
	for _, elapsed := range []time.Duration{time.Second, 5*time.Minute - time.Nanosecond} {
		if !trialCreditWarningEligible(1, now, trialBurnSample{
			SpentUSD: 0.5, Started: now.Add(-elapsed), Ended: now,
		}) {
			t.Fatalf("meaningful sample elapsed %v should trigger a warning", elapsed)
		}
	}
}

func TestTrialCreditWarningSuppressesInactiveTrialStates(t *testing.T) {
	for _, tc := range []struct {
		name     string
		eligible bool
		state    string
	}{
		{name: "exhausted", eligible: false, state: "exhausted"},
		{name: "stripe ended", eligible: false, state: "ended_by_billing_activation"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if trialCreditWarningLifecycleEligible(tc.eligible, tc.state) {
				t.Fatalf("state %q should suppress warning delivery", tc.state)
			}
		})
	}
}

func TestTrialCreditWarningProcessingDoesNotSendForInactiveTrials(t *testing.T) {
	for _, state := range []string{"exhausted", "ended_by_billing_activation"} {
		t.Run(state, func(t *testing.T) {
			sent := false
			if err := sendTrialCreditWarningIfEligible(false, state, func() error {
				sent = true
				return nil
			}); err != nil {
				t.Fatalf("unexpected processing error: %v", err)
			}
			if sent {
				t.Fatal("inactive trial must not invoke the warning sender")
			}
		})
	}
}

func TestTrialCreditWarningDeliveryPropagatesProviderOutcome(t *testing.T) {
	called := 0
	want := errors.New("provider rejected request")
	if err := sendTrialCreditWarningIfEligible(true, "active", func() error {
		called++
		return want
	}); !errors.Is(err, want) {
		t.Fatalf("provider error = %v, want %v", err, want)
	}
	if called != 1 {
		t.Fatalf("provider calls = %d, want 1", called)
	}

	called = 0
	if err := sendTrialCreditWarningIfEligible(true, "active", func() error {
		called++
		return nil
	}); err != nil {
		t.Fatalf("accepted provider outcome = %v", err)
	}
	if called != 1 {
		t.Fatalf("provider calls after acceptance = %d, want 1", called)
	}
}

func TestTrialCreditWarningDeliverySkipsProviderForIneligibleState(t *testing.T) {
	called := 0
	if err := sendTrialCreditWarningIfEligible(false, "ended_by_billing_activation", func() error {
		called++
		return errors.New("must not send")
	}); err != nil {
		t.Fatalf("ineligible delivery = %v, want nil", err)
	}
	if called != 0 {
		t.Fatalf("provider calls for ended trial = %d, want 0", called)
	}
}

func TestTrialCreditWarningRejectsSparseOrStaleSamples(t *testing.T) {
	now := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)
	base := trialBurnSample{SpentUSD: 10, Started: now.Add(-time.Hour), Ended: now}
	if trialCreditWarningEligible(1, now, trialBurnSample{SpentUSD: 0, Started: base.Started, Ended: base.Ended}) {
		t.Fatal("zero usage must not trigger")
	}
	if trialCreditWarningEligible(1, now, trialBurnSample{SpentUSD: 10, Started: now.Add(-72 * time.Hour), Ended: now.Add(-48 * time.Hour)}) {
		t.Fatal("stale sample must not trigger")
	}
}

func TestTrialCreditWarningSenderKeepsRecipientsPrivate(t *testing.T) {
	recipients := []string{"first@example.com", "second@example.com", "first@example.com"}
	queries := db.New(&mockDBTX{
		queryFn: func(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
			switch {
			case strings.Contains(sql, "-- name: ListTrialCreditWarningDeliveries"),
				strings.Contains(sql, "-- name: ListTrialCreditWarningRejections"):
				return emptyRows{}, nil
			case strings.Contains(sql, "-- name: ListTrialCreditWarningRecipients"):
				rows := &scanRows{}
				for _, recipient := range recipients {
					rows.rows = append(rows.rows, func(dest ...any) error {
						*dest[0].(*string) = recipient
						return nil
					})
				}
				return rows, nil
			default:
				return nil, fmt.Errorf("unexpected query: %s", sql)
			}
		},
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			return &mockRow{scanFn: func(dest ...any) error {
				if strings.Contains(sql, "-- name: IsTrialCreditWarningClaimCurrent") {
					*dest[0].(*bool) = true
					return nil
				}
				if strings.Contains(sql, "-- name: GetTeamTrialBalance") {
					*dest[2].(*pgtype.Numeric) = pgtype.Numeric{Int: big.NewInt(123), Exp: -2, Valid: true}
					*dest[3].(*string) = "active"
					*dest[4].(*bool) = true
					return nil
				}
				if !strings.Contains(sql, "-- name: GetTeam :one") {
					return fmt.Errorf("unexpected query: %s", sql)
				}
				*dest[1].(*string) = "example-team"
				return nil
			}}
		},
		execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			if !strings.Contains(sql, "-- name: RecordTrialCreditWarningDelivery") {
				return pgconn.CommandTag{}, fmt.Errorf("unexpected exec: %s", sql)
			}
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	})
	var payloads []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		payloads = append(payloads, payload)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	sender := NewResendTrialCreditWarningSender("test-key", "billing@example.com", queries)
	sender.endpoint, sender.client = server.URL, server.Client()
	if err := sender.SendTrialCreditWarningWithKey(context.Background(), uuid.New(), 1.23, uuid.New()); err != nil {
		t.Fatal(err)
	}
	if len(payloads) != 2 {
		t.Fatalf("provider submissions = %d, want 2 deduplicated recipients", len(payloads))
	}
	for i, payload := range payloads {
		to, ok := payload["to"].([]any)
		if !ok || len(to) != 1 || to[0] != recipients[i] {
			t.Fatalf("message %d must address only %q: %#v", i, recipients[i], payload)
		}
		encoded, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), recipients[1-i]) {
			t.Fatalf("message %d exposes another recipient: %s", i, encoded)
		}
	}
}

func TestTrialCreditWarningPartialDeliverySurvivesNewClaim(t *testing.T) {
	for _, status := range []int{http.StatusInternalServerError, http.StatusTooManyRequests, http.StatusUnauthorized, http.StatusRequestTimeout} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			teamID, claimToken := uuid.New(), uuid.New()
			recipients := []string{"first@example.com", "second@example.com"}
			delivered := map[string]bool{}
			queries := db.New(&mockDBTX{
				queryFn: func(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
					if len(args) != 1 || args[0] != teamID {
						t.Fatalf("unexpected recipient query arguments: %v", args)
					}
					var addresses []string
					switch {
					case strings.Contains(sql, "-- name: ListTrialCreditWarningDeliveries"):
						for recipient := range delivered {
							addresses = append(addresses, recipient)
						}
					case strings.Contains(sql, "-- name: ListTrialCreditWarningRejections"):
					case strings.Contains(sql, "-- name: ListTrialCreditWarningRecipients"):
						addresses = recipients
					default:
						return nil, fmt.Errorf("unexpected query: %s", sql)
					}
					rows := &scanRows{}
					for _, recipient := range addresses {
						rows.rows = append(rows.rows, func(dest ...any) error {
							*dest[0].(*string) = recipient
							return nil
						})
					}
					return rows, nil
				},
				queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
					return &mockRow{scanFn: func(dest ...any) error {
						if strings.Contains(sql, "-- name: IsTrialCreditWarningClaimCurrent") {
							*dest[0].(*bool) = true
							return nil
						}
						if strings.Contains(sql, "-- name: GetTeamTrialBalance") {
							*dest[2].(*pgtype.Numeric) = pgtype.Numeric{Int: big.NewInt(123), Exp: -2, Valid: true}
							*dest[3].(*string) = "active"
							*dest[4].(*bool) = true
							return nil
						}
						if !strings.Contains(sql, "-- name: GetTeam :one") {
							return fmt.Errorf("unexpected query: %s", sql)
						}
						*dest[1].(*string) = "example-team"
						return nil
					}}
				},
				execFn: func(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
					if !strings.Contains(sql, "-- name: RecordTrialCreditWarningDelivery") || len(args) != 3 || args[1] != teamID || args[2] != (pgtype.UUID{Bytes: claimToken, Valid: true}) {
						return pgconn.CommandTag{}, fmt.Errorf("unexpected delivery write: %s %v", sql, args)
					}
					delivered[args[0].(string)] = true
					return pgconn.NewCommandTag("INSERT 0 1"), nil
				},
			})
			calls := map[string]int{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var payload struct {
					To []string `json:"to"`
				}
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Error(err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if len(payload.To) != 1 {
					t.Errorf("expected one recipient, got %v", payload.To)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				recipient := payload.To[0]
				calls[recipient]++
				if recipient == "second@example.com" && calls[recipient] == 1 {
					w.WriteHeader(status)
					return
				}
				w.WriteHeader(http.StatusAccepted)
			}))
			defer server.Close()
			sender := NewResendTrialCreditWarningSender("test-key", "billing@example.com", queries)
			sender.endpoint, sender.client = server.URL, server.Client()
			err := sender.SendTrialCreditWarningWithKey(context.Background(), teamID, 1.23, claimToken)
			var unknown UnknownTrialCreditWarningOutcome
			var permanent *permanentTrialCreditWarningError
			if err == nil || errors.As(err, &unknown) || errors.As(err, &permanent) {
				t.Fatalf("partial delivery must leave a retryable error: %v", err)
			}
			if !delivered["first@example.com"] || delivered["second@example.com"] {
				t.Fatalf("durable progress must contain only the accepted recipient: %v", delivered)
			}
			// Releasing and reclaiming changes the token; balance and recipient
			// ordering may also change before the next background pass.
			claimToken = uuid.New()
			recipients = []string{"second@example.com", "first@example.com"}
			if err := sender.SendTrialCreditWarningWithKey(context.Background(), teamID, 0.95, claimToken); err != nil {
				t.Fatal(err)
			}
			if calls["first@example.com"] != 1 || calls["second@example.com"] != 2 || len(calls) != 2 || len(delivered) != 2 {
				t.Fatalf("retry duplicated or missed a recipient: calls=%v delivered=%v", calls, delivered)
			}
		})
	}
}

func TestTrialWarningProviderIdentityFollowsRecipient(t *testing.T) {
	var keys []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		keys = append(keys, r.Header.Get("Idempotency-Key"))
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	sender := &ResendTrialCreditWarningSender{endpoint: server.URL, client: server.Client()}
	token := uuid.New()
	for _, recipient := range []string{"first@example.com", "second@example.com", "second@example.com", "first@example.com"} {
		if err := sender.sendEmailWithKey(context.Background(), []byte(`{}`), token, recipient); err != nil {
			t.Fatal(err)
		}
	}
	if len(keys) != 4 || keys[0] == "" || keys[1] == "" || keys[0] == keys[1] || keys[0] != keys[3] || keys[1] != keys[2] {
		t.Fatalf("provider keys must distinguish recipients and survive reordering: %v", keys)
	}
}

func TestTrialCreditWarningProviderRejectionClassification(t *testing.T) {
	for _, tc := range []struct {
		name      string
		status    int
		body      string
		permanent bool
	}{
		{"invalid recipient", 422, `{"name":"validation_error"}`, true},
		{"bad request", 400, `{"name":"validation_error"}`, true},
		{"invalid sender", 422, `{"name":"invalid_from_address"}`, false},
		{"unauthorized", 401, `{}`, false},
		{"forbidden", 403, `{}`, false},
		{"request timeout", http.StatusRequestTimeout, `{}`, false},
		{"rate limited", 429, `{}`, false},
		{"unavailable", 503, `{}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			sender := &ResendTrialCreditWarningSender{endpoint: server.URL, client: server.Client()}
			err := sender.sendEmail(context.Background(), []byte(`{}`))
			var permanent *permanentTrialCreditWarningError
			if err == nil || errors.As(err, &permanent) != tc.permanent {
				t.Fatalf("error = %v, want permanent=%t", err, tc.permanent)
			}
		})
	}
}

func TestTrialCreditWarningDispatchOverflowProgress(t *testing.T) {
	h := &Handlers{}
	queue := make(chan trialCreditWarningJob, 256)
	teams := make([]uuid.UUID, 1031)
	for i := range teams {
		teams[i] = uuid.MustParse(fmt.Sprintf("00000000-0000-0000-0000-%012x", i+1))
	}
	seen := make(map[uuid.UUID]int)
	// Keep workers stalled during each sweep, including across the 1000-team
	// database page boundary. Terminal warnings still appear in later sweeps.
	for cycle := 0; cycle < 2; cycle++ {
		for sweep := 0; sweep < 5; sweep++ {
			pass := h.beginTrialCreditWarningPass()
			for start := 0; start < len(teams); start += 1000 {
				for _, team := range teams[start:min(start+1000, len(teams))] {
					pass.dispatch(h, context.Background(), team, queue)
				}
			}
			h.finishTrialCreditWarningPass(pass, true)
			if h.asyncCount != len(queue) {
				t.Fatalf("bookkeeping count=%d, queued=%d", h.asyncCount, len(queue))
			}
			for len(queue) > 0 {
				job := <-queue
				seen[job.teamID]++
				h.finishTrialCreditWarningJob(job.teamID)
			}
			h.WaitAsyncBookkeeping()
		}
		for _, team := range teams {
			if seen[team] != cycle+1 {
				t.Fatalf("team %s evaluated %d times after cycle %d", team, seen[team], cycle+1)
			}
		}
		if h.trialWarningAfter != uuid.Nil {
			t.Fatal("completed traversal did not wrap for later retries")
		}
	}
}

func TestTrialCreditWarningDispatchRetainsProgress(t *testing.T) {
	h := &Handlers{}
	queue := make(chan trialCreditWarningJob, 1)
	first := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	second := uuid.MustParse("00000000-0000-0000-0000-000000000002")
	pass := h.beginTrialCreditWarningPass()
	if !pass.dispatch(h, context.Background(), first, queue) {
		t.Fatal("first team was not enqueued")
	}
	if pass.dispatch(h, context.Background(), second, queue) {
		t.Fatal("full queue accepted another job")
	}
	h.finishTrialCreditWarningPass(pass, true)
	// Another sweep while workers remain blocked must not lose the cursor.
	pass = h.beginTrialCreditWarningPass()
	pass.dispatch(h, context.Background(), second, queue)
	h.finishTrialCreditWarningPass(pass, true)
	if h.trialWarningAfter != first || h.asyncCount != 1 {
		t.Fatalf("full sweep changed progress/count: %s/%d", h.trialWarningAfter, h.asyncCount)
	}
	job := <-queue
	h.finishTrialCreditWarningJob(job.teamID)
	pass = h.beginTrialCreditWarningPass()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if pass.dispatch(h, ctx, second, queue) || h.asyncCount != 0 {
		t.Fatal("canceled enqueue added work")
	}
	h.finishTrialCreditWarningPass(pass, false)
	pass = h.beginTrialCreditWarningPass()
	// The cursor team may have disappeared from the active-trial population.
	if !pass.dispatch(h, context.Background(), second, queue) {
		t.Fatal("overflow team did not progress after capacity became available")
	}
	h.finishTrialCreditWarningPass(pass, false)
	if h.trialWarningAfter != second {
		t.Fatal("interrupted traversal lost accepted progress")
	}
	job = <-queue
	h.finishTrialCreditWarningJob(job.teamID)
	h.WaitAsyncBookkeeping()
}

func TestTrialCreditWarningDispatchDeduplicatesPendingWork(t *testing.T) {
	h := &Handlers{}
	queue := make(chan trialCreditWarningJob, 2)
	first := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	second := uuid.MustParse("00000000-0000-0000-0000-000000000002")
	third := uuid.MustParse("00000000-0000-0000-0000-000000000003")
	pass := h.beginTrialCreditWarningPass()
	for _, team := range []uuid.UUID{first, second} {
		if !pass.dispatch(h, context.Background(), team, queue) {
			t.Fatal("initial dispatch failed")
		}
	}
	h.finishTrialCreditWarningPass(pass, true)
	// Removing a job from the queue leaves it pending until its work finishes.
	active := <-queue
	for sweep := 0; sweep < 100; sweep++ {
		pass = h.beginTrialCreditWarningPass()
		for _, team := range []uuid.UUID{first, second} {
			if pass.dispatch(h, context.WithoutCancel(context.Background()), team, queue) {
				t.Fatal("repeated sweep admitted duplicate queued or active work")
			}
		}
		h.finishTrialCreditWarningPass(pass, true)
		if len(queue) != 1 || h.asyncCount != 2 || len(h.trialWarningPending) != 2 {
			t.Fatal("repeated sweeps accumulated pending work")
		}
	}
	pass = h.beginTrialCreditWarningPass()
	if !pass.dispatch(h, context.Background(), third, queue) {
		t.Fatal("duplicate jobs consumed capacity needed by another team")
	}
	h.finishTrialCreditWarningPass(pass, true)
	h.finishTrialCreditWarningJob(active.teamID)
	for len(queue) > 0 {
		job := <-queue
		h.finishTrialCreditWarningJob(job.teamID)
	}
	pass = h.beginTrialCreditWarningPass()
	if !pass.dispatch(h, context.Background(), first, queue) {
		t.Fatal("completed work cannot be retried on a later sweep")
	}
	job := <-queue
	h.finishTrialCreditWarningJob(job.teamID)
	h.WaitAsyncBookkeeping()
	if len(h.trialWarningPending) != 0 {
		t.Fatal("completed work leaked pending entries")
	}
}

func TestTrialCreditWarningSkipsSmallAndIdleBursts(t *testing.T) {
	now := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name      string
		remaining float64
		sample    trialBurnSample
	}{
		{"insufficient spend", 0.01, trialBurnSample{SpentUSD: 0.001, Started: now.Add(-time.Second), Ended: now}},
		{"old burst", 1, trialBurnSample{SpentUSD: 1, Started: now.Add(-time.Hour), Ended: now.Add(-30 * time.Minute)}},
		{"idle wall time", 20, trialBurnSample{SpentUSD: 0.1, Started: now.Add(-10 * time.Minute), Ended: now.Add(-9 * time.Minute)}},
		{"zero duration", 1, trialBurnSample{SpentUSD: 1, Started: now, Ended: now}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if trialCreditWarningEligible(tc.remaining, now, tc.sample) {
				t.Fatal("unsafe sample triggered warning")
			}
		})
	}
}

func TestTrialCreditWarningNormalizesRecipients(t *testing.T) {
	got := dedupeWarningRecipients([]string{" Owner@Example.com ", "owner@example.com", "  "})
	if len(got) != 1 || got[0] != "owner@example.com" {
		t.Fatalf("recipients = %v", got)
	}
}
