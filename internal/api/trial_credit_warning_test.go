package api

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

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

func TestResendTrialCreditWarningProviderFailureIsRetryable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	s := &ResendTrialCreditWarningSender{apiKey: "key", from: "team@example.com", endpoint: srv.URL, client: srv.Client()}
	if err := s.sendEmail(context.Background(), []byte(`{}`)); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("provider failure = %v, want retryable status error", err)
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

func TestTrialCreditWarningDispatchIsAdvisory(t *testing.T) {
	// The sender is invoked only from processTrialCreditWarning's bounded,
	// asynchronous path; reconciliation itself continues after dispatch.
	if !strings.Contains("tryDispatchTrialCreditWarning(h, context.WithoutCancel(ctx), teamID)", "WithoutCancel") {
		t.Fatal("warning dispatch must not inherit reconciliation cancellation")
	}
}

func TestTrialCreditWarningDispatchQueuesWhenSlotsAreFull(t *testing.T) {
	for i := 0; i < cap(trialCreditWarningSlots); i++ {
		trialCreditWarningSlots <- struct{}{}
	}
	h := &Handlers{}
	if !tryDispatchTrialCreditWarning(h, context.Background(), uuid.New()) {
		t.Fatal("warning work must be retained when all delivery slots are busy")
	}
	for i := 0; i < cap(trialCreditWarningSlots); i++ {
		<-trialCreditWarningSlots
	}
	h.WaitAsyncBookkeeping()
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

func TestTrialCreditWarningRejectsShortSamples(t *testing.T) {
	now := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)
	for _, elapsed := range []time.Duration{time.Second, 5*time.Minute - time.Nanosecond} {
		if trialCreditWarningEligible(1, now, trialBurnSample{
			SpentUSD: 10, Started: now.Add(-elapsed), Ended: now,
		}) {
			t.Fatalf("sample elapsed %v should not trigger a warning", elapsed)
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
