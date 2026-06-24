package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/superserve-ai/sandbox/internal/db"
)

func ptrInt32(v int32) *int32 { return &v }

// stubRecipient is a teamEmailLookup for exercising EmailQuotaNotifier offline.
type stubRecipient struct {
	email string
	err   error
	calls int
}

func (s *stubRecipient) GetTeamNotifyEmail(context.Context, uuid.UUID) (string, error) {
	s.calls++
	return s.email, s.err
}

func TestComputeQuotaAlerts(t *testing.T) {
	atThreshold := uuid.New()  // sandboxes 80/100 = 80% -> alert
	below := uuid.New()        // sandboxes 79/100 = 79% -> no
	tmplDefault := uuid.New()  // templates 8/10 via default 10 = 80% -> alert
	tmplOverride := uuid.New() // templates 10/200 (override) = 5% -> no
	zeroLimit := uuid.New()    // max 0 -> must not alert or panic

	rows := []db.ListTeamQuotaUsageRow{
		{ID: atThreshold, Name: "at", ActiveSandboxCount: 80, MaxSandboxes: 100},
		{ID: below, Name: "below", ActiveSandboxCount: 79, MaxSandboxes: 100, TemplateCount: 1},
		{ID: tmplDefault, Name: "tdefault", MaxSandboxes: 100, TemplateCount: 8}, // MaxTemplates nil -> default
		{ID: tmplOverride, Name: "toverride", MaxSandboxes: 100, MaxTemplates: ptrInt32(200), TemplateCount: 10},
		{ID: zeroLimit, Name: "zero", ActiveSandboxCount: 5, MaxSandboxes: 0},
	}

	got := computeQuotaAlerts(rows)

	if len(got) != 2 {
		t.Fatalf("got %d alerts, want 2: %+v", len(got), got)
	}
	if a, ok := got[quotaKey{atThreshold, "sandboxes"}]; !ok {
		t.Error("expected sandbox alert at 80%")
	} else if a.Pct != 80 || a.Used != 80 || a.Limit != 100 {
		t.Errorf("sandbox alert = %+v, want 80%% 80/100", a)
	}
	if a, ok := got[quotaKey{tmplDefault, "templates"}]; !ok {
		t.Error("expected template alert at 80% (default limit)")
	} else if a.Pct != 80 {
		t.Errorf("template alert pct = %d, want 80", a.Pct)
	}

	for _, neg := range []quotaKey{
		{below, "sandboxes"},
		{tmplOverride, "templates"},
		{zeroLimit, "sandboxes"},
	} {
		if _, ok := got[neg]; ok {
			t.Errorf("%v should not have alerted", neg)
		}
	}
}

func TestShouldRearm(t *testing.T) {
	team := uuid.New()
	cutoff := time.Now().Add(-quotaAlertCooldown)

	// Inside the cooldown window: keep suppressed.
	fresh := db.ListQuotaAlertStateRow{TeamID: team, QuotaType: "sandboxes", Channel: "email", CreatedAt: time.Now().Add(-1 * time.Hour)}
	if shouldRearm(fresh, cutoff) {
		t.Error("should not re-arm inside the cooldown window")
	}

	// Aged past the cooldown: re-arm regardless of current usage.
	aged := db.ListQuotaAlertStateRow{TeamID: team, QuotaType: "sandboxes", Channel: "email", CreatedAt: time.Now().Add(-quotaAlertCooldown - time.Hour)}
	if !shouldRearm(aged, cutoff) {
		t.Error("should re-arm once the row ages past the cooldown")
	}
}

func TestEmailQuotaNotifierHandlesAndChannel(t *testing.T) {
	n := NewEmailQuotaNotifier("k", "from@superserve.ai", nil)
	if n.Channel() != "email" {
		t.Errorf("channel = %q, want email", n.Channel())
	}
	if !n.Handles("sandboxes") {
		t.Error("email notifier should handle sandboxes")
	}
	if n.Handles("templates") {
		t.Error("email notifier should not handle templates (Slack-only)")
	}
}

func TestEmailQuotaNotifierSends(t *testing.T) {
	var gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rcpt := &stubRecipient{email: "owner@acme.test"}
	n := &EmailQuotaNotifier{apiKey: "rk_test", from: "alerts@superserve.ai", recipients: rcpt, endpoint: srv.URL, client: srv.Client()}

	alert := QuotaAlert{TeamID: uuid.New(), TeamName: "Acme", Resource: "sandboxes", Used: 16, Limit: 20, Pct: 80}
	if err := n.Notify(context.Background(), alert); err != nil {
		t.Fatalf("Notify returned error: %v", err)
	}
	if gotAuth != "Bearer rk_test" {
		t.Errorf("auth header = %q, want Bearer rk_test", gotAuth)
	}

	var payload struct {
		To      []string `json:"to"`
		Subject string   `json:"subject"`
		HTML    string   `json:"html"`
	}
	if err := json.Unmarshal([]byte(gotBody), &payload); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if len(payload.To) != 1 || payload.To[0] != "owner@acme.test" {
		t.Errorf("to = %v, want [owner@acme.test]", payload.To)
	}
	if !strings.Contains(payload.Subject, "Verify your team") {
		t.Errorf("subject = %q, want it to mention verification", payload.Subject)
	}
	if !strings.Contains(payload.HTML, "Verify your team on Superserve") || !strings.Contains(payload.HTML, "Book a Meeting") {
		t.Errorf("html missing verification heading/CTA: %q", payload.HTML)
	}
}

func TestEmailQuotaNotifierServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()

	n := &EmailQuotaNotifier{apiKey: "rk", from: "f@superserve.ai", recipients: &stubRecipient{email: "o@x.test"}, endpoint: srv.URL, client: srv.Client()}
	err := n.Notify(context.Background(), QuotaAlert{TeamID: uuid.New(), Resource: "sandboxes", Pct: 90})
	if err == nil {
		t.Fatal("expected error on 5xx so the watcher retries")
	}
}

func TestEmailQuotaNotifierPermanentRejection(t *testing.T) {
	// A 422 for a bad recipient is permanent: Notify must not return an error, so
	// the claim is kept and the tick doesn't retry forever.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"name":"validation_error","message":"Invalid recipient"}`))
	}))
	defer srv.Close()

	n := &EmailQuotaNotifier{apiKey: "rk", from: "f@superserve.ai", recipients: &stubRecipient{email: "o@x.test"}, endpoint: srv.URL, client: srv.Client()}
	if err := n.Notify(context.Background(), QuotaAlert{TeamID: uuid.New(), Resource: "sandboxes", Pct: 82}); err != nil {
		t.Fatalf("permanent 4xx should be a quiet drop, got %v", err)
	}
}

func TestEmailQuotaNotifierInvalidFromRetries(t *testing.T) {
	// A malformed QUOTA_EMAIL_FROM is reported as invalid_from_address (422) but is
	// recoverable config — Notify must return an error so it retries once fixed.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"name":"invalid_from_address","message":"Invalid from"}`))
	}))
	defer srv.Close()

	n := &EmailQuotaNotifier{apiKey: "rk", from: "bad", recipients: &stubRecipient{email: "o@x.test"}, endpoint: srv.URL, client: srv.Client()}
	if err := n.Notify(context.Background(), QuotaAlert{TeamID: uuid.New(), Resource: "sandboxes", Pct: 82}); err == nil {
		t.Fatal("invalid_from_address is recoverable config; should return an error to retry")
	}
}

func TestEmailQuotaNotifierConfigErrorRetries(t *testing.T) {
	// 401/403 are recoverable config errors (bad key, unverified domain): Notify
	// must return an error so the claim releases and the next tick retries once
	// the config is fixed.
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
		}))
		n := &EmailQuotaNotifier{apiKey: "rk", from: "f@superserve.ai", recipients: &stubRecipient{email: "o@x.test"}, endpoint: srv.URL, client: srv.Client()}
		err := n.Notify(context.Background(), QuotaAlert{TeamID: uuid.New(), Resource: "sandboxes", Pct: 82})
		srv.Close()
		if err == nil {
			t.Errorf("status %d should return an error so the watcher retries", code)
		}
	}
}

func TestEmailQuotaNotifierRateLimited(t *testing.T) {
	// 429 is transient: Notify must return an error so the watcher retries.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	n := &EmailQuotaNotifier{apiKey: "rk", from: "f@superserve.ai", recipients: &stubRecipient{email: "o@x.test"}, endpoint: srv.URL, client: srv.Client()}
	if err := n.Notify(context.Background(), QuotaAlert{TeamID: uuid.New(), Resource: "sandboxes", Pct: 82}); err == nil {
		t.Fatal("429 should return an error so the watcher retries")
	}
}

func TestEmailQuotaNotifierNoRecipient(t *testing.T) {
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer srv.Close()

	n := &EmailQuotaNotifier{apiKey: "rk", from: "f@superserve.ai", recipients: &stubRecipient{err: pgx.ErrNoRows}, endpoint: srv.URL, client: srv.Client()}
	if err := n.Notify(context.Background(), QuotaAlert{TeamID: uuid.New(), Resource: "sandboxes", Pct: 85}); err != nil {
		t.Fatalf("missing recipient should be a quiet skip, got %v", err)
	}
	if called {
		t.Error("should not call Resend when there is no recipient")
	}
}

func TestEmailQuotaNotifierDisabled(t *testing.T) {
	rcpt := &stubRecipient{email: "o@x.test"}
	n := &EmailQuotaNotifier{apiKey: "", from: "f@superserve.ai", recipients: rcpt, endpoint: "http://unused", client: http.DefaultClient}
	if err := n.Notify(context.Background(), QuotaAlert{TeamID: uuid.New(), Resource: "sandboxes"}); err != nil {
		t.Fatalf("disabled notifier should no-op, got %v", err)
	}
	if rcpt.calls != 0 {
		t.Error("disabled notifier must not look up a recipient")
	}
}
