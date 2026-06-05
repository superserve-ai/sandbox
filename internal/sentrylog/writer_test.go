package sentrylog

import (
	"testing"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/rs/zerolog"
)

func TestWriter_ForwardsErrorsNotWarnings(t *testing.T) {
	mock := &sentry.MockTransport{}
	if err := sentry.Init(sentry.ClientOptions{
		Dsn:       "https://test@example.com/1",
		Transport: mock,
	}); err != nil {
		t.Fatalf("sentry init: %v", err)
	}

	w := &Writer{}
	// Below error level: must not be forwarded.
	w.WriteLevel(zerolog.WarnLevel, []byte(`{"level":"warn","message":"a warning"}`))
	w.WriteLevel(zerolog.InfoLevel, []byte(`{"level":"info","message":"an info"}`))
	// Error level: forwarded and enriched.
	w.WriteLevel(zerolog.ErrorLevel, []byte(`{"level":"error","message":"boom","error":"disk full","caller":"x.go:42","component":"builder"}`))

	sentry.Flush(2 * time.Second)

	events := mock.Events()
	if len(events) != 1 {
		t.Fatalf("expected exactly 1 forwarded event (error only), got %d", len(events))
	}
	e := events[0]

	if e.Level != sentry.LevelError {
		t.Errorf("level = %q, want error", e.Level)
	}
	if e.Message != "boom: disk full" {
		t.Errorf("message = %q, want %q (error in title)", e.Message, "boom: disk full")
	}
	if got := e.Tags["caller"]; got != "x.go:42" {
		t.Errorf("caller tag = %q, want x.go:42", got)
	}
	if got := e.Tags["component"]; got != "builder" {
		t.Errorf("component tag = %q, want builder", got)
	}
	if len(e.Fingerprint) != 2 || e.Fingerprint[0] != "boom" || e.Fingerprint[1] != "x.go:42" {
		t.Errorf("fingerprint = %v, want [boom x.go:42]", e.Fingerprint)
	}
	// caller is a tag, so it must not also be duplicated in the log context.
	if logCtx, ok := e.Contexts["log"]; ok {
		if _, dup := logCtx["caller"]; dup {
			t.Error("caller duplicated in log context; it should be a tag only")
		}
	}
}
