package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/superserve-ai/sandbox/internal/telemetry"
)

func TestDBReadinessMarksIncidentTimeoutsUnready(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "direct context deadline", err: context.DeadlineExceeded},
		{name: "context deadline", err: fmt.Errorf("query failed: %w", context.DeadlineExceeded)},
		{name: "dial timeout", err: &net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{Err: "i/o timeout", Name: "db.example", IsTimeout: true}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewDBReadinessForProbe(func(context.Context) error { return tt.err }, telemetry.NewNoopRecorder(), DBReadinessConfig{FailureCount: 1})
			r.Probe(context.Background())
			if r.Ready() {
				t.Fatalf("timeout error %T left readiness green", tt.err)
			}

			w := httptest.NewRecorder()
			engine := gin.New()
			engine.GET("/ready", r.Handler)
			engine.ServeHTTP(w, httptest.NewRequest("GET", "/ready", nil))
			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("timeout error %T returned /ready status %d, want %d", tt.err, w.Code, http.StatusServiceUnavailable)
			}
		})
	}
}

func TestDBReadinessMarksProbeContextTimeoutUnready(t *testing.T) {
	r := NewDBReadinessForProbe(func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}, telemetry.NewNoopRecorder(), DBReadinessConfig{FailureCount: 1, ProbeTimeout: time.Millisecond})

	r.Probe(context.Background())
	if r.Ready() {
		t.Fatal("probe deadline exceeded without marking readiness unready")
	}
}

func TestDBReadinessRequiresCountAndDurationAndRecovers(t *testing.T) {
	failing := true
	r := NewDBReadinessForProbe(func(context.Context) error {
		if failing {
			return errors.New("dial failed")
		}
		return nil
	}, telemetry.NewNoopRecorder(), DBReadinessConfig{FailureCount: 2, FailureDuration: 5 * time.Millisecond})

	r.Probe(context.Background())
	if !r.Ready() {
		t.Fatal("one failed probe must remain ready")
	}
	r.Probe(context.Background())
	if !r.Ready() {
		t.Fatal("count threshold without duration must remain ready")
	}
	time.Sleep(6 * time.Millisecond)
	r.Probe(context.Background())
	if r.Ready() {
		t.Fatal("consecutive and sustained failures must mark unready")
	}

	failing = false
	r.Probe(context.Background())
	if !r.Ready() {
		t.Fatal("successful connectivity probe must immediately recover readiness")
	}
}

func TestDBReadinessIgnoresOrdinaryPostgresErrors(t *testing.T) {
	r := NewDBReadinessForProbe(func(context.Context) error {
		return &pgconn.PgError{Code: "23505", Message: "constraint"}
	}, telemetry.NewNoopRecorder(), DBReadinessConfig{FailureCount: 1, FailureDuration: 0})
	r.Probe(context.Background())
	if !r.Ready() {
		t.Fatal("ordinary SQL errors must not mark DB connectivity unready")
	}
}

func TestDBReadinessHandlerReturnsServiceUnavailable(t *testing.T) {
	r := NewDBReadinessForProbe(func(context.Context) error { return errors.New("unavailable") }, telemetry.NewNoopRecorder(), DBReadinessConfig{FailureCount: 1, FailureDuration: time.Nanosecond})
	r.Probe(context.Background())
	time.Sleep(time.Millisecond)
	r.Probe(context.Background())
	w := httptest.NewRecorder()
	engine := gin.New()
	engine.GET("/ready", r.Handler)
	engine.ServeHTTP(w, httptest.NewRequest("GET", "/ready", nil))
	if w.Code != 503 {
		t.Fatalf("status = %d, want 503", w.Code)
	}
}

func TestDBReadinessIgnoresServerSideSQLErrors(t *testing.T) {
	r := NewDBReadinessForProbe(func(context.Context) error {
		return &pgconn.PgError{Code: "23505", Message: "duplicate key"}
	}, telemetry.NewNoopRecorder(), DBReadinessConfig{FailureCount: 1, FailureDuration: 0})
	r.Probe(context.Background())
	if !r.Ready() {
		t.Fatal("server-side SQL errors must not mark the process database-unready")
	}
}

func TestDBReadinessEscalatesOnceAfterProlongedFailure(t *testing.T) {
	escalations := 0
	r := NewDBReadinessForProbe(func(context.Context) error { return errors.New("dial failed") }, telemetry.NewNoopRecorder(), DBReadinessConfig{
		FailureCount:    1,
		FailureDuration: 0,
		Escalation:      time.Nanosecond,
		EscalationGuard: func() bool { return true },
		OnEscalate:      func() { escalations++ },
	})
	r.Probe(context.Background())
	r.Probe(context.Background())
	if escalations != 1 {
		t.Fatalf("escalations = %d, want one", escalations)
	}
}

func TestDBReadinessDoesNotEscalateWithoutInstanceLocalEvidence(t *testing.T) {
	escalations := 0
	r := NewDBReadinessForProbe(func(context.Context) error { return errors.New("dial failed") }, telemetry.NewNoopRecorder(), DBReadinessConfig{
		FailureCount:    1,
		FailureDuration: 0,
		Escalation:      time.Nanosecond,
		OnEscalate:      func() { escalations++ },
	})
	r.Probe(context.Background())
	r.Probe(context.Background())
	if escalations != 0 {
		t.Fatalf("escalations = %d, want zero without instance-local evidence", escalations)
	}
}

func TestDBReadinessRechecksInstanceLocalityBeforeEscalation(t *testing.T) {
	escalations := 0
	guardCalls := 0
	r := NewDBReadinessForProbe(func(context.Context) error { return errors.New("dial failed") }, telemetry.NewNoopRecorder(), DBReadinessConfig{
		FailureCount:    1,
		FailureDuration: 0,
		Escalation:      time.Nanosecond,
		EscalationGuard: func() bool {
			guardCalls++
			// The first check observes an instance-local failure; the second
			// observes that the dependency outage has become shared.
			return guardCalls == 1
		},
		OnEscalate: func() { escalations++ },
	})
	r.Probe(context.Background())
	r.Probe(context.Background())
	if escalations != 0 {
		t.Fatalf("escalations = %d, want zero after locality guard changes", escalations)
	}
}

func TestDBReadinessDisablesUnguardedEscalation(t *testing.T) {
	r := NewDBReadinessForProbe(func(context.Context) error { return errors.New("dial failed") }, telemetry.NewNoopRecorder(), DBReadinessConfig{
		FailureCount:    1,
		FailureDuration: 0,
		Escalation:      time.Nanosecond,
		OnEscalate:      func() {},
	})
	if r.config.Escalation != 0 {
		t.Fatalf("escalation = %s, want disabled without an instance-locality guard", r.config.Escalation)
	}
	r.Probe(context.Background())
	if r.Ready() {
		t.Fatal("connectivity failure should still make readiness unhealthy")
	}
}

func TestDBReadinessDoesNotEscalateByDefault(t *testing.T) {
	r := NewDBReadinessForProbe(func(context.Context) error { return errors.New("dial failed") }, telemetry.NewNoopRecorder(), DefaultDBReadinessConfig())
	r.Probe(context.Background())
	if r.config.Escalation != 0 {
		t.Fatalf("default escalation duration = %s, want disabled", r.config.Escalation)
	}
}

func TestDBReadinessLivenessRemainsHealthyAfterDBFailure(t *testing.T) {
	escalations := 0
	r := NewDBReadinessForProbe(func(context.Context) error { return errors.New("dial failed") }, telemetry.NewNoopRecorder(), DBReadinessConfig{
		FailureCount:    1,
		FailureDuration: 0,
		Escalation:      time.Hour,
		EscalationGuard: func() bool { return true },
		OnEscalate:      func() { escalations++ },
	})
	r.Probe(context.Background())
	if escalations != 0 {
		t.Fatalf("escalations = %d, want zero before escalation threshold", escalations)
	}

	w := httptest.NewRecorder()
	engine := gin.New()
	engine.GET("/ready", r.Handler)
	engine.GET("/live", r.LivenessHandler)
	engine.ServeHTTP(w, httptest.NewRequest("GET", "/ready", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness status = %d, want %d before escalation", w.Code, http.StatusServiceUnavailable)
	}

	w = httptest.NewRecorder()
	engine.ServeHTTP(w, httptest.NewRequest("GET", "/live", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("liveness status = %d, want %d while readiness is failing", w.Code, http.StatusOK)
	}
}
