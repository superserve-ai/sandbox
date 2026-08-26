package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
	"github.com/superserve-ai/sandbox/internal/telemetry"
)

const (
	DefaultReadinessInterval        = 10 * time.Second
	DefaultReadinessProbeTimeout    = time.Second
	DefaultReadinessFailureCount    = 2
	DefaultReadinessFailureDuration = 20 * time.Second
	DefaultReadinessEscalation      = 10 * time.Minute
)

// DBReadiness tracks dependency usability independently from process liveness.
// A failed probe is not exposed until both the consecutive-failure and elapsed
// duration thresholds have been met, which avoids ejecting replicas for one
// transient dial or latency spike.
type DBReadiness struct {
	mu             sync.RWMutex
	ready          bool
	consecutive    int
	unhealthySince time.Time
	config         DBReadinessConfig
	probe          func(context.Context) error
	recorder       telemetry.Recorder
	instanceID     string
	escalated      bool
}

type DBReadinessConfig struct {
	Interval        time.Duration
	ProbeTimeout    time.Duration
	FailureCount    int
	FailureDuration time.Duration
	Escalation      time.Duration
	// EscalationGuard must confirm that the failure is instance-local before
	// replacement is requested. A DB probe cannot distinguish a shared outage,
	// so omitting the guard disables replacement escalation.
	EscalationGuard func() bool
	OnEscalate      func()
}

func DefaultDBReadinessConfig() DBReadinessConfig {
	return DBReadinessConfig{Interval: DefaultReadinessInterval, ProbeTimeout: DefaultReadinessProbeTimeout, FailureCount: DefaultReadinessFailureCount, FailureDuration: DefaultReadinessFailureDuration, Escalation: DefaultReadinessEscalation}
}

// NewProductionDBReadiness keeps production fail-closed on escalation until a
// real instance-local guard exists. Readiness still removes DB-wedged
// replicas from traffic, but automatic replacement stays disabled rather than
// turning a shared DB outage into fleet churn.
func NewProductionDBReadiness(pool *pgxpool.Pool, recorder telemetry.Recorder, _ func()) *DBReadiness {
	cfg := DefaultDBReadinessConfig()
	cfg.Escalation = 0
	cfg.EscalationGuard = nil
	cfg.OnEscalate = nil
	return NewDBReadiness(pool, recorder, cfg)
}

func NewDBReadiness(pool *pgxpool.Pool, recorder telemetry.Recorder, cfg DBReadinessConfig) *DBReadiness {
	if cfg.Interval == 0 && cfg.ProbeTimeout == 0 && cfg.FailureCount == 0 && cfg.FailureDuration == 0 && cfg.Escalation == 0 && cfg.EscalationGuard == nil && cfg.OnEscalate == nil {
		cfg = DefaultDBReadinessConfig()
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultReadinessInterval
	}
	if cfg.ProbeTimeout <= 0 {
		cfg.ProbeTimeout = DefaultReadinessProbeTimeout
	}
	if cfg.FailureCount <= 0 {
		cfg.FailureCount = DefaultReadinessFailureCount
	}
	if cfg.FailureDuration < 0 {
		cfg.FailureDuration = DefaultReadinessFailureDuration
	}
	if cfg.Escalation < 0 {
		cfg.Escalation = 0
	}
	if cfg.Escalation > 0 && cfg.EscalationGuard == nil {
		cfg.Escalation = 0
	}
	probe := func(ctx context.Context) error {
		if pool == nil {
			return errors.New("database pool unavailable")
		}
		var one int
		return pool.QueryRow(ctx, "SELECT 1").Scan(&one)
	}
	instanceID := ""
	if identity, ok := recorder.(telemetry.InstanceIdentity); ok {
		instanceID = identity.ServiceInstanceID()
	}
	return &DBReadiness{ready: true, config: cfg, recorder: recorder, probe: probe, instanceID: instanceID}
}

// NewDBReadinessForProbe is used by focused tests and keeps the state machine
// independent of pgxpool's concrete type.
func NewDBReadinessForProbe(probe func(context.Context) error, recorder telemetry.Recorder, cfg DBReadinessConfig) *DBReadiness {
	r := NewDBReadiness(nil, recorder, cfg)
	r.probe = probe
	return r
}

func (r *DBReadiness) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(r.config.Interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			r.Probe(ctx)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func (r *DBReadiness) Probe(parent context.Context) {
	started := time.Now()
	ctx, cancel := context.WithTimeout(parent, r.config.ProbeTimeout)
	err := r.probe(ctx)
	cancel()
	duration := time.Since(started)
	r.mu.Lock()
	wasReady := r.ready
	escalate := false
	escalationCandidate := false
	unhealthyDuration := time.Duration(0)
	if err == nil || !readinessConnectivityError(err) {
		r.ready, r.consecutive, r.unhealthySince = true, 0, time.Time{}
	} else {
		if r.consecutive == 0 {
			r.unhealthySince = started
		}
		r.consecutive++
		if r.consecutive >= r.config.FailureCount && !r.unhealthySince.IsZero() && time.Since(r.unhealthySince) >= r.config.FailureDuration {
			r.ready = false
		}
		if r.config.OnEscalate != nil && r.config.Escalation > 0 && !r.ready && !r.escalated && !r.unhealthySince.IsZero() && time.Since(r.unhealthySince) >= r.config.Escalation {
			escalationCandidate = true
			unhealthyDuration = time.Since(r.unhealthySince)
		}
	}
	if r.ready {
		r.escalated = false
	}
	nowReady := r.ready
	consecutive := r.consecutive
	r.mu.Unlock()
	if escalationCandidate && (r.config.EscalationGuard == nil || r.config.EscalationGuard()) {
		r.mu.Lock()
		if !r.escalated && !r.ready {
			r.escalated = true
			escalate = true
		}
		r.mu.Unlock()
	}
	if rr, ok := r.recorder.(telemetry.ReadinessRecorder); ok {
		transition := ""
		if wasReady != nowReady {
			if nowReady {
				transition = "recovered"
			} else {
				transition = "unready"
			}
		}
		rr.RecordDBReadiness(parent, telemetry.DBReadiness{Ready: nowReady, Unready: !nowReady, ProbeSucceeded: err == nil, Duration: duration, Transition: transition})
	}
	if wasReady != nowReady {
		log.Warn().Str("service.instance.id", r.instanceID).Bool("ready", nowReady).Int("consecutive_failures", consecutive).Dur("probe_duration", duration).Msg("database readiness state changed")
	}
	// Re-check locality immediately before requesting replacement. The guard is
	// allowed to observe fleet health, which may change while telemetry and
	// logging run after the probe state transition; a newly shared outage must
	// not turn an already-unready replica into a restart.
	if escalate && (r.config.EscalationGuard == nil || !r.config.EscalationGuard()) {
		escalate = false
	}
	if escalate && r.config.OnEscalate != nil {
		log.Error().Str("service.instance.id", r.instanceID).Dur("unhealthy_duration", unhealthyDuration).Msg("database readiness escalation requested")
		r.config.OnEscalate()
	}
}

// SELECT 1 errors from Postgres itself are not evidence that the process lost
// connectivity (for example, a server-side SQL error). Only dial/transport
// failures and probe deadlines participate in readiness state.
func readinessConnectivityError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	var pgErr *pgconn.PgError
	return !errors.As(err, &pgErr)
}

func (r *DBReadiness) Ready() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.ready
}

func (r *DBReadiness) Handler(c *gin.Context) {
	if !r.Ready() {
		c.JSON(http.StatusServiceUnavailable, gin.H{"status": "unready"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ready"})
}

// LivenessHandler remains healthy through DB outages. Readiness is the
// dependency-specific serving signal; a DB probe cannot distinguish an
// instance-local wedge from a shared outage well enough to trigger replacement.
func (r *DBReadiness) LivenessHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "live"})
}
