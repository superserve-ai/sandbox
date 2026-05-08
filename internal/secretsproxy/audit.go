package secretsproxy

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
)

// auditEvent is one row to be persisted.
type auditEvent struct {
	TeamID         uuid.UUID
	SandboxID      uuid.UUID
	SecretID       uuid.UUID
	Provider       string
	Method         string
	Path           string
	Status         int32
	UpstreamStatus *int32
	LatencyMs      *int32
	ErrorCode      *string
}

// AuditWriter writes audit events to proxy_audit on a worker goroutine.
// Full queue drops the event rather than blocking the caller.
type AuditWriter struct {
	db      *db.Queries
	queue   chan auditEvent
	done    chan struct{}
	dropped atomic.Uint64 // events dropped since last reportInterval
}

const (
	auditQueueSize     = 4096
	auditReportInterval = 30 * time.Second
)

func NewAuditWriter(queries *db.Queries) *AuditWriter {
	return &AuditWriter{
		db:    queries,
		queue: make(chan auditEvent, auditQueueSize),
		done:  make(chan struct{}),
	}
}

// Run drains the queue until ctx is cancelled.
func (a *AuditWriter) Run(ctx context.Context) {
	defer close(a.done)
	report := time.NewTicker(auditReportInterval)
	defer report.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-a.queue:
			a.write(ctx, ev)
		case <-report.C:
			if n := a.dropped.Swap(0); n > 0 {
				log.Warn().Uint64("dropped", n).
					Dur("window", auditReportInterval).
					Int("queue_size", auditQueueSize).
					Int("queue_len", len(a.queue)).
					Msg("audit events dropped — queue saturated")
			}
		}
	}
}

func (a *AuditWriter) write(ctx context.Context, ev auditEvent) {
	if a.db == nil {
		return
	}
	writeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err := a.db.InsertProxyAudit(writeCtx, db.InsertProxyAuditParams{
		TeamID:         ev.TeamID,
		SandboxID:      ev.SandboxID,
		SecretID:       ev.SecretID,
		Provider:       ev.Provider,
		Method:         ev.Method,
		Path:           ev.Path,
		Status:         ev.Status,
		UpstreamStatus: ev.UpstreamStatus,
		LatencyMs:      ev.LatencyMs,
		ErrorCode:      ev.ErrorCode,
	})
	if err != nil {
		log.Error().Err(err).Str("sandbox_id", ev.SandboxID.String()).Msg("audit write failed")
	}
}

// Enqueue offers an event to the worker. Drops on full queue.
func (a *AuditWriter) Enqueue(ev auditEvent) {
	select {
	case a.queue <- ev:
	default:
		a.dropped.Add(1)
	}
}
