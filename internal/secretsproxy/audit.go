package secretsproxy

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
)

// auditEvent is one row to be persisted. The proxy hot path enqueues
// these on a buffered channel so disk/DB latency never blocks request
// handling.
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

// AuditWriter buffers audit events and writes them to the proxy_audit
// table on a worker goroutine. Drops events on full queue rather than
// blocking the request path; the dropped count is logged so ops can
// notice if the queue is undersized.
type AuditWriter struct {
	db    *db.Queries
	queue chan auditEvent
	done  chan struct{}
}

const (
	auditQueueSize = 4096
	auditFlushOnce = 64 // soft batch — single insert per row in MVP, batching is Phase 2.
)

func NewAuditWriter(queries *db.Queries) *AuditWriter {
	return &AuditWriter{
		db:    queries,
		queue: make(chan auditEvent, auditQueueSize),
		done:  make(chan struct{}),
	}
}

// Run drains the queue until ctx is cancelled. Call once per process.
func (a *AuditWriter) Run(ctx context.Context) {
	defer close(a.done)
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-a.queue:
			a.write(ctx, ev)
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

// Enqueue tries to push an event onto the queue. Drops if full so the
// hot path never blocks on DB latency.
func (a *AuditWriter) Enqueue(ev auditEvent) {
	select {
	case a.queue <- ev:
	default:
		log.Warn().Msg("audit queue full; dropping event")
	}
}
