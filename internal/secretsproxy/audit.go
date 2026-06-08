package secretsproxy

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
)

// AuditEvent is one row in the proxy_audit table.
type AuditEvent struct {
	TeamID    string
	SandboxID string
	SecretID  string // empty for passthrough (no credential used)

	Method string
	Host   string
	Path   string

	// Status is the status returned to the sandbox; UpstreamStatus is set only
	// when the request was forwarded.
	Status         int32
	UpstreamStatus *int32
	LatencyMs      int32
	// ErrorCode is the short proxy-reason on rejection.
	ErrorCode string
}

// AuditSink receives AuditEvents from the proxy.
type AuditSink interface {
	Emit(ev AuditEvent)
	// Shutdown drains buffered events, bounded by ctx.
	Shutdown(ctx context.Context) error
}

// nopAuditSink discards events.
type nopAuditSink struct{}

// NewNopAuditSink returns an AuditSink that discards every event.
func NewNopAuditSink() AuditSink { return nopAuditSink{} }

func (nopAuditSink) Emit(AuditEvent)                {}
func (nopAuditSink) Shutdown(context.Context) error { return nil }

// SQLAuditSink writes batched AuditEvents to proxy_audit. Drops on a full
// buffer instead of back-pressuring the request path.
type SQLAuditSink struct {
	queries *db.Queries

	bufSize   int
	batchSize int
	flushTick time.Duration

	ch       chan AuditEvent
	wg       sync.WaitGroup
	stopOnce sync.Once
	stop     chan struct{}

	dropMu  sync.Mutex
	dropped int64
}

// SQLAuditSinkOptions tunes the sink. Zero values fall back to defaults
// (BufferSize 4096, BatchSize 64, FlushInterval 250ms).
type SQLAuditSinkOptions struct {
	BufferSize    int
	BatchSize     int
	FlushInterval time.Duration
}

// NewSQLAuditSink starts the background writer.
func NewSQLAuditSink(queries *db.Queries, opts SQLAuditSinkOptions) *SQLAuditSink {
	if opts.BufferSize <= 0 {
		opts.BufferSize = 4096
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 64
	}
	if opts.FlushInterval <= 0 {
		opts.FlushInterval = 250 * time.Millisecond
	}
	s := &SQLAuditSink{
		queries:   queries,
		bufSize:   opts.BufferSize,
		batchSize: opts.BatchSize,
		flushTick: opts.FlushInterval,
		ch:        make(chan AuditEvent, opts.BufferSize),
		stop:      make(chan struct{}),
	}
	s.wg.Add(1)
	go s.run()
	return s
}

// Emit is non-blocking; drops on a full buffer (tracked by Dropped).
func (s *SQLAuditSink) Emit(ev AuditEvent) {
	select {
	case s.ch <- ev:
	default:
		s.dropMu.Lock()
		s.dropped++
		s.dropMu.Unlock()
	}
}

// Dropped returns the cumulative number of events dropped due to a full buffer.
func (s *SQLAuditSink) Dropped() int64 {
	s.dropMu.Lock()
	defer s.dropMu.Unlock()
	return s.dropped
}

// Shutdown stops the writer and drains the buffer, bounded by ctx.
func (s *SQLAuditSink) Shutdown(ctx context.Context) error {
	s.stopOnce.Do(func() { close(s.stop) })
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// run drains the channel into batched inserts on size or time triggers.
func (s *SQLAuditSink) run() {
	defer s.wg.Done()
	batch := make([]AuditEvent, 0, s.batchSize)
	ticker := time.NewTicker(s.flushTick)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		s.writeBatch(batch)
		batch = batch[:0]
	}

	for {
		select {
		case ev := <-s.ch:
			batch = append(batch, ev)
			if len(batch) >= s.batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-s.stop:
			// Drain queued events before exiting.
			for {
				select {
				case ev := <-s.ch:
					batch = append(batch, ev)
				default:
					flush()
					return
				}
			}
		}
	}
}

func (s *SQLAuditSink) writeBatch(batch []AuditEvent) {
	// Fire-and-forget: per-row failures are logged and skipped.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, ev := range batch {
		params, perr := auditEventToParams(ev)
		if perr != nil {
			log.Warn().Err(perr).Msg("secretsproxy: drop audit event with malformed ids")
			continue
		}
		if err := s.queries.InsertProxyAudit(ctx, params); err != nil {
			log.Warn().Err(err).Msg("secretsproxy: InsertProxyAudit failed")
		}
	}
}

func auditEventToParams(ev AuditEvent) (db.InsertProxyAuditParams, error) {
	teamID, err := uuid.Parse(ev.TeamID)
	if err != nil {
		return db.InsertProxyAuditParams{}, err
	}
	sandboxID, err := uuid.Parse(ev.SandboxID)
	if err != nil {
		return db.InsertProxyAuditParams{}, err
	}
	var secretID pgtype.UUID
	if ev.SecretID != "" {
		parsed, err := uuid.Parse(ev.SecretID)
		if err != nil {
			return db.InsertProxyAuditParams{}, err
		}
		secretID = pgtype.UUID{Bytes: parsed, Valid: true}
	}
	var errorCode *string
	if ev.ErrorCode != "" {
		c := ev.ErrorCode
		errorCode = &c
	}
	latency := ev.LatencyMs
	return db.InsertProxyAuditParams{
		TeamID:         teamID,
		SandboxID:      sandboxID,
		SecretID:       secretID,
		Method:         ev.Method,
		Host:           ev.Host,
		Path:           ev.Path,
		Status:         ev.Status,
		UpstreamStatus: ev.UpstreamStatus,
		LatencyMs:      &latency,
		ErrorCode:      errorCode,
	}, nil
}
