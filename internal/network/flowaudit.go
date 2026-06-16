package network

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
)

// FlowEvent is one egress connection observed by the proxy. team_id is resolved
// by the writer from SandboxID, so the hot path never needs team context.
type FlowEvent struct {
	SandboxID  string // sandbox UUID (the proxy's host-IP → sandbox mapping)
	Protocol   string // 'http' | 'tls' | 'other'
	Host       string // SNI / Host header; empty for raw connections
	DstIP      string
	DstPort    int32
	Verdict    string // 'allowed' | 'blocked' | 'failed'
	MatchRule  string
	BytesSent  int64
	BytesRecv  int64
	DurationMs int32
}

// FlowSink receives FlowEvents from the egress proxy.
type FlowSink interface {
	Emit(ev FlowEvent)
	Shutdown(ctx context.Context) error
}

// nopFlowSink discards events. Used when no DB is configured so the proxy's
// data path is identical to having no logging at all.
type nopFlowSink struct{}

// NewNopFlowSink returns a FlowSink that discards every event.
func NewNopFlowSink() FlowSink { return nopFlowSink{} }

func (nopFlowSink) Emit(FlowEvent)                 {}
func (nopFlowSink) Shutdown(context.Context) error { return nil }

// SQLFlowSink writes batched FlowEvents to net_flow. Drops on a full buffer
// instead of back-pressuring the connection path.
type SQLFlowSink struct {
	queries *db.Queries

	batchSize int
	flushTick time.Duration

	ch       chan FlowEvent
	wg       sync.WaitGroup
	stopOnce sync.Once
	stop     chan struct{}

	dropMu  sync.Mutex
	dropped int64

	// resolveTeam looks up a sandbox's team; defaults to the DB query.
	resolveTeam func(context.Context, uuid.UUID) (uuid.UUID, error)

	// teams caches sandbox_id → team_id so each insert doesn't re-query.
	teamMu sync.Mutex
	teams  map[uuid.UUID]uuid.UUID
}

// SQLFlowSinkOptions tunes the sink. Zero values fall back to defaults
// (BufferSize 8192, BatchSize 128, FlushInterval 500ms).
type SQLFlowSinkOptions struct {
	BufferSize    int
	BatchSize     int
	FlushInterval time.Duration
}

// NewSQLFlowSink starts the background writer.
func NewSQLFlowSink(queries *db.Queries, opts SQLFlowSinkOptions) *SQLFlowSink {
	if opts.BufferSize <= 0 {
		opts.BufferSize = 8192
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 128
	}
	if opts.FlushInterval <= 0 {
		opts.FlushInterval = 500 * time.Millisecond
	}
	s := &SQLFlowSink{
		queries:   queries,
		batchSize: opts.BatchSize,
		flushTick: opts.FlushInterval,
		ch:        make(chan FlowEvent, opts.BufferSize),
		stop:      make(chan struct{}),
		teams:     make(map[uuid.UUID]uuid.UUID),
	}
	if queries != nil {
		s.resolveTeam = queries.GetSandboxTeamID
	}
	s.wg.Add(1)
	go s.run()
	return s
}

// Emit is non-blocking; drops on a full buffer (tracked by Dropped).
func (s *SQLFlowSink) Emit(ev FlowEvent) {
	select {
	case s.ch <- ev:
	default:
		s.dropMu.Lock()
		s.dropped++
		s.dropMu.Unlock()
	}
}

// Dropped returns the cumulative number of events dropped due to a full buffer.
func (s *SQLFlowSink) Dropped() int64 {
	s.dropMu.Lock()
	defer s.dropMu.Unlock()
	return s.dropped
}

// Shutdown stops the writer and drains the buffer, bounded by ctx.
func (s *SQLFlowSink) Shutdown(ctx context.Context) error {
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

func (s *SQLFlowSink) run() {
	defer s.wg.Done()
	batch := make([]FlowEvent, 0, s.batchSize)
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

func (s *SQLFlowSink) writeBatch(batch []FlowEvent) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, ev := range batch {
		params, ok := s.eventToParams(ctx, ev)
		if !ok {
			continue
		}
		if err := s.queries.InsertNetFlow(ctx, params); err != nil {
			log.Warn().Err(err).Msg("network: InsertNetFlow failed")
		}
	}
}

// maxTeamCache bounds the sandbox→team map so it can't grow without limit
// over the host's lifetime. At the cap, an arbitrary entry is evicted; a
// re-lookup just re-populates it.
const maxTeamCache = 4096

// teamFor resolves and caches the team for a sandbox. Returns false when the
// sandbox can't be resolved (e.g. already destroyed) — the event is dropped
// rather than written without a team.
func (s *SQLFlowSink) teamFor(ctx context.Context, sandboxID uuid.UUID) (uuid.UUID, bool) {
	s.teamMu.Lock()
	if t, ok := s.teams[sandboxID]; ok {
		s.teamMu.Unlock()
		return t, true
	}
	s.teamMu.Unlock()

	if s.resolveTeam == nil {
		return uuid.UUID{}, false
	}
	team, err := s.resolveTeam(ctx, sandboxID)
	if err != nil {
		return uuid.UUID{}, false
	}
	s.teamMu.Lock()
	if len(s.teams) >= maxTeamCache {
		for k := range s.teams {
			delete(s.teams, k)
			break
		}
	}
	s.teams[sandboxID] = team
	s.teamMu.Unlock()
	return team, true
}

func (s *SQLFlowSink) eventToParams(ctx context.Context, ev FlowEvent) (db.InsertNetFlowParams, bool) {
	sandboxID, err := uuid.Parse(ev.SandboxID)
	if err != nil {
		return db.InsertNetFlowParams{}, false
	}
	teamID, ok := s.teamFor(ctx, sandboxID)
	if !ok {
		return db.InsertNetFlowParams{}, false
	}
	return flowParams(ev, sandboxID, teamID)
}

// flowParams builds insert params from an event and its resolved ids.
func flowParams(ev FlowEvent, sandboxID, teamID uuid.UUID) (db.InsertNetFlowParams, bool) {
	dstIP, err := netip.ParseAddr(ev.DstIP)
	if err != nil {
		return db.InsertNetFlowParams{}, false
	}
	var host *string
	if ev.Host != "" {
		h := ev.Host
		host = &h
	}
	var matchRule *string
	if ev.MatchRule != "" {
		m := ev.MatchRule
		matchRule = &m
	}
	var bytesSent, bytesRecv *int64
	if ev.BytesSent > 0 {
		bytesSent = &ev.BytesSent
	}
	if ev.BytesRecv > 0 {
		bytesRecv = &ev.BytesRecv
	}
	var durationMs *int32
	if ev.DurationMs > 0 {
		durationMs = &ev.DurationMs
	}
	return db.InsertNetFlowParams{
		TeamID:     teamID,
		SandboxID:  sandboxID,
		Protocol:   ev.Protocol,
		Host:       host,
		DstIp:      dstIP,
		DstPort:    ev.DstPort,
		Verdict:    ev.Verdict,
		MatchRule:  matchRule,
		BytesSent:  bytesSent,
		BytesRecv:  bytesRecv,
		DurationMs: durationMs,
	}, true
}
