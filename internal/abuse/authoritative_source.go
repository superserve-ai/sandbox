package abuse

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/db"
)

type CacheStats struct {
	Ready            bool
	DenyEntries      int
	DenyCapacity     int
	TrustedTeams     int
	Expired          int
	CapacityRejected int
	Generation       int64
	LastSuccess      time.Time
}

type AuthoritativeOptions struct {
	Capacity int
	TTL      time.Duration
	Interval time.Duration
	Report   func(string, CacheStats)
	Loader   PolicyLoader
}

type publishedPolicy struct {
	snapshot    *ComputeSnapshot
	records     map[uuid.UUID]PolicyRecord
	generation  int64
	lastSuccess time.Time
	fresh       bool
}

// AuthoritativeSource publishes immutable projections. All expiry, capacity
// and database work happens in the writer; admission retains its map lookups.
type AuthoritativeSource struct {
	q       db.DBTX
	opts    AuthoritativeOptions
	mu      sync.Mutex
	current atomic.Pointer[publishedPolicy]
	changes chan struct{}
	now     func() time.Time
}

func NewAuthoritativeSource(q db.DBTX, opts AuthoritativeOptions) *AuthoritativeSource {
	if opts.Capacity <= 0 {
		opts.Capacity = 16384
	}
	if opts.TTL <= 0 {
		opts.TTL = time.Hour
	}
	if opts.Interval <= 0 {
		opts.Interval = 2 * time.Second
	}
	if opts.Loader == nil {
		opts.Loader = DatabasePolicyLoader(q)
	}
	return &AuthoritativeSource{q: q, opts: opts, changes: make(chan struct{}, 1), now: time.Now}
}

func (s *AuthoritativeSource) Snapshot() *ComputeSnapshot {
	if p := s.current.Load(); p != nil {
		return p.snapshot
	}
	return nil
}

func (s *AuthoritativeSource) TeamPolicy(team uuid.UUID) TeamPolicy {
	policy := TeamPolicy{TeamID: team}
	p := s.current.Load()
	if p == nil || team == uuid.Nil {
		return policy
	}
	policy.Trusted = p.snapshot.trusted[team]
	policy.Known, policy.Mode, policy.Generation = p.fresh || policy.Trusted, p.snapshot.mode, p.generation
	policy.Restricted = !policy.Trusted && p.snapshot.teams[team]
	return policy
}

func (s *AuthoritativeSource) CurrentTeamPolicy(ctx context.Context, team uuid.UUID) (TeamPolicy, error) {
	if s.q == nil {
		return TeamPolicy{TeamID: team}, fmt.Errorf("authoritative policy database unavailable")
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return ResolveTeamPolicy(lookupCtx, s.q, team)
}

func (s *AuthoritativeSource) Changes() <-chan struct{} { return s.changes }

func (s *AuthoritativeSource) Run(ctx context.Context) {
	s.Refresh(ctx)
	ticker := time.NewTicker(s.opts.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.Refresh(ctx)
		}
	}
}

func (s *AuthoritativeSource) Refresh(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	previous := s.current.Load()
	trusted := make(map[uuid.UUID]PolicyRecord)
	retained := make(map[uuid.UUID]PolicyRecord)
	newRecords := make([]PolicyRecord, 0, s.opts.Capacity)
	total := 0
	refreshCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	mode, generation, err := s.opts.Loader(refreshCtx, func(record PolicyRecord) {
		if record.TeamID == uuid.Nil {
			return
		}
		if record.Trusted {
			trusted[record.TeamID] = PolicyRecord{TeamID: record.TeamID, Trusted: true}
			return
		}
		if !record.Restricted || (record.ExpiresAt != nil && !record.ExpiresAt.After(s.now())) {
			return
		}
		total++
		if previous != nil && previous.snapshot.teams[record.TeamID] {
			retained[record.TeamID] = record
		} else if len(newRecords) < s.opts.Capacity {
			newRecords = append(newRecords, record)
		}
	})
	cancel()
	if err != nil || !ValidComputeMode(mode) {
		s.pruneLocked(previous)
		s.report("sync_error", CacheStats{})
		return
	}
	records := trusted
	count := 0
	for id, record := range retained {
		if count == s.opts.Capacity {
			break
		}
		records[id] = record
		count++
	}
	for _, record := range newRecords {
		if count == s.opts.Capacity {
			break
		}
		records[record.TeamID] = record
		count++
	}
	s.publishLocked(mode, generation, records, s.now())
	stats := CacheStats{CapacityRejected: total - count}
	if stats.CapacityRejected > 0 {
		s.report("capacity_rejected", stats)
	} else {
		s.report("success", stats)
	}
}

func (s *AuthoritativeSource) pruneLocked(previous *publishedPolicy) {
	if previous == nil {
		return
	}
	now := s.now()
	records := make(map[uuid.UUID]PolicyRecord, len(previous.records))
	expired := 0
	for id, record := range previous.records {
		if !record.Trusted && (now.Sub(previous.lastSuccess) >= s.opts.TTL || (record.ExpiresAt != nil && !record.ExpiresAt.After(now))) {
			expired++
			continue
		}
		records[id] = record
	}
	if expired > 0 || (previous.fresh && now.Sub(previous.lastSuccess) >= s.opts.TTL) {
		s.publishLocked(previous.snapshot.mode, previous.generation, records, previous.lastSuccess)
		s.report("expired", CacheStats{Expired: expired})
	}
}

func (s *AuthoritativeSource) publishLocked(mode ComputeMode, generation int64, records map[uuid.UUID]PolicyRecord, lastSuccess time.Time) {
	snapshot := &ComputeSnapshot{mode: mode, trusted: make(map[uuid.UUID]bool), teams: make(map[uuid.UUID]bool)}
	for id, record := range records {
		if record.Trusted {
			snapshot.trusted[id] = true
		} else if record.Restricted {
			snapshot.teams[id] = true
		}
	}
	previous := s.current.Swap(&publishedPolicy{snapshot: snapshot, records: records, generation: generation, lastSuccess: lastSuccess, fresh: s.now().Sub(lastSuccess) < s.opts.TTL})
	if previous == nil || !reflect.DeepEqual(previous.snapshot, snapshot) {
		select {
		case s.changes <- struct{}{}:
		default:
		}
	}
}

func (s *AuthoritativeSource) Stats() CacheStats {
	stats := CacheStats{DenyCapacity: s.opts.Capacity}
	if p := s.current.Load(); p != nil {
		stats.Ready, stats.Generation, stats.LastSuccess = p.fresh, p.generation, p.lastSuccess
		stats.DenyEntries, stats.TrustedTeams = len(p.snapshot.teams), len(p.snapshot.trusted)
	}
	return stats
}

func (s *AuthoritativeSource) report(result string, event CacheStats) {
	if s.opts.Report == nil {
		return
	}
	stats := s.Stats()
	stats.Expired, stats.CapacityRejected = event.Expired, event.CapacityRejected
	s.opts.Report(result, stats)
}
