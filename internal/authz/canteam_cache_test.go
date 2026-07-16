package authz

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// countingStore is a fake db.DBTX that records how many QueryRow calls reach it
// and Scans a fixed bool result. A per-call delay lets the test force concurrent
// misses so singleflight coalescing is observable.
type countingStore struct {
	result bool
	delay  time.Duration
	calls  atomic.Int64
}

func (s *countingStore) Exec(context.Context, string, ...interface{}) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}
func (s *countingStore) Query(context.Context, string, ...interface{}) (pgx.Rows, error) {
	return nil, nil
}
func (s *countingStore) QueryRow(context.Context, string, ...interface{}) pgx.Row {
	s.calls.Add(1)
	if s.delay > 0 {
		time.Sleep(s.delay)
	}
	return scanRow{result: s.result}
}

type scanRow struct{ result bool }

func (r scanRow) Scan(dest ...any) error {
	if len(dest) == 1 {
		if p, ok := dest[0].(*bool); ok {
			*p = r.result
		}
	}
	return nil
}

func TestCanTeamCachesGrants(t *testing.T) {
	store := &countingStore{result: true}
	s := New(store)
	user, team := uuid.New(), uuid.New()

	for i := 0; i < 5; i++ {
		ok, err := s.CanTeam(context.Background(), user, team, "settings:write")
		if err != nil || !ok {
			t.Fatalf("call %d: ok=%v err=%v", i, ok, err)
		}
	}
	if n := store.calls.Load(); n != 1 {
		t.Fatalf("expected 1 DB query for 5 cached calls, got %d", n)
	}
}

func TestCanTeamDoesNotCacheDenials(t *testing.T) {
	store := &countingStore{result: false}
	s := New(store)
	user, team := uuid.New(), uuid.New()

	for i := 0; i < 3; i++ {
		ok, _ := s.CanTeam(context.Background(), user, team, "settings:write")
		if ok {
			t.Fatalf("call %d: expected denied", i)
		}
	}
	// Denials are never cached, so every call re-queries.
	if n := store.calls.Load(); n != 3 {
		t.Fatalf("expected 3 DB queries for uncached denials, got %d", n)
	}
}

func TestCanTeamSingleflightCollapsesConcurrentMisses(t *testing.T) {
	store := &countingStore{result: true, delay: 30 * time.Millisecond}
	s := New(store)
	user, team := uuid.New(), uuid.New()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = s.CanTeam(context.Background(), user, team, "settings:write")
		}()
	}
	wg.Wait()

	// 50 concurrent identical misses should collapse to a small number of
	// queries (ideally 1); assert it's far below 50 to prove coalescing.
	if n := store.calls.Load(); n > 5 {
		t.Fatalf("expected concurrent misses to coalesce (<=5 queries), got %d", n)
	}
}
