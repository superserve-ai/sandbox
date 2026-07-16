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

func TestCanTeamInvalidateTeamForcesRequery(t *testing.T) {
	store := &countingStore{result: true}
	s := New(store)
	user, team := uuid.New(), uuid.New()
	other := uuid.New()

	// Prime the cache for two teams.
	_, _ = s.CanTeam(context.Background(), user, team, "settings:write")
	_, _ = s.CanTeam(context.Background(), user, other, "settings:write")
	if n := store.calls.Load(); n != 2 {
		t.Fatalf("expected 2 priming queries, got %d", n)
	}

	s.InvalidateTeam(team)

	// The invalidated team re-queries; the untouched team still hits cache.
	_, _ = s.CanTeam(context.Background(), user, team, "settings:write")
	_, _ = s.CanTeam(context.Background(), user, other, "settings:write")
	if n := store.calls.Load(); n != 3 {
		t.Fatalf("expected 1 re-query for the invalidated team only, total 3, got %d", n)
	}
}

// gateStore lets the test hold a query in flight, invalidate mid-query, then
// release — reproducing the store-after-invalidate race.
type gateStore struct {
	result  bool
	entered chan struct{}
	release chan struct{}
	calls   atomic.Int64
}

func (s *gateStore) Exec(context.Context, string, ...interface{}) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}
func (s *gateStore) Query(context.Context, string, ...interface{}) (pgx.Rows, error) {
	return nil, nil
}
func (s *gateStore) QueryRow(context.Context, string, ...interface{}) pgx.Row {
	s.calls.Add(1)
	close(s.entered)
	<-s.release
	return scanRow{result: s.result}
}

func TestCanTeamStoreAfterInvalidateDoesNotResurrectGrant(t *testing.T) {
	store := &gateStore{result: true, entered: make(chan struct{}), release: make(chan struct{})}
	s := New(store)
	user, team := uuid.New(), uuid.New()

	done := make(chan bool, 1)
	go func() {
		ok, _ := s.CanTeam(context.Background(), user, team, "settings:write")
		done <- ok
	}()

	<-store.entered           // query is in flight, reading the (still valid) grant
	s.InvalidateTeam(team)    // role revoked + committed → epoch bumped mid-query
	close(store.release)      // query now returns the stale true and stores it
	if !<-done {
		t.Fatal("in-flight query should still return its observed grant")
	}

	// The store landed after invalidation. A subsequent check must NOT be served
	// from cache — it must re-query, because the stored entry is a stale epoch.
	countingBacking := &countingStore{result: false}
	s.store = countingBacking
	ok, _ := s.CanTeam(context.Background(), user, team, "settings:write")
	if ok {
		t.Fatal("revoked grant was resurrected from cache after invalidation")
	}
	if n := countingBacking.calls.Load(); n != 1 {
		t.Fatalf("expected a re-query after invalidation, got %d queries", n)
	}
}

func TestCanTeamLateJoinerAfterInvalidateStartsFreshQuery(t *testing.T) {
	gate := &gateStore{result: true, entered: make(chan struct{}), release: make(chan struct{})}
	s := New(gate)
	user, team := uuid.New(), uuid.New()

	aResult := make(chan bool, 1)
	go func() {
		ok, _ := s.CanTeam(context.Background(), user, team, "settings:write")
		aResult <- ok
	}()
	<-gate.entered // A's pre-revocation query is in flight

	s.InvalidateTeam(team) // role revoked, epoch bumped

	// B arrives after the revocation. It must NOT coalesce onto A's in-flight
	// query (different epoch in the singleflight key); it starts its own query
	// against the post-revocation state.
	fresh := &countingStore{result: false}
	s.store = fresh
	bOK, _ := s.CanTeam(context.Background(), user, team, "settings:write")
	if bOK {
		t.Fatal("post-revocation request was served A's stale grant via singleflight")
	}
	if n := fresh.calls.Load(); n != 1 {
		t.Fatalf("expected B to run its own query, got %d", n)
	}

	close(gate.release)
	<-aResult // A drains (its pre-revocation grant is acceptable)
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
