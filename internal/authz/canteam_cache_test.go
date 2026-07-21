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
// misses so singleflight coalescing is observable. lastCtxErr records the
// context state the query ran under, to distinguish caller-context (uncached)
// from detached-context (cached) paths.
type countingStore struct {
	result     bool
	delay      time.Duration
	calls      atomic.Int64
	lastCtxErr atomic.Value // error or nil sentinel
}

func (s *countingStore) Exec(context.Context, string, ...interface{}) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}
func (s *countingStore) Query(context.Context, string, ...interface{}) (pgx.Rows, error) {
	return nil, nil
}
func (s *countingStore) QueryRow(ctx context.Context, _ string, _ ...interface{}) pgx.Row {
	s.calls.Add(1)
	if err := ctx.Err(); err != nil {
		s.lastCtxErr.Store(err)
	}
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

func newCachedForTest(store *countingStore) *Service {
	return NewCached(store)
}

func (s *Service) cacheLen() int {
	s.cache.mu.Lock()
	defer s.cache.mu.Unlock()
	return len(s.cache.m)
}

func TestCanTeamCachesGrants(t *testing.T) {
	store := &countingStore{result: true}
	s := newCachedForTest(store)
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
	s := newCachedForTest(store)
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

// Plain New() instances (the per-transaction shape) must not cache and must run
// the query under the caller's context, so a client disconnect cancels a check
// that runs while the tx holds the per-team advisory lock.
func TestCanTeamUncachedInstanceQueriesEveryCallWithCallerContext(t *testing.T) {
	store := &countingStore{result: true}
	s := New(store)
	user, team := uuid.New(), uuid.New()

	_, _ = s.CanTeam(context.Background(), user, team, "settings:write")
	_, _ = s.CanTeam(context.Background(), user, team, "settings:write")
	if n := store.calls.Load(); n != 2 {
		t.Fatalf("uncached instance must query every call, got %d queries", n)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = s.CanTeam(ctx, user, team, "settings:write")
	if err, _ := store.lastCtxErr.Load().(error); err == nil {
		t.Fatal("uncached query must run under the caller's context (cancellation not visible)")
	}
}

func TestCanTeamInvalidateTeamForcesRequery(t *testing.T) {
	store := &countingStore{result: true}
	s := newCachedForTest(store)
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
	s := NewCached(store)
	user, team := uuid.New(), uuid.New()

	done := make(chan bool, 1)
	go func() {
		ok, _ := s.CanTeam(context.Background(), user, team, "settings:write")
		done <- ok
	}()

	<-store.entered        // query is in flight, reading the (still valid) grant
	s.InvalidateTeam(team) // role revoked + committed → generation bumped mid-query
	close(store.release)   // query returns the stale true; the store must discard it
	if !<-done {
		t.Fatal("in-flight query should still return its observed grant")
	}

	// The stale result must not have been cached: a subsequent check re-queries
	// and sees the revoked state.
	countingBacking := &countingStore{result: false}
	s.store = countingBacking
	ok, _ := s.CanTeam(context.Background(), user, team, "settings:write")
	if ok {
		t.Fatal("revoked grant was resurrected from cache after invalidation")
	}
	if n := countingBacking.calls.Load(); n != 1 {
		t.Fatalf("expected a re-query after invalidation, got %d queries", n)
	}
	if s.cacheLen() != 0 {
		t.Fatalf("stale-generation result must be discarded, cache holds %d entries", s.cacheLen())
	}
}

func TestCanTeamLateJoinerAfterInvalidateStartsFreshQuery(t *testing.T) {
	gate := &gateStore{result: true, entered: make(chan struct{}), release: make(chan struct{})}
	s := NewCached(gate)
	user, team := uuid.New(), uuid.New()

	aResult := make(chan bool, 1)
	go func() {
		ok, _ := s.CanTeam(context.Background(), user, team, "settings:write")
		aResult <- ok
	}()
	<-gate.entered // A's pre-revocation query is in flight

	s.InvalidateTeam(team) // role revoked, generation bumped

	// B arrives after the revocation. It must NOT coalesce onto A's in-flight
	// query (different generation in the singleflight key); it starts its own
	// query against the post-revocation state.
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

func TestCanTeamCacheStaysBounded(t *testing.T) {
	store := &countingStore{result: true}
	s := newCachedForTest(store)
	team := uuid.New()

	// Insert well past the cap with distinct users; the overflow sweep finds
	// nothing expired and resets, so the map never exceeds the cap.
	for i := 0; i < teamPermCacheMaxEntries+50; i++ {
		_, _ = s.CanTeam(context.Background(), uuid.New(), team, "settings:write")
	}
	if n := s.cacheLen(); n > teamPermCacheMaxEntries {
		t.Fatalf("cache grew past the cap: %d > %d", n, teamPermCacheMaxEntries)
	}
}

func TestCanTeamSingleflightCollapsesConcurrentMisses(t *testing.T) {
	store := &countingStore{result: true, delay: 30 * time.Millisecond}
	s := newCachedForTest(store)
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

// ageTeamPermEntry rewinds a cached entry's expiry so tests can enter the
// stale-grace and past-grace windows without waiting out real TTLs.
func ageTeamPermEntry(s *Service, key teamPermCacheKey, expiry time.Time) {
	s.cache.mu.Lock()
	e := s.cache.m[key]
	e.expiry = expiry
	s.cache.m[key] = e
	s.cache.mu.Unlock()
}

func waitForCalls(t *testing.T, c *atomic.Int64, want int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for c.Load() < want {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d calls, have %d", want, c.Load())
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestCanTeamStaleServeRefreshesInBackground(t *testing.T) {
	store := &countingStore{result: true}
	s := newCachedForTest(store)
	user, team := uuid.New(), uuid.New()
	key := teamPermCacheKey{userID: user, teamID: team, permission: "settings:write"}

	if ok, _ := s.CanTeam(context.Background(), user, team, "settings:write"); !ok {
		t.Fatal("prime failed")
	}
	ageTeamPermEntry(s, key, time.Now().Add(-time.Second)) // expired, inside grace

	// Served instantly from the stale entry — no blocking on the refresh.
	if ok, err := s.CanTeam(context.Background(), user, team, "settings:write"); !ok || err != nil {
		t.Fatalf("stale entry must be served: ok=%v err=%v", ok, err)
	}
	// The background refresh runs exactly one more query and re-freshens the entry.
	waitForCalls(t, &store.calls, 2)
	s.cache.mu.Lock()
	fresh := time.Now().Before(s.cache.m[key].expiry)
	s.cache.mu.Unlock()
	if !fresh {
		t.Fatal("background refresh must restore a fresh expiry")
	}
}

func TestCanTeamStaleNeverServedAcrossGenerationBump(t *testing.T) {
	store := &countingStore{result: true}
	s := newCachedForTest(store)
	user, team := uuid.New(), uuid.New()
	key := teamPermCacheKey{userID: user, teamID: team, permission: "settings:write"}

	_, _ = s.CanTeam(context.Background(), user, team, "settings:write")
	ageTeamPermEntry(s, key, time.Now().Add(-time.Second))
	// Out-of-band generation bump (what a revocation does) without touching
	// the entry: the stale grant must NOT be served on the old generation.
	s.cache.mu.Lock()
	s.cache.gen[team]++
	s.cache.mu.Unlock()
	store.result = false

	if ok, _ := s.CanTeam(context.Background(), user, team, "settings:write"); ok {
		t.Fatal("revoked (generation-bumped) grant was stale-served")
	}
	if n := store.calls.Load(); n != 2 {
		t.Fatalf("expected a blocking re-query, got %d calls", n)
	}
}

func TestCanTeamStaleDenialRefreshDropsEntry(t *testing.T) {
	store := &countingStore{result: true}
	s := newCachedForTest(store)
	user, team := uuid.New(), uuid.New()
	key := teamPermCacheKey{userID: user, teamID: team, permission: "settings:write"}

	_, _ = s.CanTeam(context.Background(), user, team, "settings:write")
	ageTeamPermEntry(s, key, time.Now().Add(-time.Second))
	store.result = false // the grant has been revoked upstream

	// Grace window: the stale grant is served once while the refresh runs.
	if ok, _ := s.CanTeam(context.Background(), user, team, "settings:write"); !ok {
		t.Fatal("expected stale serve inside grace")
	}
	waitForCalls(t, &store.calls, 2)
	// The refresh saw the denial and dropped the entry: no more stale serves.
	if ok, _ := s.CanTeam(context.Background(), user, team, "settings:write"); ok {
		t.Fatal("denial-refreshed entry must not be served")
	}
}

func TestCanTeamPastGraceBlocks(t *testing.T) {
	store := &countingStore{result: true}
	s := newCachedForTest(store)
	user, team := uuid.New(), uuid.New()
	key := teamPermCacheKey{userID: user, teamID: team, permission: "settings:write"}

	_, _ = s.CanTeam(context.Background(), user, team, "settings:write")
	ageTeamPermEntry(s, key, time.Now().Add(-teamPermStaleGrace-time.Second))

	if ok, _ := s.CanTeam(context.Background(), user, team, "settings:write"); !ok {
		t.Fatal("past-grace check must still succeed via blocking query")
	}
	if n := store.calls.Load(); n != 2 {
		t.Fatalf("past-grace entry must block on a fresh query, got %d calls", n)
	}
}
