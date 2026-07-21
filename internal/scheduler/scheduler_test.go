package scheduler

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/superserve-ai/sandbox/internal/db"
)

// hostStore is a fake db.DBTX serving one host row per Query and counting calls.
type hostStore struct {
	calls       atomic.Int64
	block       chan struct{} // non-nil: Query waits until closed
	blockOnCall int64         // 0 = block every call; N = block only the Nth
}

func (h *hostStore) Exec(context.Context, string, ...interface{}) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}
func (h *hostStore) QueryRow(context.Context, string, ...interface{}) pgx.Row { return nil }
func (h *hostStore) Query(context.Context, string, ...interface{}) (pgx.Rows, error) {
	n := h.calls.Add(1)
	if h.block != nil && (h.blockOnCall == 0 || n == h.blockOnCall) {
		<-h.block
	}
	return &hostRows{id: fmt.Sprintf("host-%d", n)}, nil
}

// hostRows yields a single minimal host row whose ID names the query that
// produced it, so tests can tell which load's result the cache holds.
type hostRows struct {
	id   string
	done bool
}

func (r *hostRows) Close()                                       {}
func (r *hostRows) Err() error                                   { return nil }
func (r *hostRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *hostRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *hostRows) Values() ([]any, error)                       { return nil, nil }
func (r *hostRows) RawValues() [][]byte                          { return nil }
func (r *hostRows) Conn() *pgx.Conn                              { return nil }
func (r *hostRows) Next() bool {
	if r.done {
		return false
	}
	r.done = true
	return true
}
func (r *hostRows) Scan(dest ...any) error {
	*dest[0].(*string) = r.id // remaining columns keep zero values
	return nil
}

func TestLoadHostsServesStaleAndRefreshesInBackground(t *testing.T) {
	store := &hostStore{}
	s := &LeastLoaded{DB: db.New(store), TTL: time.Minute}

	// First call blocks and fills the cache.
	if _, err := s.SelectHost(context.Background()); err != nil {
		t.Fatalf("first select: %v", err)
	}
	if n := store.calls.Load(); n != 1 {
		t.Fatalf("expected 1 query, got %d", n)
	}

	// Age the cache far past the TTL; the next call must serve instantly from
	// the stale list and refresh behind it.
	s.mu.Lock()
	s.cachedAt = time.Now().Add(-s.ttl() - 5*time.Second) // stale, inside grace
	s.mu.Unlock()

	if _, err := s.SelectHost(context.Background()); err != nil {
		t.Fatalf("stale select: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for store.calls.Load() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("background refresh never ran, calls=%d", store.calls.Load())
		}
		time.Sleep(2 * time.Millisecond)
	}

	// Refresh landed: cache is fresh again, further calls stay cached.
	s.mu.RLock()
	fresh := time.Since(s.cachedAt) < time.Minute
	s.mu.RUnlock()
	if !fresh {
		t.Fatal("refresh must restore a fresh cachedAt")
	}
	if _, err := s.SelectHost(context.Background()); err != nil {
		t.Fatalf("post-refresh select: %v", err)
	}
	if n := store.calls.Load(); n != 2 {
		t.Fatalf("fresh cache must not re-query, got %d", n)
	}
}

func TestLoadHostsStaleServeDoesNotBlockOnSlowRefresh(t *testing.T) {
	store := &hostStore{}
	s := &LeastLoaded{DB: db.New(store), TTL: time.Minute}
	if _, err := s.SelectHost(context.Background()); err != nil {
		t.Fatalf("prime: %v", err)
	}

	// Refresh query hangs; stale selects must return instantly anyway, and the
	// CAS guard must keep it to a single in-flight refresh.
	store.block = make(chan struct{})
	s.mu.Lock()
	s.cachedAt = time.Now().Add(-s.ttl() - 5*time.Second) // stale, inside grace
	s.mu.Unlock()

	done := make(chan struct{})
	go func() {
		for i := 0; i < 10; i++ {
			_, _ = s.SelectHost(context.Background())
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stale selects blocked behind the hanging refresh")
	}
	// Wait for the (single) guarded refresh goroutine to reach its query, then
	// confirm the CAS kept it to exactly one despite 10 stale selects.
	deadline := time.Now().Add(2 * time.Second)
	for store.calls.Load() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("refresh goroutine never started, calls=%d", store.calls.Load())
		}
		time.Sleep(2 * time.Millisecond)
	}
	if n := store.calls.Load(); n != 2 { // prime + one guarded refresh
		t.Errorf("expected a single in-flight refresh, got %d queries", n)
	}
	close(store.block)
}

func TestInvalidateForcesBlockingReload(t *testing.T) {
	store := &hostStore{}
	s := &LeastLoaded{DB: db.New(store), TTL: time.Minute}
	if _, err := s.SelectHost(context.Background()); err != nil {
		t.Fatalf("prime: %v", err)
	}

	s.Invalidate()
	if _, err := s.SelectHost(context.Background()); err != nil {
		t.Fatalf("post-invalidate select: %v", err)
	}
	if n := store.calls.Load(); n != 2 {
		t.Fatalf("invalidate must force a blocking reload, got %d queries", n)
	}
}

func TestInvalidateBeatsInFlightRefresh(t *testing.T) {
	store := &hostStore{}
	s := &LeastLoaded{DB: db.New(store), TTL: time.Minute}
	if _, err := s.SelectHost(context.Background()); err != nil {
		t.Fatalf("prime: %v", err)
	}

	// Hold a background refresh in flight, then invalidate underneath it.
	store.block = make(chan struct{})
	s.mu.Lock()
	s.cachedAt = time.Now().Add(-s.ttl() - 5*time.Second) // stale, inside grace
	s.mu.Unlock()
	if _, err := s.SelectHost(context.Background()); err != nil { // triggers the refresh
		t.Fatalf("stale select: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for store.calls.Load() < 2 { // refresh goroutine reached its (blocked) query
		if time.Now().After(deadline) {
			t.Fatalf("refresh never started, calls=%d", store.calls.Load())
		}
		time.Sleep(2 * time.Millisecond)
	}

	s.Invalidate()      // host retired while the refresh holds the old list
	close(store.block)  // the pre-invalidation refresh now returns

	// The stale refresh must be discarded: the cache stays empty until a
	// fresh blocking load, not resurrected with the pre-invalidation list.
	deadline = time.Now().Add(2 * time.Second)
	for {
		s.mu.RLock()
		resurrected := s.cached != nil
		s.mu.RUnlock()
		if !resurrected && !s.refreshing.Load() {
			break // refresh finished and stored nothing
		}
		if resurrected {
			t.Fatal("pre-invalidation refresh resurrected the retired host list")
		}
		if time.Now().After(deadline) {
			t.Fatal("refresh goroutine never finished")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestLoadHostsPastGraceBlocksInsteadOfServingStale(t *testing.T) {
	store := &hostStore{}
	s := &LeastLoaded{DB: db.New(store), TTL: time.Minute}
	if _, err := s.SelectHost(context.Background()); err != nil {
		t.Fatalf("prime: %v", err)
	}

	// Way past ttl+grace (refreshes never landed): must block on a fresh
	// load, not keep serving a possibly-dead host list.
	s.mu.Lock()
	s.cachedAt = time.Now().Add(-time.Hour)
	s.mu.Unlock()

	if _, err := s.SelectHost(context.Background()); err != nil {
		t.Fatalf("past-grace select: %v", err)
	}
	if n := store.calls.Load(); n != 2 {
		t.Fatalf("past-grace select must reload synchronously, got %d queries", n)
	}
}

func TestBlockingReloadNotClobberedBySlowRefresh(t *testing.T) {
	store := &hostStore{}
	s := &LeastLoaded{DB: db.New(store), TTL: time.Minute}
	if _, err := s.SelectHost(context.Background()); err != nil { // query 1
		t.Fatalf("prime: %v", err)
	}

	// Hold only the background refresh (query 2) in flight.
	store.block = make(chan struct{})
	store.blockOnCall = 2
	s.mu.Lock()
	s.cachedAt = time.Now().Add(-s.ttl() - 5*time.Second) // stale, inside grace
	s.mu.Unlock()
	if _, err := s.SelectHost(context.Background()); err != nil { // kicks the refresh
		t.Fatalf("stale select: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for store.calls.Load() < 2 { // refresh goroutine reached its (blocked) query
		if time.Now().After(deadline) {
			t.Fatalf("refresh never started, calls=%d", store.calls.Load())
		}
		time.Sleep(2 * time.Millisecond)
	}

	// Age past grace: the next call reloads synchronously (query 3) and must
	// retire the still-hanging refresh so its older result cannot land on top.
	s.mu.Lock()
	s.cachedAt = time.Now().Add(-time.Hour)
	s.mu.Unlock()
	if _, err := s.SelectHost(context.Background()); err != nil {
		t.Fatalf("past-grace select: %v", err)
	}
	close(store.block) // the pre-reload refresh now returns

	deadline = time.Now().Add(2 * time.Second)
	for s.refreshing.Load() { // wait until the refresh goroutine finished
		if time.Now().After(deadline) {
			t.Fatal("refresh goroutine never finished")
		}
		time.Sleep(2 * time.Millisecond)
	}
	s.mu.RLock()
	id := s.cached[0].ID
	s.mu.RUnlock()
	if id != "host-3" {
		t.Fatalf("older refresh clobbered the blocking reload: cached %s, want host-3", id)
	}
}
