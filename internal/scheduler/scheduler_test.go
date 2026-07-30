package scheduler

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/preview"
)

type queryCapture struct {
	sql   string
	args  [][]string
	calls int
}

func (c *queryCapture) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, fmt.Errorf("unexpected Exec")
}

func (c *queryCapture) Query(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
	c.sql = sql
	c.calls++
	c.args = append(c.args, append([]string(nil), args[0].([]string)...))
	return schedulerEmptyRows{}, nil
}

func (c *queryCapture) QueryRow(context.Context, string, ...any) pgx.Row {
	return schedulerErrorRow{err: fmt.Errorf("unexpected QueryRow")}
}

type schedulerErrorRow struct{ err error }

func (r schedulerErrorRow) Scan(...any) error { return r.err }

type schedulerEmptyRows struct{}

func (schedulerEmptyRows) Close()                                       {}
func (schedulerEmptyRows) Err() error                                   { return nil }
func (schedulerEmptyRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (schedulerEmptyRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (schedulerEmptyRows) Next() bool                                   { return false }
func (schedulerEmptyRows) Scan(...any) error                            { return fmt.Errorf("no row") }
func (schedulerEmptyRows) Values() ([]any, error)                       { return nil, nil }
func (schedulerEmptyRows) RawValues() [][]byte                          { return nil }
func (schedulerEmptyRows) Conn() *pgx.Conn                              { return nil }

func TestLeastLoadedQueryExcludesHostsWithoutPreviewEnforcement(t *testing.T) {
	capture := &queryCapture{}
	s := &LeastLoaded{DB: db.New(capture), DefaultHostID: "fallback"}
	required := []string{preview.HostCapabilityPorts}
	got, err := s.SelectHost(context.Background(), required)
	if err != nil {
		t.Fatalf("SelectHost: %v", err)
	}
	if got != "fallback" {
		t.Fatalf("host = %q, want fallback", got)
	}
	if !strings.Contains(capture.sql, "FROM host_capability") ||
		!strings.Contains(capture.sql, "FROM unnest(") ||
		strings.Count(capture.sql, "NOT EXISTS") < 2 ||
		!strings.Contains(capture.sql, "hc.heartbeat_at = h.last_heartbeat_at") {
		t.Fatalf("scheduler query does not require all current-heartbeat capabilities:\n%s", capture.sql)
	}
	if !reflect.DeepEqual(capture.args, [][]string{required}) {
		t.Fatalf("query capabilities = %#v, want %#v", capture.args, [][]string{required})
	}
}

func TestLeastLoadedCachesCandidateSetsByCanonicalCapabilities(t *testing.T) {
	capture := &queryCapture{}
	s := &LeastLoaded{DB: db.New(capture), DefaultHostID: "fallback"}
	ctx := context.Background()

	public := []string{preview.HostCapabilityPorts}
	private := []string{preview.HostCapabilityPortBrowserAuth, preview.HostCapabilityPortTokens, preview.HostCapabilityPortAccess, preview.HostCapabilityPorts}
	for _, required := range [][]string{public, public, private, {
		preview.HostCapabilityPorts, preview.HostCapabilityPortTokens, preview.HostCapabilityPortAccess,
		preview.HostCapabilityPortBrowserAuth, preview.HostCapabilityPorts, preview.HostCapabilityPortTokens,
	}} {
		if got, err := s.SelectHost(ctx, required); err != nil || got != "fallback" {
			t.Fatalf("SelectHost(%v) = (%q, %v), want fallback", required, got, err)
		}
	}

	if capture.calls != 2 {
		t.Fatalf("query calls = %d, want 2 capability-specific cache fills", capture.calls)
	}
	wantPrivate := []string{
		preview.HostCapabilityPortAccess,
		preview.HostCapabilityPortBrowserAuth,
		preview.HostCapabilityPortTokens,
		preview.HostCapabilityPorts,
	}
	if !reflect.DeepEqual(capture.args[1], wantPrivate) {
		t.Fatalf("private requirements = %#v, want %#v", capture.args[1], wantPrivate)
	}
}

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

func setCachedAtForTest(t *testing.T, s *LeastLoaded, capabilities []string, at time.Time) {
	t.Helper()
	key, _ := capabilityCacheKey(capabilities)
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.cache[key]
	if !ok {
		t.Fatalf("cache entry for %v is missing", capabilities)
	}
	entry.cachedAt = at
	s.cache[key] = entry
}

func readCacheForTest(s *LeastLoaded, capabilities []string) (hostID string, cachedAt time.Time, ok bool) {
	key, _ := capabilityCacheKey(capabilities)
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.cache[key]
	if !ok {
		return "", time.Time{}, false
	}
	if len(entry.hosts) != 0 {
		hostID = entry.hosts[0].ID
	}
	return hostID, entry.cachedAt, true
}

func TestLoadHostsServesStaleAndRefreshesInBackground(t *testing.T) {
	store := &hostStore{}
	s := &LeastLoaded{DB: db.New(store), TTL: time.Minute}

	// First call blocks and fills the cache.
	if _, err := s.SelectHost(context.Background(), nil); err != nil {
		t.Fatalf("first select: %v", err)
	}
	if n := store.calls.Load(); n != 1 {
		t.Fatalf("expected 1 query, got %d", n)
	}

	// Age the cache far past the TTL; the next call must serve instantly from
	// the stale list and refresh behind it.
	setCachedAtForTest(t, s, nil, time.Now().Add(-s.ttl()-5*time.Second)) // stale, inside grace

	if _, err := s.SelectHost(context.Background(), nil); err != nil {
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
	_, cachedAt, cached := readCacheForTest(s, nil)
	fresh := cached && time.Since(cachedAt) < time.Minute
	if !fresh {
		t.Fatal("refresh must restore a fresh cachedAt")
	}
	if _, err := s.SelectHost(context.Background(), nil); err != nil {
		t.Fatalf("post-refresh select: %v", err)
	}
	if n := store.calls.Load(); n != 2 {
		t.Fatalf("fresh cache must not re-query, got %d", n)
	}
}

func TestLoadHostsStaleServeDoesNotBlockOnSlowRefresh(t *testing.T) {
	store := &hostStore{}
	s := &LeastLoaded{DB: db.New(store), TTL: time.Minute}
	if _, err := s.SelectHost(context.Background(), nil); err != nil {
		t.Fatalf("prime: %v", err)
	}

	// Refresh query hangs; stale selects must return instantly anyway, and the
	// CAS guard must keep it to a single in-flight refresh.
	store.block = make(chan struct{})
	setCachedAtForTest(t, s, nil, time.Now().Add(-s.ttl()-5*time.Second)) // stale, inside grace

	done := make(chan struct{})
	go func() {
		for i := 0; i < 10; i++ {
			_, _ = s.SelectHost(context.Background(), nil)
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
	if _, err := s.SelectHost(context.Background(), nil); err != nil {
		t.Fatalf("prime: %v", err)
	}

	s.Invalidate()
	if _, err := s.SelectHost(context.Background(), nil); err != nil {
		t.Fatalf("post-invalidate select: %v", err)
	}
	if n := store.calls.Load(); n != 2 {
		t.Fatalf("invalidate must force a blocking reload, got %d queries", n)
	}
}

func TestInvalidateBeatsInFlightRefresh(t *testing.T) {
	store := &hostStore{}
	s := &LeastLoaded{DB: db.New(store), TTL: time.Minute}
	if _, err := s.SelectHost(context.Background(), nil); err != nil {
		t.Fatalf("prime: %v", err)
	}

	// Hold a background refresh in flight, then invalidate underneath it.
	store.block = make(chan struct{})
	setCachedAtForTest(t, s, nil, time.Now().Add(-s.ttl()-5*time.Second)) // stale, inside grace
	if _, err := s.SelectHost(context.Background(), nil); err != nil {    // triggers the refresh
		t.Fatalf("stale select: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for store.calls.Load() < 2 { // refresh goroutine reached its (blocked) query
		if time.Now().After(deadline) {
			t.Fatalf("refresh never started, calls=%d", store.calls.Load())
		}
		time.Sleep(2 * time.Millisecond)
	}

	s.Invalidate()     // host retired while the refresh holds the old list
	close(store.block) // the pre-invalidation refresh now returns

	// The stale refresh must be discarded: the cache stays empty until a
	// fresh blocking load, not resurrected with the pre-invalidation list.
	deadline = time.Now().Add(2 * time.Second)
	for {
		_, _, resurrected := readCacheForTest(s, nil)
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
	if _, err := s.SelectHost(context.Background(), nil); err != nil {
		t.Fatalf("prime: %v", err)
	}

	// Way past ttl+grace (refreshes never landed): must block on a fresh
	// load, not keep serving a possibly-dead host list.
	setCachedAtForTest(t, s, nil, time.Now().Add(-time.Hour))

	if _, err := s.SelectHost(context.Background(), nil); err != nil {
		t.Fatalf("past-grace select: %v", err)
	}
	if n := store.calls.Load(); n != 2 {
		t.Fatalf("past-grace select must reload synchronously, got %d queries", n)
	}
}

func TestBlockingReloadNotClobberedBySlowRefresh(t *testing.T) {
	store := &hostStore{}
	s := &LeastLoaded{DB: db.New(store), TTL: time.Minute}
	if _, err := s.SelectHost(context.Background(), nil); err != nil { // query 1
		t.Fatalf("prime: %v", err)
	}

	// Hold only the background refresh (query 2) in flight.
	store.block = make(chan struct{})
	store.blockOnCall = 2
	setCachedAtForTest(t, s, nil, time.Now().Add(-s.ttl()-5*time.Second)) // stale, inside grace
	if _, err := s.SelectHost(context.Background(), nil); err != nil {    // kicks the refresh
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
	setCachedAtForTest(t, s, nil, time.Now().Add(-time.Hour))
	if _, err := s.SelectHost(context.Background(), nil); err != nil {
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
	id, _, cached := readCacheForTest(s, nil)
	if !cached {
		t.Fatal("blocking reload did not leave a cached result")
	}
	if id != "host-3" {
		t.Fatalf("older refresh clobbered the blocking reload: cached %s, want host-3", id)
	}
}
