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
	"github.com/jackc/pgx/v5/pgtype"

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

func (c *queryCapture) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	// The empty-candidate fallback verifies the default host's status; an
	// active row preserves the old fallback behavior in these tests.
	if strings.Contains(sql, "-- name: GetHost :one") {
		return schedulerHostRow(args[0].(string), "active")
	}
	return schedulerErrorRow{err: fmt.Errorf("unexpected QueryRow: %s", sql)}
}

// schedulerHostRow scans like a host row: sqlc's 10-column SELECT * order.
func schedulerHostRow(id, status string) pgx.Row {
	return schedulerScanRow{scan: func(dest ...any) error {
		*dest[0].(*string) = id
		*dest[1].(*string) = "10.0.0.1:50051"
		*dest[2].(*string) = "10.0.0.1:5007"
		*dest[3].(*string) = "region-a"
		*dest[4].(*string) = status
		*dest[5].(*int32) = 1024
		*dest[6].(*int32) = 8
		*dest[7].(*pgtype.Timestamptz) = pgtype.Timestamptz{Time: time.Now(), Valid: true}
		*dest[8].(*time.Time) = time.Now()
		*dest[9].(*time.Time) = time.Now()
		*dest[10].(*bool) = false
		return nil
	}}
}

type schedulerScanRow struct{ scan func(...any) error }

func (r schedulerScanRow) Scan(dest ...any) error { return r.scan(dest...) }

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

// The legacy DefaultHostID fallback must never route to a host row that
// exists in a non-active state: a freshly self-registered 'provisioning'
// host under the default ID would otherwise take creates before an operator
// activates it. Only a genuinely missing row (unpopulated table, the
// bootstrap case) or an active row may fall back.
func TestSelectHostFallbackRefusesNonActiveDefault(t *testing.T) {
	run := func(t *testing.T, row pgx.Row) (string, error) {
		mock := &fallbackProbe{row: row}
		s := &LeastLoaded{DB: db.New(mock), DefaultHostID: "default"}
		id, _, err := s.SelectHost(context.Background(), nil)
		return id, err
	}

	for _, status := range []string{"provisioning", "draining", "unhealthy"} {
		if id, err := run(t, schedulerHostRow("default", status)); err == nil {
			t.Fatalf("status %s: fallback returned %q, want error", status, id)
		}
	}
	if id, err := run(t, schedulerHostRow("default", "active")); err != nil || id != "default" {
		t.Fatalf("active: got (%q, %v), want (default, nil)", id, err)
	}
	if id, err := run(t, schedulerErrorRow{err: pgx.ErrNoRows}); err != nil || id != "default" {
		t.Fatalf("missing row (bootstrap): got (%q, %v), want (default, nil)", id, err)
	}
}

// The fallback status is resolved once per cache fill, not per create: in
// bootstrap mode the SWR cache must keep eliminating per-create DB I/O.
func TestSelectHostFallbackStatusIsCached(t *testing.T) {
	mock := &fallbackProbe{row: schedulerErrorRow{err: pgx.ErrNoRows}}
	s := &LeastLoaded{DB: db.New(mock), DefaultHostID: "default", TTL: time.Minute}
	for i := 0; i < 5; i++ {
		if id, _, err := s.SelectHost(context.Background(), nil); err != nil || id != "default" {
			t.Fatalf("select %d: got (%q, %v)", i, id, err)
		}
	}
	if got := mock.rowCalls.Load(); got != 1 {
		t.Fatalf("GetHost calls = %d, want 1 (per fill, not per create)", got)
	}
}

// fallbackProbe returns zero active hosts and serves GetHost from a canned row.
type fallbackProbe struct {
	row      pgx.Row
	rowCalls atomic.Int64
}

func (f *fallbackProbe) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, fmt.Errorf("unexpected Exec")
}
func (f *fallbackProbe) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return schedulerEmptyRows{}, nil
}
func (f *fallbackProbe) QueryRow(context.Context, string, ...any) pgx.Row {
	f.rowCalls.Add(1)
	return f.row
}

func TestLeastLoadedQueryExcludesHostsWithoutPreviewEnforcement(t *testing.T) {
	capture := &queryCapture{}
	s := &LeastLoaded{DB: db.New(capture), DefaultHostID: "fallback"}
	required := []string{preview.HostCapabilityPorts}
	got, _, err := s.SelectHost(context.Background(), required)
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
		if got, _, err := s.SelectHost(ctx, required); err != nil || got != "fallback" {
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
	calls          atomic.Int64
	block          chan struct{} // non-nil: Query waits until closed
	blockOnCall    int64         // 0 = block every call; N = block only the Nth
	emptyUntilCall int64         // calls up to and including this one return no hosts
	defaultRow     pgx.Row       // answer for the default-host row read on an empty fill
	fixedID        string        // when set, every fill returns this host instead of host-N
}

func (h *hostStore) Exec(context.Context, string, ...interface{}) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}
func (h *hostStore) QueryRow(context.Context, string, ...interface{}) pgx.Row { return h.defaultRow }
func (h *hostStore) Query(context.Context, string, ...interface{}) (pgx.Rows, error) {
	n := h.calls.Add(1)
	if h.block != nil && (h.blockOnCall == 0 || n == h.blockOnCall) {
		<-h.block
	}
	id := fmt.Sprintf("host-%d", n)
	if h.fixedID != "" {
		id = h.fixedID
	}
	return &hostRows{id: id, done: n <= h.emptyUntilCall}, nil
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
	if _, _, err := s.SelectHost(context.Background(), nil); err != nil {
		t.Fatalf("first select: %v", err)
	}
	if n := store.calls.Load(); n != 1 {
		t.Fatalf("expected 1 query, got %d", n)
	}

	// Age the cache far past the TTL; the next call must serve instantly from
	// the stale list and refresh behind it.
	setCachedAtForTest(t, s, nil, time.Now().Add(-s.ttl()-5*time.Second)) // stale, inside grace

	if _, _, err := s.SelectHost(context.Background(), nil); err != nil {
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
	if _, _, err := s.SelectHost(context.Background(), nil); err != nil {
		t.Fatalf("post-refresh select: %v", err)
	}
	if n := store.calls.Load(); n != 2 {
		t.Fatalf("fresh cache must not re-query, got %d", n)
	}
}

func TestLoadHostsStaleServeDoesNotBlockOnSlowRefresh(t *testing.T) {
	store := &hostStore{}
	s := &LeastLoaded{DB: db.New(store), TTL: time.Minute}
	if _, _, err := s.SelectHost(context.Background(), nil); err != nil {
		t.Fatalf("prime: %v", err)
	}

	// Refresh query hangs; stale selects must return instantly anyway, and the
	// CAS guard must keep it to a single in-flight refresh.
	store.block = make(chan struct{})
	setCachedAtForTest(t, s, nil, time.Now().Add(-s.ttl()-5*time.Second)) // stale, inside grace

	done := make(chan struct{})
	go func() {
		for i := 0; i < 10; i++ {
			_, _, _ = s.SelectHost(context.Background(), nil)
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
	if _, _, err := s.SelectHost(context.Background(), nil); err != nil {
		t.Fatalf("prime: %v", err)
	}

	s.Invalidate()
	if _, _, err := s.SelectHost(context.Background(), nil); err != nil {
		t.Fatalf("post-invalidate select: %v", err)
	}
	if n := store.calls.Load(); n != 2 {
		t.Fatalf("invalidate must force a blocking reload, got %d queries", n)
	}
}

func TestInvalidateBeatsInFlightRefresh(t *testing.T) {
	store := &hostStore{}
	s := &LeastLoaded{DB: db.New(store), TTL: time.Minute}
	if _, _, err := s.SelectHost(context.Background(), nil); err != nil {
		t.Fatalf("prime: %v", err)
	}

	// Hold a background refresh in flight, then invalidate underneath it.
	store.block = make(chan struct{})
	setCachedAtForTest(t, s, nil, time.Now().Add(-s.ttl()-5*time.Second)) // stale, inside grace
	if _, _, err := s.SelectHost(context.Background(), nil); err != nil { // triggers the refresh
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

// However old the cached set is, a select serves it without waiting on the
// DB: an instance that has been idle for an hour must not pay a blocking
// load on its next create, and the refresh rides behind the request.
func TestLoadHostsAnyAgeServesStaleAndRefreshesBehind(t *testing.T) {
	store := &hostStore{}
	s := &LeastLoaded{DB: db.New(store), TTL: time.Minute}
	if _, _, err := s.SelectHost(context.Background(), nil); err != nil {
		t.Fatalf("prime: %v", err)
	}

	// Hold the refresh (query 2) so a select that blocked on it would hang.
	store.block = make(chan struct{})
	store.blockOnCall = 2
	setCachedAtForTest(t, s, nil, time.Now().Add(-time.Hour))

	done := make(chan error, 1)
	go func() {
		_, _, err := s.SelectHost(context.Background(), nil)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("stale select: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("select blocked on the refresh instead of serving the stale set")
	}
	close(store.block)

	deadline := time.Now().Add(2 * time.Second)
	for s.refreshing.Load() || store.calls.Load() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("background refresh never landed, calls=%d", store.calls.Load())
		}
		time.Sleep(2 * time.Millisecond)
	}
	if _, cachedAt, cached := readCacheForTest(s, nil); !cached || time.Since(cachedAt) > time.Minute {
		t.Fatal("refresh must restore a fresh cachedAt")
	}
}

func TestBlockingReloadNotClobberedBySlowRefresh(t *testing.T) {
	store := &hostStore{}
	s := &LeastLoaded{DB: db.New(store), TTL: time.Minute}
	if _, _, err := s.SelectHost(context.Background(), nil); err != nil { // query 1
		t.Fatalf("prime: %v", err)
	}

	// Hold only the background refresh (query 2) in flight.
	store.block = make(chan struct{})
	store.blockOnCall = 2
	setCachedAtForTest(t, s, nil, time.Now().Add(-s.ttl()-5*time.Second)) // stale, inside grace
	if _, _, err := s.SelectHost(context.Background(), nil); err != nil { // kicks the refresh
		t.Fatalf("stale select: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for store.calls.Load() < 2 { // refresh goroutine reached its (blocked) query
		if time.Now().After(deadline) {
			t.Fatalf("refresh never started, calls=%d", store.calls.Load())
		}
		time.Sleep(2 * time.Millisecond)
	}

	// Invalidate: the next call reloads synchronously (query 3) and must
	// retire the still-hanging refresh so its older result cannot land on top.
	s.Invalidate()
	if _, _, err := s.SelectHost(context.Background(), nil); err != nil {
		t.Fatalf("post-invalidate select: %v", err)
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

// A cached set with nothing to place on is not served past its TTL: the
// next select reloads in line and places on what the DB has now, instead of
// refusing the create and only refreshing behind the refusal.
func TestLoadHostsExpiredEmptySetReloadsInline(t *testing.T) {
	store := &hostStore{emptyUntilCall: 1}
	s := &LeastLoaded{DB: db.New(store), TTL: time.Minute}
	if _, _, err := s.SelectHost(context.Background(), nil); err == nil {
		t.Fatal("prime: expected no hosts available")
	}
	setCachedAtForTest(t, s, nil, time.Now().Add(-2*time.Minute))

	id, _, err := s.SelectHost(context.Background(), nil)
	if err != nil || id != "host-2" {
		t.Fatalf("expired empty select = (%q, %v), want (host-2, nil)", id, err)
	}
	if n := store.calls.Load(); n != 2 {
		t.Fatalf("queries = %d, want 2 (one in-line reload)", n)
	}
}

// A rejected host drops only the candidate sets that still name it. Once a
// fresh load no longer includes it, further rejections of that host are
// no-ops, so concurrent creates that all drew it share one reload.
func TestRejectDropsOnlySetsStillNamingTheHost(t *testing.T) {
	store := &hostStore{}
	s := &LeastLoaded{DB: db.New(store), TTL: time.Minute}
	id, gen, err := s.SelectHost(context.Background(), nil)
	if err != nil || id != "host-1" {
		t.Fatalf("prime = (%q, %v)", id, err)
	}
	s.Reject("host-1", nil, gen)
	if id, _, err := s.SelectHost(context.Background(), nil); err != nil || id != "host-2" {
		t.Fatalf("after reject = (%q, %v), want host-2 from a fresh load", id, err)
	}
	s.Reject("host-1", nil, gen) // a late waiter with the old set: no-op
	if id, _, err := s.SelectHost(context.Background(), nil); err != nil || id != "host-2" {
		t.Fatalf("after stale reject = (%q, %v), want the cached host-2", id, err)
	}
	if n := store.calls.Load(); n != 2 {
		t.Fatalf("queries = %d, want 2 (one reload for the whole burst)", n)
	}
}

// A rejection is scoped to the capability set that produced the selection:
// rejecting a host for a private-only set leaves the public set cached.
func TestRejectLeavesOtherCapabilitySetsCached(t *testing.T) {
	store := &hostStore{}
	s := &LeastLoaded{DB: db.New(store), TTL: time.Minute}
	public := []string{"preview_ports_v1"}
	private := []string{"preview_ports_v1", "preview_port_browser_auth_v1"}
	if _, _, err := s.SelectHost(context.Background(), public); err != nil { // query 1: host-1
		t.Fatalf("public prime: %v", err)
	}
	_, privGen, err := s.SelectHost(context.Background(), private) // query 2: host-2
	if err != nil {
		t.Fatalf("private prime: %v", err)
	}
	s.Reject("host-2", private, privGen)
	if _, _, err := s.SelectHost(context.Background(), public); err != nil {
		t.Fatalf("public after private reject: %v", err)
	}
	if n := store.calls.Load(); n != 2 {
		t.Fatalf("queries = %d, want 2 (the public set must not be reloaded)", n)
	}
	if id, _, err := s.SelectHost(context.Background(), private); err != nil || id != "host-3" {
		t.Fatalf("private after reject = (%q, %v), want host-3 from a fresh load", id, err)
	}
}

// An expired empty set whose fallback is a capability-filtered default host
// reloads in line too: the fallback will be refused by the pre-flight, and
// only a fresh load can find a host that has since gained the capability.
func TestLoadHostsExpiredFilteredDefaultReloadsInline(t *testing.T) {
	store := &hostStore{emptyUntilCall: 1, defaultRow: schedulerHostRow("default-host", "active")}
	s := &LeastLoaded{DB: db.New(store), DefaultHostID: "default-host", TTL: time.Minute}
	if id, _, err := s.SelectHost(context.Background(), nil); err != nil || id != "default-host" {
		t.Fatalf("prime = (%q, %v), want the filtered default as fallback", id, err)
	}
	setCachedAtForTest(t, s, nil, time.Now().Add(-2*time.Minute))
	id, _, err := s.SelectHost(context.Background(), nil)
	if err != nil || id != "host-2" {
		t.Fatalf("expired select = (%q, %v), want host-2 from an in-line reload", id, err)
	}
	if n := store.calls.Load(); n != 2 {
		t.Fatalf("queries = %d, want 2", n)
	}
}

// A fresh load may legitimately list the rejected host again (it regained
// the capability). Waiters that shared the earlier negative pre-flight carry
// the OLD set's generation, so their rejections cannot evict the fresh set:
// the burst reloads once and the host is re-attested from the fresh set.
func TestRejectWithSupersededGenerationKeepsTheFreshSet(t *testing.T) {
	store := &hostStore{fixedID: "host-1"}
	s := &LeastLoaded{DB: db.New(store), TTL: time.Minute}
	_, oldGen, err := s.SelectHost(context.Background(), nil) // query 1
	if err != nil {
		t.Fatalf("prime: %v", err)
	}
	s.Reject("host-1", nil, oldGen)                                                          // the first waiter drops the set
	if id, _, err := s.SelectHost(context.Background(), nil); err != nil || id != "host-1" { // query 2: fresh, lists host-1 again
		t.Fatalf("reload = (%q, %v)", id, err)
	}
	for i := 0; i < 5; i++ { // the other waiters, still holding the old generation
		s.Reject("host-1", nil, oldGen)
	}
	if _, _, err := s.SelectHost(context.Background(), nil); err != nil {
		t.Fatalf("select after stale rejections: %v", err)
	}
	if n := store.calls.Load(); n != 2 {
		t.Fatalf("queries = %d, want 2 (one reload for the burst)", n)
	}
}

// A blocking fill for one capability set runs outside the scheduler mutex:
// while it is stuck on a slow query, selects for another set that is cached
// and usable must not wait behind it.
func TestBlockingFillDoesNotBlockOtherCapabilitySets(t *testing.T) {
	store := &hostStore{emptyUntilCall: 1}
	s := &LeastLoaded{DB: db.New(store), TTL: time.Minute}
	setA, setB := []string{"a"}, []string{"b"}
	if _, _, err := s.SelectHost(context.Background(), setA); err == nil { // query 1: empty, no host
		t.Fatal("prime A: expected no hosts")
	}
	if id, _, err := s.SelectHost(context.Background(), setB); err != nil || id != "host-2" { // query 2
		t.Fatalf("prime B = (%q, %v)", id, err)
	}
	setCachedAtForTest(t, s, setA, time.Now().Add(-2*time.Minute)) // A: expired and empty → in-line reload
	store.block = make(chan struct{})
	store.blockOnCall = 3 // hold A's reload
	aDone := make(chan error, 1)
	go func() {
		_, _, err := s.SelectHost(context.Background(), setA)
		aDone <- err
	}()
	deadline := time.Now().Add(2 * time.Second)
	for store.calls.Load() < 3 {
		if time.Now().After(deadline) {
			t.Fatal("A's reload never started")
		}
		time.Sleep(time.Millisecond)
	}

	bDone := make(chan string, 1)
	go func() {
		id, _, _ := s.SelectHost(context.Background(), setB)
		bDone <- id
	}()
	select {
	case id := <-bDone:
		if id != "host-2" {
			t.Fatalf("B during A's reload = %q, want the cached host-2", id)
		}
	case <-time.After(time.Second):
		t.Fatal("a select for B blocked behind A's reload")
	}
	close(store.block)
	if err := <-aDone; err != nil {
		t.Fatalf("A after reload: %v", err)
	}
}

// A background refresh publishes under a new generation: a rejection that
// carries the stale set's generation cannot evict the refreshed set.
func TestBackgroundRefreshPublishesANewGeneration(t *testing.T) {
	store := &hostStore{}
	s := &LeastLoaded{DB: db.New(store), TTL: time.Minute}
	_, oldGen, err := s.SelectHost(context.Background(), nil) // query 1: host-1
	if err != nil {
		t.Fatalf("prime: %v", err)
	}
	setCachedAtForTest(t, s, nil, time.Now().Add(-2*time.Minute))
	if _, _, err := s.SelectHost(context.Background(), nil); err != nil { // stale serve, refresh behind
		t.Fatalf("stale select: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for s.refreshing.Load() || store.calls.Load() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("refresh never landed")
		}
		time.Sleep(time.Millisecond)
	}
	s.Reject("host-1", nil, oldGen) // a late negative result from the old set
	if id, gen, err := s.SelectHost(context.Background(), nil); err != nil || id != "host-2" || gen == oldGen {
		t.Fatalf("after stale reject = (%q, gen %d, %v), want the refreshed host-2 under a new generation", id, gen, err)
	}
	if n := store.calls.Load(); n != 2 {
		t.Fatalf("queries = %d, want 2 (the refreshed set must survive the stale rejection)", n)
	}
}

// A background refresh that started from a set later replaced by a
// rejection reload must not land its older snapshot on top of the reload.
func TestOldRefreshCannotReplaceARejectionReload(t *testing.T) {
	store := &hostStore{}
	s := &LeastLoaded{DB: db.New(store), TTL: time.Minute}
	_, gen, err := s.SelectHost(context.Background(), nil) // query 1: host-1
	if err != nil {
		t.Fatalf("prime: %v", err)
	}
	setCachedAtForTest(t, s, nil, time.Now().Add(-2*time.Minute))
	store.block = make(chan struct{})
	store.blockOnCall = 2                                                 // hold the refresh
	if _, _, err := s.SelectHost(context.Background(), nil); err != nil { // stale serve; refresh (query 2) starts and blocks
		t.Fatalf("stale select: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for store.calls.Load() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("refresh never started")
		}
		time.Sleep(time.Millisecond)
	}
	s.Reject("host-1", nil, gen)                                                             // the served host failed its pre-flight
	if id, _, err := s.SelectHost(context.Background(), nil); err != nil || id != "host-3" { // query 3: rejection reload
		t.Fatalf("reload = (%q, %v), want host-3", id, err)
	}
	close(store.block) // the older refresh now returns host-2
	deadline = time.Now().Add(2 * time.Second)
	for s.refreshing.Load() {
		if time.Now().After(deadline) {
			t.Fatal("refresh never finished")
		}
		time.Sleep(time.Millisecond)
	}
	if id, _, _ := readCacheForTest(s, nil); id != "host-3" {
		t.Fatalf("cached = %q after the old refresh landed, want host-3 kept", id)
	}
}

// A create arriving after an Invalidate must not join a fill that began
// before it: it starts its own, and gets what the DB says now.
func TestFillAfterInvalidateDoesNotJoinAnOlderFlight(t *testing.T) {
	store := &hostStore{}
	s := &LeastLoaded{DB: db.New(store), TTL: time.Minute}
	store.block = make(chan struct{})
	store.blockOnCall = 1 // hold the cold fill
	first := make(chan string, 1)
	go func() {
		id, _, _ := s.SelectHost(context.Background(), nil) // query 1, held
		first <- id
	}()
	deadline := time.Now().Add(2 * time.Second)
	for store.calls.Load() < 1 {
		if time.Now().After(deadline) {
			t.Fatal("cold fill never started")
		}
		time.Sleep(time.Millisecond)
	}
	s.Invalidate() // a host status change lands while that fill is in flight

	second := make(chan string, 1)
	go func() {
		id, _, _ := s.SelectHost(context.Background(), nil) // must run its own fill: query 2
		second <- id
	}()
	select {
	case id := <-second:
		if id != "host-2" {
			t.Fatalf("post-invalidate select = %q, want host-2 from its own fill", id)
		}
	case <-time.After(time.Second):
		t.Fatal("post-invalidate select joined the older, held fill")
	}
	close(store.block)
	if id := <-first; id != "host-1" {
		t.Fatalf("pre-invalidate select = %q, want its own host-1", id)
	}
	if id, _, _ := readCacheForTest(s, nil); id != "host-2" {
		t.Fatalf("cached = %q, want host-2 (the pre-invalidate fill must not be cached)", id)
	}
}
