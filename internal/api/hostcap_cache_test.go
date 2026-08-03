package api

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/superserve-ai/sandbox/internal/db"
)

// capMockHandlers returns a Handlers whose DB answers every capability read
// with the current value of *answer, counting reads in *reads.
func capMockHandlers(reads *atomic.Int64, answer *atomic.Bool) *Handlers {
	mock := &mockDBTX{
		queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
			reads.Add(1)
			return &mockRow{scanFn: func(dest ...any) error {
				*(dest[0].(*bool)) = answer.Load()
				return nil
			}}
		},
	}
	return &Handlers{DB: db.New(mock)}
}

// A positive attestation must be served from cache within the TTL — the
// steady-state hot path pays zero DB reads.
func TestHostCapCachePositiveHitSkipsDB(t *testing.T) {
	var reads atomic.Int64
	var answer atomic.Bool
	answer.Store(true)
	h := capMockHandlers(&reads, &answer)

	for i := 0; i < 5; i++ {
		ok, err := h.hostHasCapabilitiesCached(context.Background(), "host-a", []string{"preview_ports_v1"})
		if err != nil || !ok {
			t.Fatalf("call %d: ok=%v err=%v", i, ok, err)
		}
	}
	if got := reads.Load(); got != 1 {
		t.Fatalf("DB reads = %d, want 1 (subsequent calls must hit the cache)", got)
	}
}

// A negative result must never be cached: every check of an unattested
// capability re-reads the database, so a 409 is always based on a fresh read.
func TestHostCapCacheNegativeNeverCached(t *testing.T) {
	var reads atomic.Int64
	var answer atomic.Bool // false
	h := capMockHandlers(&reads, &answer)

	for i := 0; i < 3; i++ {
		ok, err := h.hostHasCapabilitiesCached(context.Background(), "host-a", []string{"preview_ports_v1"})
		if err != nil || ok {
			t.Fatalf("call %d: ok=%v err=%v, want false,nil", i, ok, err)
		}
	}
	if got := reads.Load(); got != 3 {
		t.Fatalf("DB reads = %d, want 3 (negatives must not be cached)", got)
	}

	// The capability appearing (host upgraded) is visible immediately.
	answer.Store(true)
	if ok, err := h.hostHasCapabilitiesCached(context.Background(), "host-a", []string{"preview_ports_v1"}); err != nil || !ok {
		t.Fatalf("after upgrade: ok=%v err=%v, want true", ok, err)
	}
}

// Distinct capability sets are distinct cache keys — a hit for one set must
// not attest another.
func TestHostCapCacheKeyIncludesCapabilitySet(t *testing.T) {
	var reads atomic.Int64
	var answer atomic.Bool
	answer.Store(true)
	h := capMockHandlers(&reads, &answer)

	ctx := context.Background()
	if _, err := h.hostHasCapabilitiesCached(ctx, "host-a", []string{"preview_ports_v1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.hostHasCapabilitiesCached(ctx, "host-a", []string{"preview_ports_v1", "preview_port_access_v1"}); err != nil {
		t.Fatal(err)
	}
	if got := reads.Load(); got != 2 {
		t.Fatalf("DB reads = %d, want 2 (different capability sets must not share an entry)", got)
	}
}

// A TTL-expired positive is served through the grace window while one
// background refresh runs; a refuting refresh evicts it, after which checks
// read fresh. Past ttl+grace an entry is a plain miss.
func TestHostCapCacheStaleGraceAndEviction(t *testing.T) {
	var reads atomic.Int64
	var answer atomic.Bool
	answer.Store(true)
	h := capMockHandlers(&reads, &answer)
	h.hostCaps.init()
	h.hostCaps.ttl = 20 * time.Millisecond

	ctx := context.Background()
	caps := []string{"preview_ports_v1"}
	if ok, _ := h.hostHasCapabilitiesCached(ctx, "host-a", caps); !ok {
		t.Fatal("first read should attest")
	}
	time.Sleep(30 * time.Millisecond) // past TTL, inside the grace window
	answer.Store(false)               // capability lost
	if ok, _ := h.hostHasCapabilitiesCached(ctx, "host-a", caps); !ok {
		t.Fatal("within grace the stale positive must still serve")
	}
	// That serve armed one background refresh; it sees the refuting read and
	// evicts the entry, after which checks are fresh (and false).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ok, _ := h.hostHasCapabilitiesCached(ctx, "host-a", caps); !ok {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if ok, _ := h.hostHasCapabilitiesCached(ctx, "host-a", caps); ok {
		t.Fatal("refuted entry must be evicted, not served")
	}
	if reads.Load() < 2 {
		t.Fatalf("background refresh never ran (reads=%d)", reads.Load())
	}

	// Past ttl+grace an entry is a miss, not a stale serve.
	c := &h.hostCaps
	c.put("k2", time.Now().Add(-c.ttl-hostCapCacheStaleGrace-time.Millisecond))
	if _, ok := c.get("k2", time.Now()); ok {
		t.Fatal("entry past ttl+grace must be a miss")
	}

	// A put sweeps expired entries, so retired hosts' keys don't accumulate.
	c.put("retired", time.Now().Add(-c.ttl-hostCapCacheStaleGrace-time.Millisecond))
	c.put("live", time.Now())
	c.mu.Lock()
	_, retired := c.m["retired"]
	c.mu.Unlock()
	if retired {
		t.Fatal("put must sweep entries past serving age")
	}
}

// The transactional validate must issue the locked query; the pre-flight
// cache must issue the unlocked one. Pins the routing so a refactor can't
// silently drop FOR SHARE from the mutation path.
func TestCapabilityQueryRouting(t *testing.T) {
	var mu sync.Mutex
	var sqls []string
	mock := &mockDBTX{queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
		mu.Lock()
		sqls = append(sqls, sql)
		mu.Unlock()
		return &mockRow{scanFn: func(dest ...any) error {
			*(dest[0].(*bool)) = true
			return nil
		}}
	}}
	q := db.New(mock)

	if err := validateHostPreviewCapabilities(context.Background(), q, "host-a", "preview_ports_v1"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	first := sqls[0]
	mu.Unlock()
	if !strings.Contains(first, "-- name: HostHasCapabilities :one") || !strings.Contains(first, "FOR SHARE") {
		t.Fatalf("transactional validate must use the locked query, got: %.60s", first)
	}

	h := &Handlers{DB: q}
	if ok, err := h.hostHasCapabilitiesCached(context.Background(), "host-a", []string{"preview_ports_v1"}); err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	mu.Lock()
	last := sqls[len(sqls)-1]
	mu.Unlock()
	if !strings.Contains(last, "-- name: HostHasCapabilitiesUnlocked :one") || strings.Contains(last, "FOR SHARE") {
		t.Fatalf("pre-flight must use the unlocked query, got: %.60s", last)
	}
}

// TTL <= 0 disables caching entirely (the kill switch).
func TestHostCapCacheDisabled(t *testing.T) {
	var reads atomic.Int64
	var answer atomic.Bool
	answer.Store(true)
	h := capMockHandlers(&reads, &answer)
	h.hostCaps.init()
	h.hostCaps.ttl = 0

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if ok, err := h.hostHasCapabilitiesCached(ctx, "host-a", []string{"preview_ports_v1"}); err != nil || !ok {
			t.Fatalf("call %d: ok=%v err=%v", i, ok, err)
		}
	}
	if got := reads.Load(); got != 3 {
		t.Fatalf("DB reads = %d, want 3 (TTL=0 must disable caching)", got)
	}
}
