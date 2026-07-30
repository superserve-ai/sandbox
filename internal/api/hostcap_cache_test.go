package api

import (
	"context"
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

// An expired positive is refreshed, and a refuting read evicts it rather than
// letting the stale positive linger.
func TestHostCapCacheExpiryAndEviction(t *testing.T) {
	var reads atomic.Int64
	var answer atomic.Bool
	answer.Store(true)
	h := capMockHandlers(&reads, &answer)
	h.hostCaps.init()
	h.hostCaps.ttl = 20 * time.Millisecond

	ctx := context.Background()
	if ok, _ := h.hostHasCapabilitiesCached(ctx, "host-a", []string{"preview_ports_v1"}); !ok {
		t.Fatal("first read should attest")
	}
	time.Sleep(30 * time.Millisecond)
	answer.Store(false) // capability lost while the entry expired
	if ok, _ := h.hostHasCapabilitiesCached(ctx, "host-a", []string{"preview_ports_v1"}); ok {
		t.Fatal("expired entry must re-read and see the lost capability")
	}
	if ok, _ := h.hostHasCapabilitiesCached(ctx, "host-a", []string{"preview_ports_v1"}); ok {
		t.Fatal("refuted entry must have been evicted, not served")
	}
	if got := reads.Load(); got != 3 {
		t.Fatalf("DB reads = %d, want 3", got)
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
