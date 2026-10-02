package api

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/hostreg"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

// capMockHandlers returns a Handlers whose DB answers every capability read
// with the current value of *answer, counting reads in *reads.
func capMockHandlers(reads *atomic.Int64, answer *atomic.Bool) *Handlers {
	mock := &mockDBTX{
		queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
			reads.Add(1)
			return &mockRow{scanFn: func(dest ...any) error {
				*(dest[0].(*bool)) = answer.Load()
				*(dest[1].(*string)) = "10.0.0.9:50051"
				return nil
			}}
		},
	}
	return &Handlers{DB: db.New(mock)}
}

type verifyRecorder struct {
	mu        sync.Mutex
	verified  []string
	remaining time.Duration // budget left on the last MarkVerified's context
	err       error         // returned by every MarkVerified
}

func (v *verifyRecorder) ClientFor(context.Context, string) (vmdclient.Client, error) {
	return nil, fmt.Errorf("not used in this test")
}
func (v *verifyRecorder) Invalidate(string)        {}
func (v *verifyRecorder) Generation(string) uint64 { return 0 }
func (v *verifyRecorder) MarkVerified(ctx context.Context, hostID, addr string, _ uint64) error {
	v.mu.Lock()
	v.verified = append(v.verified, hostID+"="+addr)
	if deadline, ok := ctx.Deadline(); ok {
		v.remaining = time.Until(deadline)
	}
	v.mu.Unlock()
	return v.err
}

// The registry wait gets the registry's own budget, not what is left of the
// capability query's, so a read that ran long cannot starve the resolution.
func TestHostCapReadGivesRegistryItsOwnBudget(t *testing.T) {
	var reads atomic.Int64
	var answer atomic.Bool
	answer.Store(true)
	h := capMockHandlers(&reads, &answer)
	reg := &verifyRecorder{}
	h.Hosts = reg

	if ok, err := h.hostHasCapabilitiesCached(context.Background(), "host-a", []string{"preview_ports_v1"}); err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if got := reg.remaining; got <= hostreg.ResolveTimeout-time.Second || got > hostreg.ResolveTimeout {
		t.Fatalf("registry wait budget = %v, want about %v", got, hostreg.ResolveTimeout)
	}
}

// A registry resolution that fails during the pre-flight fails the
// pre-flight, uncached, so the create ends here instead of repeating the
// same lookup at dispatch.
func TestHostCapReadFailsWhenRegistryResolutionFails(t *testing.T) {
	var reads atomic.Int64
	var answer atomic.Bool
	answer.Store(true)
	h := capMockHandlers(&reads, &answer)
	h.Hosts = &verifyRecorder{err: fmt.Errorf("row unreadable")}

	for i := 0; i < 2; i++ {
		if ok, err := h.hostHasCapabilitiesCached(context.Background(), "host-a", []string{"preview_ports_v1"}); err == nil || ok {
			t.Fatalf("call %d: ok=%v err=%v, want the resolution error", i, ok, err)
		}
	}
	if n := reads.Load(); n != 2 {
		t.Fatalf("reads = %d, want 2 (a failed pre-flight is not cached)", n)
	}
}

// The pre-flight read is also the host registry's address verification: an
// affirmative answer hands the address over, a negative one does not.
func TestHostCapReadVerifiesRegistryAddress(t *testing.T) {
	var reads atomic.Int64
	var answer atomic.Bool
	answer.Store(true)
	h := capMockHandlers(&reads, &answer)
	reg := &verifyRecorder{}
	h.Hosts = reg

	if ok, err := h.hostHasCapabilitiesCached(context.Background(), "host-a", []string{"preview_ports_v1"}); err != nil || !ok {
		t.Fatalf("positive: ok=%v err=%v", ok, err)
	}
	answer.Store(false)
	if ok, err := h.hostHasCapabilitiesCached(context.Background(), "host-b", []string{"preview_ports_v1"}); err != nil || ok {
		t.Fatalf("negative: ok=%v err=%v", ok, err)
	}
	if want := []string{"host-a=10.0.0.9:50051"}; !reflect.DeepEqual(reg.verified, want) {
		t.Fatalf("verified = %v, want %v", reg.verified, want)
	}
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
// silently drop the lock-then-read transaction from the mutation path.
func TestCapabilityQueryRouting(t *testing.T) {
	var mu sync.Mutex
	var sqls []string
	var events []string
	mock := &mockDBTX{capabilityTxEvent: func(event string) { events = append(events, event) }, queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
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
	if strings.Join(events, ",") != "begin,lock,commit" {
		t.Fatalf("transaction sequence=%v", events)
	}
	mu.Lock()
	first := sqls[0]
	mu.Unlock()
	if !strings.Contains(first, "-- name: HostHasCapabilities :one") || strings.Contains(first, "FOR SHARE") {
		t.Fatalf("transactional validate must evaluate with a fresh non-locking statement, got: %.60s", first)
	}

	events = nil
	h := &Handlers{DB: q}
	if ok, err := h.hostHasCapabilitiesCached(context.Background(), "host-a", []string{"preview_ports_v1"}); err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if len(events) != 0 {
		t.Fatalf("preflight opened a transaction: %v", events)
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

// The TTL is the drain admission bound, so configuration can shorten or
// disable it but never stretch it past the cap.
func TestHostCapCacheTTLClamped(t *testing.T) {
	for raw, want := range map[string]time.Duration{
		"":    defaultHostCapCacheTTL,
		"5s":  5 * time.Second,
		"0":   0,
		"10m": maxHostCapCacheTTL,
		"bad": defaultHostCapCacheTTL,
	} {
		t.Setenv("HOST_CAPABILITY_CACHE_TTL", raw)
		if got := hostCapCacheTTLFromEnv(); got != want {
			t.Fatalf("HOST_CAPABILITY_CACHE_TTL=%q: ttl = %v, want %v", raw, got, want)
		}
	}
}

func TestHostCapCacheSeparatesOwnerResumeEligibility(t *testing.T) {
	t.Setenv("HOST_CAPABILITY_CACHE_TTL", "10s")
	var ownerReads, activeReads int
	h := &Handlers{DB: db.New(&mockDBTX{queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
		owner := reflect.DeepEqual(args[2], []string{"active", "draining"})
		if owner {
			ownerReads++
		} else {
			activeReads++
		}
		return &mockRow{scanFn: func(dest ...any) error {
			*(dest[0].(*bool)) = owner
			*(dest[1].(*string)) = "192.0.2.1:50051"
			return nil
		}}
	}})}
	registry := &verifyRecorder{}
	h.Hosts = registry
	caps := []string{"cap-a", "cap-b"}
	for i := 0; i < 2; i++ {
		got, err := h.hostHasCapabilitiesCachedForScope(context.Background(), "owner", caps, ownerResumeCapabilities)
		if err != nil || !got {
			t.Fatalf("resume=%v err=%v", got, err)
		}
		got, err = h.hostHasCapabilitiesCached(context.Background(), "owner", caps)
		if err != nil || got {
			t.Fatalf("active-only=%v err=%v", got, err)
		}
	}
	if ownerReads != 2 || activeReads != 2 {
		t.Fatalf("owner/active reads=%d/%d", ownerReads, activeReads)
	}
	if want := []string{"owner=192.0.2.1:50051", "owner=192.0.2.1:50051"}; !reflect.DeepEqual(registry.verified, want) {
		t.Fatalf("address verification=%v", registry.verified)
	}
}

func TestHostCapabilityScopeParameters(t *testing.T) {
	for _, owner := range []bool{false, true} {
		for _, unlocked := range []bool{false, true} {
			t.Run(fmt.Sprintf("owner=%v/unlocked=%v", owner, unlocked), func(t *testing.T) {
				before := time.Now().Add(-heartbeatTimeout)
				reads := 0
				h := &Handlers{DB: db.New(&mockDBTX{queryRowFn: func(_ context.Context, _ string, args ...any) pgx.Row {
					reads++
					statuses := []string{"active"}
					if owner {
						statuses = append(statuses, "draining")
					}
					if !reflect.DeepEqual(args[2], statuses) {
						t.Fatalf("allowed statuses=%v, want %v", args[2], statuses)
					}
					cutoff, ok := args[3].(pgtype.Timestamptz)
					if !ok || cutoff.Valid != owner || (owner && (cutoff.Time.Before(before) || cutoff.Time.After(time.Now().Add(-heartbeatTimeout)))) {
						t.Fatalf("heartbeat cutoff=%+v, owner=%v", args[3], owner)
					}
					return &mockRow{scanFn: func(dest ...any) error {
						*(dest[0].(*bool)) = false
						if unlocked {
							*(dest[1].(*string)) = ""
						}
						return nil
					}}
				}})}
				registry := &verifyRecorder{}
				h.Hosts = registry
				scope := activeHostCapabilities
				if owner {
					scope = ownerResumeCapabilities
				}
				if unlocked {
					has, err := h.readHostCaps(context.Background(), db.HostHasCapabilitiesUnlockedParams{
						HostID: "owner", RequiredCapabilities: previewBrowserCapabilities(),
					}, scope)
					if err != nil || has {
						t.Fatalf("capabilities=%v, err=%v, want rejection", has, err)
					}
				} else {
					validate := validateHostPreviewCapabilities
					if owner {
						validate = validateOwnerResumeCapabilities
					}
					if err := validate(context.Background(), h.DB, "owner", previewBrowserCapabilities()...); err == nil {
						t.Fatal("expected capability rejection")
					}
				}
				if reads != 1 || len(registry.verified) != 0 {
					t.Fatalf("reads=%d, address verifications=%v", reads, registry.verified)
				}
			})
		}
	}
}

func TestOwnerResumeCapabilitiesRechecksAfterSuccess(t *testing.T) {
	t.Setenv("HOST_CAPABILITY_CACHE_TTL", "10s")
	var reads atomic.Int64
	var answer atomic.Bool
	answer.Store(true)
	h := capMockHandlers(&reads, &answer)
	registry := &verifyRecorder{}
	h.Hosts = registry
	ctx := context.Background()
	caps := []string{"preview_ports_v1"}

	// A placement cache hit must not hide a later owner eligibility change.
	if ok, err := h.hostHasCapabilitiesCached(ctx, "owner", caps); err != nil || !ok {
		t.Fatalf("active: ok=%v err=%v", ok, err)
	}
	if ok, err := h.hostHasCapabilitiesCachedForScope(ctx, "owner", caps, ownerResumeCapabilities); err != nil || !ok {
		t.Fatalf("initial resume: ok=%v err=%v", ok, err)
	}
	// The query rejects when status or heartbeat attestations become ineligible.
	answer.Store(false)
	if ok, err := h.hostHasCapabilitiesCachedForScope(ctx, "owner", caps, ownerResumeCapabilities); err != nil || ok {
		t.Fatalf("after eligibility loss: ok=%v err=%v, want false,nil", ok, err)
	}
	if got := reads.Load(); got != 3 {
		t.Fatalf("DB reads=%d, want 3", got)
	}
	if len(registry.verified) != 2 {
		t.Fatalf("address verifications=%v, want only the two successful reads", registry.verified)
	}

	answer.Store(true)
	registry.err = fmt.Errorf("registry resolution failed")
	if ok, err := h.hostHasCapabilitiesCachedForScope(ctx, "owner", caps, ownerResumeCapabilities); err == nil || ok {
		t.Fatalf("registry failure: ok=%v err=%v, want rejection", ok, err)
	}
}
