package api

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

func TestAPIKeyCache_HitReturnsEntry(t *testing.T) {
	c := newAPIKeyCache(30 * time.Second)
	now := time.Now()
	c.put("hash1", apiKeyCacheEntry{id: "id1", teamID: "team1"}, now)

	entry, needTouch, ok := c.get("hash1", now.Add(time.Second))
	if !ok {
		t.Fatal("expected cache hit")
	}
	if entry.id != "id1" || entry.teamID != "team1" {
		t.Errorf("wrong entry: %+v", entry)
	}
	// put counts as a touch, so a hit 1s later must not touch again.
	if needTouch {
		t.Error("expected no touch within lastUsedTouchInterval of put")
	}
}

func TestAPIKeyCache_MissAfterTTL(t *testing.T) {
	c := newAPIKeyCache(30 * time.Second)
	now := time.Now()
	c.put("hash1", apiKeyCacheEntry{id: "id1", teamID: "team1"}, now)

	if _, _, ok := c.get("hash1", now.Add(31*time.Second)); ok {
		t.Error("expected miss after TTL")
	}
	// The expired entry is retained (never served) so put can carry its
	// lastTouch across the refill; the capacity sweep reclaims it eventually.
	c.mu.Lock()
	_, exists := c.m["hash1"]
	c.mu.Unlock()
	if !exists {
		t.Error("expected expired entry to be retained for touch-throttle continuity")
	}
}

func TestAPIKeyCache_TouchThrottleSurvivesRefill(t *testing.T) {
	c := newAPIKeyCache(10 * time.Second)
	now := time.Now()
	if !c.put("hash1", apiKeyCacheEntry{id: "id1"}, now) {
		t.Fatal("first put must touch")
	}

	// TTL expires, the miss path refills within the touch interval: no touch.
	if c.put("hash1", apiKeyCacheEntry{id: "id1"}, now.Add(11*time.Second)) {
		t.Error("refill within lastUsedTouchInterval must not touch")
	}
	// A refill after the interval elapses touches again.
	if !c.put("hash1", apiKeyCacheEntry{id: "id1"}, now.Add(lastUsedTouchInterval+time.Second)) {
		t.Error("refill after the interval must touch")
	}
}

func TestAPIKeyCache_MissUnknownKey(t *testing.T) {
	c := newAPIKeyCache(30 * time.Second)
	if _, _, ok := c.get("nope", time.Now()); ok {
		t.Error("expected miss for unknown key")
	}
}

func TestAPIKeyCache_KeyExpiryCheckedOnHit(t *testing.T) {
	c := newAPIKeyCache(30 * time.Second)
	now := time.Now()
	c.put("hash1", apiKeyCacheEntry{
		id:        "id1",
		teamID:    "team1",
		expiresAt: pgtype.Timestamptz{Time: now.Add(10 * time.Second), Valid: true},
	}, now)

	// Inside TTL and before expires_at: hit.
	if _, _, ok := c.get("hash1", now.Add(5*time.Second)); !ok {
		t.Error("expected hit before expires_at")
	}
	// Inside TTL but past expires_at: miss, even though TTL hasn't lapsed.
	if _, _, ok := c.get("hash1", now.Add(11*time.Second)); ok {
		t.Error("expected miss after expires_at despite fresh TTL")
	}
}

func TestAPIKeyCache_TouchThrottle(t *testing.T) {
	c := newAPIKeyCache(10 * time.Minute) // TTL long enough to not interfere
	now := time.Now()
	c.put("hash1", apiKeyCacheEntry{id: "id1"}, now)

	if _, needTouch, _ := c.get("hash1", now.Add(30*time.Second)); needTouch {
		t.Error("expected no touch before interval elapses")
	}
	if _, needTouch, _ := c.get("hash1", now.Add(lastUsedTouchInterval)); !needTouch {
		t.Error("expected touch once interval elapsed")
	}
	// The touch above reset the clock; immediately after, no touch again.
	if _, needTouch, _ := c.get("hash1", now.Add(lastUsedTouchInterval+time.Second)); needTouch {
		t.Error("expected no touch right after a touch")
	}
}

func TestAPIKeyCache_DisabledNilSafe(t *testing.T) {
	c := newAPIKeyCache(0) // disabled → nil
	if c != nil {
		t.Fatal("expected nil cache when TTL <= 0")
	}
	now := time.Now()
	c.put("hash1", apiKeyCacheEntry{id: "id1"}, now) // must not panic
	if _, _, ok := c.get("hash1", now); ok {
		t.Error("disabled cache must always miss")
	}
}

func TestAPIKeyCache_SweepAtCapacity(t *testing.T) {
	c := newAPIKeyCache(30 * time.Second)
	now := time.Now()
	for i := 0; i < apiKeyCacheMaxEntries; i++ {
		c.put(fmt.Sprintf("hash%d", i), apiKeyCacheEntry{id: "x"}, now)
	}
	// All entries are stale by the time the cap-triggering put happens:
	// the sweep clears them and the new entry fits.
	later := now.Add(31 * time.Second)
	c.put("fresh", apiKeyCacheEntry{id: "fresh"}, later)

	if _, _, ok := c.get("fresh", later); !ok {
		t.Error("expected fresh entry after sweep")
	}
	c.mu.Lock()
	size := len(c.m)
	c.mu.Unlock()
	if size != 1 {
		t.Errorf("expected sweep to leave 1 entry, got %d", size)
	}
}

func TestAPIKeyCache_ResetWhenFullOfFreshEntries(t *testing.T) {
	c := newAPIKeyCache(10 * time.Minute)
	now := time.Now()
	for i := 0; i < apiKeyCacheMaxEntries; i++ {
		c.put(fmt.Sprintf("hash%d", i), apiKeyCacheEntry{id: "x"}, now)
	}
	// Nothing is stale, so the cap forces a full reset; the map must not
	// exceed the cap and the new entry must be present.
	c.put("fresh", apiKeyCacheEntry{id: "fresh"}, now.Add(time.Second))

	if _, _, ok := c.get("fresh", now.Add(2*time.Second)); !ok {
		t.Error("expected fresh entry after reset")
	}
	c.mu.Lock()
	size := len(c.m)
	c.mu.Unlock()
	if size > apiKeyCacheMaxEntries {
		t.Errorf("cache exceeded cap: %d", size)
	}
}

func TestAPIKeyCacheTTLFromEnv(t *testing.T) {
	t.Setenv("API_KEY_CACHE_TTL", "")
	if got := apiKeyCacheTTLFromEnv(); got != defaultAPIKeyCacheTTL {
		t.Errorf("unset: expected default, got %v", got)
	}
	t.Setenv("API_KEY_CACHE_TTL", "45s")
	if got := apiKeyCacheTTLFromEnv(); got != 45*time.Second {
		t.Errorf("45s: got %v", got)
	}
	t.Setenv("API_KEY_CACHE_TTL", "0")
	if got := apiKeyCacheTTLFromEnv(); got != 0 {
		t.Errorf("0: got %v", got)
	}
	t.Setenv("API_KEY_CACHE_TTL", "garbage")
	if got := apiKeyCacheTTLFromEnv(); got != defaultAPIKeyCacheTTL {
		t.Errorf("garbage: expected default, got %v", got)
	}
}

func TestAPIKeyCache_FetchCoalescesConcurrentMisses(t *testing.T) {
	c := newAPIKeyCache(10 * time.Second)
	var calls atomic.Int64
	release := make(chan struct{})

	// Every flight blocks on release, and release closes only after all 50
	// goroutines have signaled ready immediately before calling fetch — so
	// nearly all of them are parked inside the first flight when it completes.
	// Only a goroutine preempted in the instructions between ready.Done and
	// group.Do can run its own (instant) flight afterward; a small tolerance
	// absorbs those without any wall-clock dependence.
	var wg, ready sync.WaitGroup
	launch := func() {
		defer wg.Done()
		ready.Done()
		entry, err := c.fetch(context.Background(), "hash1", func(context.Context) (apiKeyCacheEntry, error) {
			calls.Add(1)
			<-release
			return apiKeyCacheEntry{id: "id1"}, nil
		})
		if err != nil || entry.id != "id1" {
			t.Errorf("fetch: entry=%+v err=%v", entry, err)
		}
	}

	wg.Add(50)
	ready.Add(50)
	for i := 0; i < 50; i++ {
		go launch()
	}
	ready.Wait()
	time.Sleep(2 * time.Millisecond) // let the signaled goroutines cross into group.Do
	close(release)
	wg.Wait()

	if n := calls.Load(); n > 5 {
		t.Errorf("expected coalesced lookups (<=5), got %d", n)
	}
}

// fetch's context contract: the coalescing branch detaches from the caller
// (waiters may outlive the triggering request), the disabled branch must NOT
// (a client disconnect has to cancel the lookup).
func TestAPIKeyCache_FetchContextContract(t *testing.T) {
	// The shared flight runs detached from the caller: no cancellation, own
	// deadline. Exercised with a LIVE caller ctx so fn actually runs.
	c := newAPIKeyCache(10 * time.Second)
	if _, err := c.fetch(context.Background(), "hash1", func(qctx context.Context) (apiKeyCacheEntry, error) {
		if qctx.Err() != nil {
			t.Errorf("shared flight must be detached from the caller, got %v", qctx.Err())
		}
		if _, ok := qctx.Deadline(); !ok {
			t.Error("shared flight must carry its own deadline")
		}
		return apiKeyCacheEntry{id: "id1"}, nil
	}); err != nil {
		t.Errorf("fetch: %v", err)
	}

	// A waiter whose own context is done returns immediately rather than
	// blocking on the flight. fn is gated open so the only way fetch can
	// return is via the caller's cancellation.
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	gate := make(chan struct{})
	if _, err := c.fetch(cancelled, "hash2", func(context.Context) (apiKeyCacheEntry, error) {
		<-gate // never released
		return apiKeyCacheEntry{}, nil
	}); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled caller must return context.Canceled, got %v", err)
	}
	close(gate)

	// Disabled cache (nil) runs fn directly under the caller's context, so a
	// client disconnect cancels the lookup.
	var disabled *apiKeyCache
	if _, err := disabled.fetch(cancelled, "hash1", func(qctx context.Context) (apiKeyCacheEntry, error) {
		if qctx.Err() == nil {
			t.Error("disabled cache must run under the caller's context (cancellation invisible)")
		}
		return apiKeyCacheEntry{id: "id2"}, nil
	}); err != nil {
		t.Errorf("nil-cache fetch: %v", err)
	}
}
