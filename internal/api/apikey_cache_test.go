package api

import (
	"fmt"
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
	// Expired entry must have been evicted, not just skipped.
	c.mu.Lock()
	_, exists := c.m["hash1"]
	c.mu.Unlock()
	if exists {
		t.Error("expected expired entry to be deleted")
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
