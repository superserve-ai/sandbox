package proxy

import (
	"sync"
	"testing"
	"time"
)

func TestNonceCache_FreshNonceAccepted(t *testing.T) {
	c := NewNonceCache(10, time.Minute)
	now := time.Unix(1_700_000_000, 0)
	if !c.CheckAndStore("a", now) {
		t.Error("first sighting of nonce should be accepted")
	}
}

func TestNonceCache_ReplayRejected(t *testing.T) {
	c := NewNonceCache(10, time.Minute)
	now := time.Unix(1_700_000_000, 0)

	if !c.CheckAndStore("a", now) {
		t.Fatal("first call should succeed")
	}
	if c.CheckAndStore("a", now) {
		t.Error("replay should be rejected")
	}
}

func TestNonceCache_ExpiredEntryReleasesSlot(t *testing.T) {
	c := NewNonceCache(10, time.Minute)
	now := time.Unix(1_700_000_000, 0)

	c.CheckAndStore("a", now)

	// Advance past TTL — replay should now be allowed because the
	// entry has expired and the cache treats it as fresh.
	later := now.Add(2 * time.Minute)
	if !c.CheckAndStore("a", later) {
		t.Error("expired nonce should be re-acceptable as fresh")
	}
}

func TestNonceCache_LRUEvictionAtCap(t *testing.T) {
	// With cap=3, inserting 4 nonces evicts the oldest. Verify both that
	// the oldest is gone (re-insertable) and that the survivors still
	// replay-protect.
	c := NewNonceCache(3, time.Hour)
	now := time.Unix(1_700_000_000, 0)

	c.CheckAndStore("a", now)
	c.CheckAndStore("b", now)
	c.CheckAndStore("c", now)
	c.CheckAndStore("d", now) // evicts "a"

	if c.Len() != 3 {
		t.Errorf("len = %d, want 3", c.Len())
	}

	// "b", "c", "d" should still replay-protect.
	for _, k := range []string{"b", "c", "d"} {
		if c.CheckAndStore(k, now) {
			t.Errorf("nonce %q should still be cached", k)
		}
	}

	// "a" was evicted by the size cap, so it should be re-acceptable
	// (treated as fresh on the next sighting).
	if !c.CheckAndStore("a", now) {
		t.Error("evicted nonce should be re-acceptable")
	}
}

func TestNonceCache_ConcurrentReplayProtection(t *testing.T) {
	// Hammer the same nonce from many goroutines simultaneously. Exactly
	// one should win — if the check-and-store is not atomic, we'd see
	// multiple winners.
	c := NewNonceCache(10, time.Minute)
	now := time.Unix(1_700_000_000, 0)

	const goroutines = 100
	wins := 0
	var mu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			if c.CheckAndStore("contested", now) {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if wins != 1 {
		t.Errorf("wins = %d, want exactly 1", wins)
	}
}

func TestNonceCache_DistinctNoncesIndependent(t *testing.T) {
	c := NewNonceCache(10, time.Minute)
	now := time.Unix(1_700_000_000, 0)

	for _, k := range []string{"a", "b", "c", "d", "e"} {
		if !c.CheckAndStore(k, now) {
			t.Errorf("distinct nonce %q should be accepted", k)
		}
	}
	if c.Len() != 5 {
		t.Errorf("len = %d, want 5", c.Len())
	}
}
