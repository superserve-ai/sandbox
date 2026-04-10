package proxy

import "sync"

// connLimiter tracks active connections per key (sandbox ID or client IP)
// and rejects new connections when a per-key limit is exceeded.
type connLimiter struct {
	mu     sync.Mutex
	counts map[string]int
	limit  int
}

func newConnLimiter(limit int) *connLimiter {
	return &connLimiter{
		counts: make(map[string]int),
		limit:  limit,
	}
}

// acquire increments the counter for key. Returns false if the limit is reached.
func (cl *connLimiter) acquire(key string) bool {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	if cl.counts[key] >= cl.limit {
		return false
	}
	cl.counts[key]++
	return true
}

// release decrements the counter for key.
func (cl *connLimiter) release(key string) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	cl.counts[key]--
	if cl.counts[key] <= 0 {
		delete(cl.counts, key)
	}
}
