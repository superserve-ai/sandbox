package network

import (
	"sync"
	"sync/atomic"
)

// ConnectionLimiter tracks and limits per-sandbox concurrent TCP connections.
type ConnectionLimiter struct {
	mu          sync.Mutex
	connections map[string]*atomic.Int64
}

func NewConnectionLimiter() *ConnectionLimiter {
	return &ConnectionLimiter{
		connections: make(map[string]*atomic.Int64),
	}
}

func (l *ConnectionLimiter) getCounter(sandboxID string) *atomic.Int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	c, ok := l.connections[sandboxID]
	if !ok {
		c = &atomic.Int64{}
		l.connections[sandboxID] = c
	}
	return c
}

// TryAcquire attempts to acquire a connection slot.
// Returns (current count, true) on success, (current count, false) if limit exceeded.
// A negative maxLimit means unlimited. Zero means all connections blocked.
func (l *ConnectionLimiter) TryAcquire(sandboxID string, maxLimit int) (int64, bool) {
	counter := l.getCounter(sandboxID)
	for {
		current := counter.Load()
		if maxLimit >= 0 && current >= int64(maxLimit) {
			return current, false
		}
		if counter.CompareAndSwap(current, current+1) {
			return current + 1, true
		}
	}
}

// Release decrements the connection count for a sandbox.
func (l *ConnectionLimiter) Release(sandboxID string) {
	l.mu.Lock()
	counter, ok := l.connections[sandboxID]
	l.mu.Unlock()
	if !ok {
		return
	}
	for {
		current := counter.Load()
		if current <= 0 {
			return
		}
		if counter.CompareAndSwap(current, current-1) {
			return
		}
	}
}

// Remove removes a sandbox's connection tracking entry entirely.
func (l *ConnectionLimiter) Remove(sandboxID string) {
	l.mu.Lock()
	delete(l.connections, sandboxID)
	l.mu.Unlock()
}

// Count returns the current connection count for a sandbox.
func (l *ConnectionLimiter) Count(sandboxID string) int64 {
	l.mu.Lock()
	counter, ok := l.connections[sandboxID]
	l.mu.Unlock()
	if !ok {
		return 0
	}
	return counter.Load()
}
