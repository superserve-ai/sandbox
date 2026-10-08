package network

import "sync"

type connectionCounter struct{ active int64 }

// ConnectionLimiter counts live acquisitions, including retired registrations.
// Release handles retain their counter even after its address is reused.
type ConnectionLimiter struct {
	mu          sync.Mutex
	connections map[string]*connectionCounter
}

func NewConnectionLimiter() *ConnectionLimiter {
	return &ConnectionLimiter{connections: make(map[string]*connectionCounter)}
}

// TryAcquire returns an idempotent release handle. Negative limits are unlimited;
// zero rejects every attempt. The caller must close its sockets before release.
func (l *ConnectionLimiter) TryAcquire(key string, limit int) (func(), bool) {
	l.mu.Lock()
	c := l.connections[key]
	if c == nil {
		c = &connectionCounter{}
	}
	if limit >= 0 && c.active >= int64(limit) {
		l.mu.Unlock()
		return nil, false
	}
	c.active++
	l.connections[key] = c
	l.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			c.active--
			if c.active == 0 && l.connections[key] == c {
				delete(l.connections, key)
			}
		})
	}, true
}

func (l *ConnectionLimiter) Remove(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.connections, key)
}

func (l *ConnectionLimiter) Count(key string) int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	if c := l.connections[key]; c != nil {
		return c.active
	}
	return 0
}
