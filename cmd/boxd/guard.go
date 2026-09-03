package main

import (
	"context"
	"sync"
)

// spawnGuard is a read-write guard whose write side can wait with a context.
// Readers (spawns) share it; a writer (freeze) waits for them and holds new
// ones off only while it is still waiting, so a writer that gives up leaves
// nothing blocked behind it.
type spawnGuard struct {
	mu      sync.Mutex
	readers int
	writer  bool
	waiting int
	changed chan struct{} // closed on every release; nil while nobody waits
}

func (g *spawnGuard) changes() chan struct{} {
	if g.changed == nil {
		g.changed = make(chan struct{})
	}
	return g.changed
}

func (g *spawnGuard) release() {
	if g.changed != nil {
		close(g.changed)
		g.changed = nil
	}
}

func (g *spawnGuard) RLock() {
	g.mu.Lock()
	for g.writer || g.waiting > 0 {
		ch := g.changes()
		g.mu.Unlock()
		<-ch
		g.mu.Lock()
	}
	g.readers++
	g.mu.Unlock()
}

func (g *spawnGuard) RUnlock() {
	g.mu.Lock()
	g.readers--
	g.release()
	g.mu.Unlock()
}

// Lock takes the write side, waiting as long as it takes.
func (g *spawnGuard) Lock() { _ = g.LockContext(context.Background()) }

// LockContext takes the write side, or gives up when ctx ends first.
func (g *spawnGuard) LockContext(ctx context.Context) error {
	g.mu.Lock()
	g.waiting++
	for g.writer || g.readers > 0 {
		ch := g.changes()
		g.mu.Unlock()
		select {
		case <-ch:
			g.mu.Lock()
		case <-ctx.Done():
			g.mu.Lock()
			g.waiting--
			g.release()
			g.mu.Unlock()
			return ctx.Err()
		}
	}
	g.waiting--
	g.writer = true
	g.mu.Unlock()
	return nil
}

func (g *spawnGuard) Unlock() {
	g.mu.Lock()
	g.writer = false
	g.release()
	g.mu.Unlock()
}
