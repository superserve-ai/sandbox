package proxy

import (
	"container/list"
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	ownershipCacheTTL   = time.Second
	ownershipCacheSize  = 4096
	ownershipMaxLookups = 32
	// Callers held for a slot are bounded too, so a backlog or random IDs still
	// shed load; 256 is several rounds of lookups within one lookup timeout.
	ownershipMaxWaiters = 256
)

var errOwnershipCapacity = errors.New("ownership lookup capacity exhausted")

type ownershipEntry struct {
	id      string
	route   SandboxRoute
	err     error
	expires time.Time
}

type ownershipFlight struct {
	done  chan struct{}
	route SandboxRoute
	err   error
}

// CachedOwnershipResolver permits at most one second of ownership staleness.
// Expiry starts before the query; failures never extend a previously valid route.
// One canceled HTTP request must not cancel a lookup shared by other requests.
type CachedOwnershipResolver struct {
	ctx     context.Context
	source  OwnershipResolver
	mu      sync.Mutex
	entries map[string]*list.Element
	lru     list.List
	flights map[string]*ownershipFlight
	// waiters queue callers for a free lookup slot in arrival order. A
	// finished lookup hands its slot to the oldest waiter (reserved) so newer
	// callers cannot overtake the backlog; each handoff wakes exactly one.
	waiters  list.List
	reserved int
	now      func() time.Time
}

func NewCachedOwnershipResolver(ctx context.Context, source OwnershipResolver) *CachedOwnershipResolver {
	return &CachedOwnershipResolver{ctx: ctx, source: source, entries: make(map[string]*list.Element), flights: make(map[string]*ownershipFlight), now: time.Now}
}

func (c *CachedOwnershipResolver) ResolveSandbox(ctx context.Context, id string) (SandboxRoute, error) {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return SandboxRoute{}, err
	}
	id = parsed.String()
	if err := ctx.Err(); err != nil {
		return SandboxRoute{}, err
	}
	c.mu.Lock()
	if entry, ok := c.cachedLocked(id); ok {
		c.mu.Unlock()
		return entry.route, entry.err
	}
	f := c.flights[id]
	if f == nil && (len(c.flights)+c.reserved >= ownershipMaxLookups || c.waiters.Len() > 0) {
		// A full lookup table holds the caller for a slot rather than failing
		// a burst; one lookup timeout bounds the wait, since a slot frees within it.
		if c.waiters.Len() >= ownershipMaxWaiters {
			c.mu.Unlock()
			return SandboxRoute{}, errOwnershipCapacity
		}
		wake := make(chan struct{}, 1)
		queued := c.waiters.PushBack(wake)
		c.mu.Unlock()
		waitLimit := time.NewTimer(ownershipLookupTimeout)
		granted := false
		var cancelErr error
		select {
		case <-wake:
			granted = true
		case <-waitLimit.C:
		case <-ctx.Done():
		case <-c.ctx.Done():
		}
		waitLimit.Stop()
		// A caller canceled while waiting must not take the slot.
		if cancelErr = ctx.Err(); cancelErr == nil {
			cancelErr = c.ctx.Err()
		}
		c.mu.Lock()
		c.waiters.Remove(queued)
		if !granted {
			select {
			case <-wake:
				granted = true
			default:
			}
		}
		if granted {
			c.reserved--
		}
		if cancelErr != nil {
			if granted {
				c.wakeWaiterLocked()
			}
			c.mu.Unlock()
			return SandboxRoute{}, cancelErr
		}
		// The wait may have outlasted a lookup for the same sandbox.
		if entry, ok := c.cachedLocked(id); ok {
			if granted {
				c.wakeWaiterLocked()
			}
			c.mu.Unlock()
			return entry.route, entry.err
		}
		if f = c.flights[id]; f != nil {
			// Joining an existing lookup passes the slot to the next waiter.
			if granted {
				c.wakeWaiterLocked()
			}
		} else if !granted {
			c.mu.Unlock()
			return SandboxRoute{}, errOwnershipCapacity
		}
	}
	if f == nil {
		f = &ownershipFlight{done: make(chan struct{})}
		c.flights[id] = f
		started := c.now()
		go c.lookup(id, f, started)
	}
	c.mu.Unlock()
	select {
	case <-ctx.Done():
		return SandboxRoute{}, ctx.Err()
	case <-c.ctx.Done():
		return SandboxRoute{}, c.ctx.Err()
	case <-f.done:
		return f.route, f.err
	}
}

func (c *CachedOwnershipResolver) lookup(id string, f *ownershipFlight, started time.Time) {
	ctx, cancel := context.WithTimeout(c.ctx, ownershipLookupTimeout)
	defer cancel()
	f.route, f.err = c.source.ResolveSandbox(ctx, id)
	c.mu.Lock()
	defer c.mu.Unlock()
	ttl := ownershipCacheTTL
	if f.err != nil {
		// Briefly coalesce failures as well as successes during an outage.
		ttl = 100 * time.Millisecond
	}
	expires := started.Add(ttl)
	if c.ctx.Err() == nil && c.now().Before(expires) {
		if c.lru.Len() == ownershipCacheSize {
			oldest := c.lru.Back()
			delete(c.entries, oldest.Value.(ownershipEntry).id)
			c.lru.Remove(oldest)
		}
		c.entries[id] = c.lru.PushFront(ownershipEntry{id: id, route: f.route, err: f.err, expires: expires})
	}
	delete(c.flights, id)
	c.wakeWaiterLocked()
	close(f.done)
}

// wakeWaiterLocked hands a free lookup slot to the longest waiting caller.
func (c *CachedOwnershipResolver) wakeWaiterLocked() {
	if front := c.waiters.Front(); front != nil {
		c.waiters.Remove(front)
		c.reserved++
		front.Value.(chan struct{}) <- struct{}{}
	}
}

func (c *CachedOwnershipResolver) cachedLocked(id string) (ownershipEntry, bool) {
	e := c.entries[id]
	if e == nil {
		return ownershipEntry{}, false
	}
	entry := e.Value.(ownershipEntry)
	if c.now().Before(entry.expires) {
		c.lru.MoveToFront(e)
		return entry, true
	}
	c.lru.Remove(e)
	delete(c.entries, id)
	return ownershipEntry{}, false
}
