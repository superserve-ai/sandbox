package proxy

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/sync/singleflight"

	"github.com/superserve-ai/sandbox/internal/auth"
)

// CachedMachineAuthority provides the bounded local freshness boundary used by
// request and stream admission. Revoked/disabled rows are misses; an outage
// never extends an expired snapshot and no frame performs durable I/O.
type CachedMachineAuthority struct {
	pool   machineAuthorityQuerier
	ttl    time.Duration
	mu     sync.Mutex
	items  map[machineAuthorityKey]machineAuthorityEntry
	epoch  uint64
	flight singleflight.Group
}

type machineAuthorityQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

type machineAuthorityKey struct{ principal, credential uuid.UUID }
type machineAuthorityEntry struct {
	generation uint64
	expiresAt  time.Time
}

var errAuthoritySnapshotExpired = errors.New("machine authority snapshot expired")

func NewCachedMachineAuthority(pool *pgxpool.Pool, ttl time.Duration) *CachedMachineAuthority {
	if ttl <= 0 || ttl > 5*time.Second {
		ttl = 5 * time.Second
	}
	a := &CachedMachineAuthority{pool: pool, ttl: ttl, items: make(map[machineAuthorityKey]machineAuthorityEntry)}
	return a
}

func (a *CachedMachineAuthority) Lookup(ctx context.Context, principalID, credentialID uuid.UUID) (uint64, error) {
	generation, _, err := a.LookupSnapshot(ctx, principalID, credentialID)
	return generation, err
}

// LookupSnapshot returns the generation and an absolute freshness deadline.
// The deadline is based on when the durable observation began, not when a
// slow query happened to complete. In-flight fills are coalesced and an
// invalidation epoch prevents late results from re-entering the cache.
func (a *CachedMachineAuthority) LookupSnapshot(ctx context.Context, principalID, credentialID uuid.UUID) (uint64, time.Time, error) {
	return a.lookupSnapshot(ctx, principalID, credentialID, false)
}

func (a *CachedMachineAuthority) RefreshSnapshot(ctx context.Context, principalID, credentialID uuid.UUID) (uint64, time.Time, error) {
	return a.lookupSnapshot(ctx, principalID, credentialID, true)
}

func (a *CachedMachineAuthority) lookupSnapshot(ctx context.Context, principalID, credentialID uuid.UUID, force bool) (uint64, time.Time, error) {
	if a == nil || a.pool == nil || principalID == uuid.Nil || credentialID == uuid.Nil {
		return 0, time.Time{}, errors.New("machine authority unavailable")
	}
	if err := ctx.Err(); err != nil {
		return 0, time.Time{}, err
	}
	now := time.Now()
	key := machineAuthorityKey{principal: principalID, credential: credentialID}
	a.mu.Lock()
	if entry, ok := a.items[key]; ok && a.usable(entry, now, force) {
		a.mu.Unlock()
		return entry.generation, entry.expiresAt, nil
	}
	epoch := a.epoch
	a.mu.Unlock()
	result := a.flight.DoChan(keyString(key), func() (any, error) {
		observedAt := time.Now()
		a.mu.Lock()
		if a.epoch != epoch {
			a.mu.Unlock()
			return authoritySnapshot{}, errors.New("machine authority invalidated")
		}
		// A previous flight may have finished after this caller's first cache
		// check. Reuse it instead of serializing one durable read per stream.
		if entry, ok := a.items[key]; ok && a.usable(entry, observedAt, force) {
			a.mu.Unlock()
			return authoritySnapshot{generation: entry.generation, expiresAt: entry.expiresAt}, nil
		}
		a.mu.Unlock()
		// One disconnected stream must not cancel the durable observation shared
		// by other streams. The query retains its own bounded lifetime.
		queryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		var generation int64
		err := a.pool.QueryRow(queryCtx, `SELECT c.revocation_generation FROM machine_credential c JOIN machine_principal p ON p.id=c.principal_id WHERE c.id=$1 AND c.principal_id=$2 AND c.state='active' AND c.expires_at>now() AND p.status='active' AND c.revocation_generation=p.generation`, credentialID, principalID).Scan(&generation)
		deadline := observedAt.Add(a.ttl)
		if err != nil {
			a.mu.Lock()
			if a.epoch == epoch {
				delete(a.items, key)
			}
			a.mu.Unlock()
			if errors.Is(err, pgx.ErrNoRows) {
				return authoritySnapshot{}, auth.ErrMachineCapabilityDenied
			}
			return authoritySnapshot{}, err
		}
		if !time.Now().Before(deadline) {
			return authoritySnapshot{}, errAuthoritySnapshotExpired
		}
		a.mu.Lock()
		if a.epoch != epoch {
			a.mu.Unlock()
			return authoritySnapshot{}, errors.New("machine authority invalidated")
		}
		a.items[key] = machineAuthorityEntry{generation: uint64(generation), expiresAt: deadline}
		a.trimLocked()
		a.mu.Unlock()
		return authoritySnapshot{generation: uint64(generation), expiresAt: deadline}, nil
	})
	select {
	case <-ctx.Done():
		return 0, time.Time{}, ctx.Err()
	case completed := <-result:
		if completed.Err != nil {
			return 0, time.Time{}, completed.Err
		}
		snapshot := completed.Val.(authoritySnapshot)
		return snapshot.generation, snapshot.expiresAt, nil
	}
}

// Refresh early enough to renew healthy streams, but share each observation
// across staggered timers as well as concurrent calls. Admission may use the
// full freshness window; continuation refreshes after half the window.
func (a *CachedMachineAuthority) usable(entry machineAuthorityEntry, now time.Time, refresh bool) bool {
	remaining := entry.expiresAt.Sub(now)
	return remaining > 0 && (!refresh || remaining > a.ttl/2)
}

type authoritySnapshot struct {
	generation uint64
	expiresAt  time.Time
}

func keyString(key machineAuthorityKey) string {
	return key.principal.String() + ":" + key.credential.String()
}

func (a *CachedMachineAuthority) trimLocked() {
	for len(a.items) > 4096 {
		for k := range a.items {
			delete(a.items, k)
			break
		}
	}
}

func (a *CachedMachineAuthority) InvalidateCredential(credentialID uuid.UUID) {
	if a == nil {
		return
	}
	a.mu.Lock()
	a.epoch++
	defer a.mu.Unlock()
	for key := range a.items {
		if key.credential == credentialID {
			delete(a.items, key)
		}
	}
}

func (a *CachedMachineAuthority) InvalidatePrincipal(principalID uuid.UUID) {
	if a == nil {
		return
	}
	a.mu.Lock()
	a.epoch++
	defer a.mu.Unlock()
	for key := range a.items {
		if key.principal == principalID {
			delete(a.items, key)
		}
	}
}
