package proxy

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CachedMachineAuthority provides the bounded local freshness boundary used by
// request and stream admission. Revoked/disabled rows are misses; an outage
// never extends an expired snapshot and no frame performs durable I/O.
type CachedMachineAuthority struct {
	pool  *pgxpool.Pool
	ttl   time.Duration
	mu    sync.Mutex
	items map[machineAuthorityKey]machineAuthorityEntry
}

type machineAuthorityKey struct{ principal, credential uuid.UUID }
type machineAuthorityEntry struct {
	generation uint64
	expiresAt  time.Time
}

func NewCachedMachineAuthority(pool *pgxpool.Pool, ttl time.Duration) *CachedMachineAuthority {
	if ttl <= 0 {
		ttl = 5 * time.Second
	}
	a := &CachedMachineAuthority{pool: pool, ttl: ttl, items: make(map[machineAuthorityKey]machineAuthorityEntry)}
	return a
}

func (a *CachedMachineAuthority) Lookup(ctx context.Context, principalID, credentialID uuid.UUID) (uint64, error) {
	if a == nil || a.pool == nil || principalID == uuid.Nil || credentialID == uuid.Nil {
		return 0, errors.New("machine authority unavailable")
	}
	now := time.Now()
	key := machineAuthorityKey{principal: principalID, credential: credentialID}
	a.mu.Lock()
	if entry, ok := a.items[key]; ok && now.Before(entry.expiresAt) {
		a.mu.Unlock()
		return entry.generation, nil
	}
	a.mu.Unlock()

	var generation int64
	err := a.pool.QueryRow(ctx, `SELECT c.revocation_generation FROM machine_credential c JOIN machine_principal p ON p.id=c.principal_id WHERE c.id=$1 AND c.principal_id=$2 AND c.state='active' AND c.expires_at>now() AND p.status='active' AND c.revocation_generation=p.generation`, credentialID, principalID).Scan(&generation)
	if err != nil {
		a.mu.Lock()
		delete(a.items, key)
		a.mu.Unlock()
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, errors.New("machine authority denied")
		}
		return 0, err
	}
	a.mu.Lock()
	if len(a.items) >= 4096 {
		for k := range a.items {
			delete(a.items, k)
			break
		}
	}
	a.items[key] = machineAuthorityEntry{generation: uint64(generation), expiresAt: now.Add(a.ttl)}
	a.mu.Unlock()
	return uint64(generation), nil
}

func (a *CachedMachineAuthority) InvalidateCredential(credentialID uuid.UUID) {
	if a == nil {
		return
	}
	a.mu.Lock()
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
	defer a.mu.Unlock()
	for key := range a.items {
		if key.principal == principalID {
			delete(a.items, key)
		}
	}
}
