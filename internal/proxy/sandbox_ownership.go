package proxy

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/sync/singleflight"

	"github.com/superserve-ai/sandbox/internal/auth"
)

const sandboxOwnershipTTL = 5 * time.Second
const sandboxOwnershipSQL = `SELECT mo.owner_principal_id::text, mo.team_id::text
 FROM sandbox s LEFT JOIN sandbox_machine_owner mo ON mo.sandbox_id=s.id
 WHERE s.id=$1 AND s.team_id=$2 AND s.destroyed_at IS NULL`

// CachedSandboxOwnership attests legacy records which have no local ownership
// metadata. Only a live, team-matching durable row can establish ordinary
// ownership; a missing association is never inferred from a VMD record.
// Lookups happen after token verification, never during VM boot or per frame.
type CachedSandboxOwnership struct {
	pool   machineAuthorityQuerier
	mu     sync.Mutex
	items  map[string]sandboxOwnershipEntry
	flight singleflight.Group
}

type sandboxOwnershipEntry struct {
	principal string
	expiresAt time.Time
}

func NewCachedSandboxOwnership(pool *pgxpool.Pool) *CachedSandboxOwnership {
	a := &CachedSandboxOwnership{items: make(map[string]sandboxOwnershipEntry)}
	if pool != nil {
		a.pool = pool
	}
	return a
}

func (h *Handler) WithSandboxOwnership(authority *CachedSandboxOwnership) *Handler {
	h.sandboxOwnership = authority
	return h
}

func (a *CachedSandboxOwnership) lookup(ctx context.Context, sandboxID, teamID string) (string, error) {
	if a == nil || a.pool == nil {
		return "", errors.New("sandbox ownership unavailable")
	}
	sandbox, err := uuid.Parse(sandboxID)
	if err != nil || sandbox == uuid.Nil {
		return "", errors.New("invalid sandbox")
	}
	team, err := uuid.Parse(teamID)
	if err != nil || team == uuid.Nil {
		return "", errors.New("invalid sandbox team")
	}
	key := sandbox.String() + ":" + team.String()
	a.mu.Lock()
	cached, ok := a.items[key]
	a.mu.Unlock()
	if ok && time.Now().Before(cached.expiresAt) {
		return cached.principal, nil
	}
	result, err, _ := a.flight.Do(key, func() (any, error) {
		a.mu.Lock()
		cached, ok := a.items[key]
		a.mu.Unlock()
		if ok && time.Now().Before(cached.expiresAt) {
			return cached, nil
		}
		observedAt := time.Now()
		lookupCtx, cancel := context.WithTimeout(ctx, ownershipLookupTimeout)
		defer cancel()
		var principal, ownerTeam *string
		if err := a.pool.QueryRow(lookupCtx, sandboxOwnershipSQL, sandbox, team).Scan(&principal, &ownerTeam); err != nil {
			return nil, err
		}
		if lookupCtx.Err() != nil || !time.Now().Before(observedAt.Add(ownershipLookupTimeout)) {
			return nil, errors.New("sandbox ownership lookup expired")
		}
		entry := sandboxOwnershipEntry{expiresAt: observedAt.Add(sandboxOwnershipTTL)}
		if principal != nil {
			id, err := uuid.Parse(*principal)
			if err != nil || id == uuid.Nil || ownerTeam == nil || *ownerTeam != team.String() {
				return nil, errors.New("sandbox owner association mismatch")
			}
			entry.principal = id.String()
		} else if ownerTeam != nil {
			return nil, errors.New("incomplete sandbox owner association")
		}
		a.mu.Lock()
		// A fixed ceiling bounds memory even for many distinct valid credentials.
		if len(a.items) >= 4096 {
			for k := range a.items {
				delete(a.items, k)
				break
			}
		}
		a.items[key] = entry
		a.mu.Unlock()
		return entry, nil
	})
	if err != nil {
		return "", err
	}
	return result.(sandboxOwnershipEntry).principal, nil
}

func (h *Handler) attestUnclassifiedSandbox(ctx context.Context, sandboxID string, info InstanceInfo) (InstanceInfo, error) {
	if info.OwnershipState != auth.OwnershipUnknown || info.MachineOwned || info.MachineOwnerPrincipalID != "" {
		return info, nil
	}
	if info.OwnerID != "" {
		creator, err := uuid.Parse(info.OwnerID)
		if !info.legacyOwnershipState || err != nil || creator == uuid.Nil {
			return info, nil
		}
	}
	principal, err := h.sandboxOwnership.lookup(ctx, sandboxID, info.TeamID)
	if err != nil {
		return info, err
	}
	info.OwnershipState = auth.OwnershipOrdinary
	if principal != "" {
		info.OwnershipState = auth.OwnershipMachine
		info.MachineOwned = true
		info.MachineOwnerPrincipalID = principal
	}
	return info, nil
}
