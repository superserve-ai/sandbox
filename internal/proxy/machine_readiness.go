package proxy

import (
	"context"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/sync/singleflight"

	"github.com/superserve-ai/sandbox/internal/auth"
)

const MachineIdentityRevision = auth.MachineIdentityRevision
const machineReadinessTimeout = 500 * time.Millisecond
const machineReadinessTTL = time.Second

// These zero-row queries check the columns and SELECT privileges used by the
// serving resolvers without scanning tenant data or reading credential secrets.
const machineAuthorityReadinessSQL = `SELECT EXISTS (
 SELECT 1 FROM machine_credential c JOIN machine_principal p ON p.id=c.principal_id
 WHERE false AND c.id IS NOT NULL AND c.state='active' AND c.expires_at>now()
 AND p.status='active' AND c.revocation_generation=p.generation)`
const machineOwnershipReadinessSQL = `SELECT EXISTS (
 SELECT 1 FROM sandbox s LEFT JOIN sandbox_machine_owner mo ON mo.sandbox_id=s.id
 WHERE false AND s.id IS NOT NULL AND s.team_id IS NOT NULL AND s.destroyed_at IS NULL
 AND mo.owner_principal_id IS NOT NULL AND mo.team_id IS NOT NULL)`

type machineReadinessState struct {
	mu        sync.Mutex
	ready     bool
	expiresAt time.Time
	flight    singleflight.Group
}

// MachineIdentityReady reports the machine contract's local wiring and database
// availability. The health transport combines this with its existing VMD probe.
// This check is never consulted by stream frames or sandbox lifecycle requests.
func (h *Handler) MachineIdentityReady(ctx context.Context) bool {
	if h == nil || auth.ValidateSeed(h.seedKey) != nil || h.machineAuthority == nil || h.sessions == nil || h.sandboxOwnership == nil {
		return false
	}
	authority, ok := h.machineAuthoritySnapshotter.(*CachedMachineAuthority)
	if !ok || authority == nil || !configuredMachineReadinessPool(authority.pool) || !configuredMachineReadinessPool(h.sandboxOwnership.pool) {
		return false
	}
	state := &h.machineReadiness
	state.mu.Lock()
	if time.Now().Before(state.expiresAt) {
		ready := state.ready
		state.mu.Unlock()
		return ready
	}
	state.mu.Unlock()
	probeCtx, cancel := context.WithTimeout(ctx, machineReadinessTimeout)
	defer cancel()
	result := state.flight.DoChan("health", func() (any, error) {
		state.mu.Lock()
		if time.Now().Before(state.expiresAt) {
			ready := state.ready
			state.mu.Unlock()
			return ready, nil
		}
		state.mu.Unlock()
		started := time.Now()
		var unused bool
		ready := authority.pool.QueryRow(probeCtx, machineAuthorityReadinessSQL).Scan(&unused) == nil
		if ready {
			ready = h.sandboxOwnership.pool.QueryRow(probeCtx, machineOwnershipReadinessSQL).Scan(&unused) == nil
		}
		ready = ready && probeCtx.Err() == nil && time.Since(started) < machineReadinessTimeout
		state.mu.Lock()
		state.ready, state.expiresAt = ready, started.Add(machineReadinessTTL)
		state.mu.Unlock()
		return ready, nil
	})
	select {
	case <-probeCtx.Done():
		return false
	case value := <-result:
		return value.Err == nil && value.Val.(bool)
	}
}

func configuredMachineReadinessPool(pool machineAuthorityQuerier) bool {
	if pool == nil {
		return false
	}
	if concrete, ok := pool.(*pgxpool.Pool); ok && concrete == nil {
		return false
	}
	return true
}
