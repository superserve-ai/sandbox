package proxy

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	dbq "github.com/superserve-ai/sandbox/internal/db"
)

// DBOwnershipResolver performs the authoritative edge lookup in one round trip.
type DBOwnershipResolver struct{ pool *pgxpool.Pool }

// ownershipLookupTimeout bounds the synchronous database work performed
// before a new connection can be routed. The caller's cancellation and
// deadline remain effective through the derived context.
const ownershipLookupTimeout = 500 * time.Millisecond

func NewDBOwnershipResolver(pool *pgxpool.Pool) *DBOwnershipResolver {
	return &DBOwnershipResolver{pool: pool}
}
func (r *DBOwnershipResolver) ResolveSandbox(ctx context.Context, id string) (SandboxRoute, error) {
	sandboxID, err := uuid.Parse(id)
	if err != nil {
		return SandboxRoute{}, fmt.Errorf("invalid sandbox id: %w", err)
	}
	lookupCtx, cancel := context.WithTimeout(ctx, ownershipLookupTimeout)
	defer cancel()
	row, err := dbq.New(r.pool).GetSandboxRoute(lookupCtx, sandboxID)
	if err != nil {
		if lookupCtx.Err() != nil {
			err = lookupCtx.Err()
		}
		return SandboxRoute{}, fmt.Errorf("resolve sandbox ownership: %w", err)
	}
	route, err := routeFromRecordedHost(row.HostID, row.VmdAddr)
	if err != nil {
		return SandboxRoute{}, fmt.Errorf("resolve sandbox ownership: %w", err)
	}
	return route, nil
}

// Only the registered VMD IP selects the peer. Heartbeat-supplied proxy_addr
// is deliberately excluded from the ownership query and cannot redirect traffic.
func routeFromRecordedHost(hostID, vmdAddr string) (SandboxRoute, error) {
	addr, err := netip.ParseAddrPort(vmdAddr)
	if err != nil || addr.Port() == 0 || !addr.Addr().IsGlobalUnicast() || addr.Addr().IsLoopback() || addr.Addr().Zone() != "" {
		return SandboxRoute{}, fmt.Errorf("invalid recorded VMD address")
	}
	return NormalizeSandboxRoute(SandboxRoute{HostID: strings.TrimSpace(hostID), ProxyAddr: netip.AddrPortFrom(addr.Addr().Unmap(), 5009).String()})
}
