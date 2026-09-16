package proxy

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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
	row, err := dbq.New(r.pool).GetSandboxPeerEndpoint(lookupCtx, sandboxID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return SandboxRoute{}, ErrInstanceNotFound
		}
		if lookupCtx.Err() != nil {
			err = lookupCtx.Err()
		}
		return SandboxRoute{}, fmt.Errorf("resolve sandbox ownership: %w", err)
	}
	endpoint, err := PeerEndpointFromDiscovery(row)
	if err != nil {
		return SandboxRoute{}, fmt.Errorf("resolve sandbox ownership: %w", err)
	}
	route, err := routeFromRecordedHost(row.HostID, *row.VmdAddr, endpoint.Generation)
	if err != nil {
		return SandboxRoute{}, fmt.Errorf("resolve sandbox ownership: %w", err)
	}
	return route, nil
}

// Only the registered VMD IP selects the peer. The advertised listener gates
// eligibility in PeerEndpointFromDiscovery but cannot redirect traffic.
func routeFromRecordedHost(hostID, vmdAddr string, generation uint64) (SandboxRoute, error) {
	addr, err := netip.ParseAddrPort(vmdAddr)
	if err != nil || addr.Port() == 0 || !addr.Addr().IsGlobalUnicast() || addr.Addr().IsLoopback() || addr.Addr().Zone() != "" {
		return SandboxRoute{}, fmt.Errorf("invalid recorded VMD address")
	}
	return NormalizeSandboxRoute(SandboxRoute{Generation: generation, HostID: strings.TrimSpace(hostID), ProxyAddr: netip.AddrPortFrom(addr.Addr().Unmap(), PeerPort).String()})
}
