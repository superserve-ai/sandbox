package proxy

import (
	"context"
	"fmt"
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
	route, err := NormalizeSandboxRoute(SandboxRoute{HostID: strings.TrimSpace(row.HostID), ProxyAddr: strings.TrimSpace(row.ProxyAddr)})
	if err != nil {
		return SandboxRoute{}, fmt.Errorf("resolve sandbox ownership: %w", err)
	}
	return route, nil
}
