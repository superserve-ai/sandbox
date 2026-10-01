package proxy

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
)

const revocationTTL = time.Second
const revocationPollInterval = 500 * time.Millisecond
const maxRoutingRevocations = 65536
const routingClockSkew = time.Minute

type routeVersion struct {
	sandbox string
	version int64
}

// RoutingRevocations permits bypass only with a complete, recent primary read.
// Notifications add denied versions; they never extend its lifetime.
type RoutingRevocations struct {
	mu      sync.RWMutex
	revoked map[routeVersion]struct{}
	pushed  map[routeVersion]struct{}
	expires time.Time
	epoch   uint64
}

func (r *RoutingRevocations) Ready() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return time.Now().Before(r.expires)
}

func (r *RoutingRevocations) Allows(sandbox string, version int64) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, revoked := r.revoked[routeVersion{sandbox, version}]
	return version > 0 && !revoked && time.Now().Before(r.expires)
}
func (r *RoutingRevocations) invalidate() {
	r.mu.Lock()
	r.expires = time.Time{}
	r.epoch++
	r.mu.Unlock()
}

// A push only denies its old version. It neither grants routes nor renews the
// snapshot, and is merged into a concurrent snapshot before publication.
func (r *RoutingRevocations) applyNotification(payload string) {
	id, raw, ok := strings.Cut(payload, ":")
	parsed, err := uuid.Parse(id)
	version, versionErr := strconv.ParseInt(raw, 10, 64)
	if !ok || err != nil || versionErr != nil || version <= 0 {
		r.invalidate()
		return
	}
	key := routeVersion{parsed.String(), version}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pushed == nil {
		r.pushed = make(map[routeVersion]struct{})
	}
	if r.revoked == nil {
		r.revoked = make(map[routeVersion]struct{})
	}
	if len(r.pushed) >= maxRoutingRevocations || len(r.revoked) >= maxRoutingRevocations {
		r.expires = time.Time{}
		r.epoch++
		return
	}
	r.pushed[key] = struct{}{}
	r.revoked[key] = struct{}{}
}

type routingQueryer interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func (r *RoutingRevocations) refresh(ctx context.Context, q routingQueryer) error {
	started := time.Now()
	r.mu.RLock()
	epoch := r.epoch
	r.mu.RUnlock()
	ctx, cancel := context.WithTimeout(ctx, ownershipLookupTimeout)
	defer cancel()
	// Sentinel row carries primary/time checks even when the revocation set is empty.
	rows, err := q.Query(ctx, `SELECT x.sandbox_id::text, x.routing_version, statement_timestamp(), pg_is_in_recovery()
 FROM (SELECT 1) sentinel LEFT JOIN LATERAL (
   SELECT sandbox_id, routing_version FROM sandbox_routing_revocation
   WHERE expires_at IS NULL OR expires_at > statement_timestamp()
   LIMIT 65537
 ) x ON true`)
	if err != nil {
		r.invalidate()
		return err
	}
	defer rows.Close()
	revoked := make(map[routeVersion]struct{})
	valid := false
	for rows.Next() {
		var id *string
		var version *int64
		var dbNow time.Time
		var replica bool
		if err := rows.Scan(&id, &version, &dbNow, &replica); err != nil {
			r.invalidate()
			return err
		}
		// Retention is two hours, versus one-hour hints. Reject clocks outside the
		// documented one-minute skew allowance instead of consuming that margin.
		if replica || dbNow.Before(started.Add(-routingClockSkew)) || dbNow.After(started.Add(routingClockSkew)) {
			r.invalidate()
			return errors.New("routing revocations require a primary with synchronized clock")
		}
		valid = true
		if id != nil && version != nil {
			revoked[routeVersion{*id, *version}] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		r.invalidate()
		return err
	}
	if !valid || len(revoked) > maxRoutingRevocations {
		r.invalidate()
		return errors.New("routing revocation snapshot incomplete or over capacity")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.epoch == epoch {
		for key := range r.pushed {
			revoked[key] = struct{}{}
		}
		r.pushed = nil
		if len(revoked) > maxRoutingRevocations {
			r.expires = time.Time{}
			return errors.New("routing revocation merge over capacity")
		}
		r.revoked, r.expires = revoked, started.Add(revocationTTL)
	}
	return nil
}

// Start uses one dedicated session for LISTEN and periodic snapshots. The same
// session refreshes host discovery; it never borrows ownership-query capacity.
func (r *RoutingRevocations) Start(ctx context.Context, pool *pgxpool.Pool, hosts *HostDirectory, log zerolog.Logger) {
	go func() {
		for ctx.Err() == nil {
			err := r.run(ctx, pool, hosts)
			r.invalidate()
			if ctx.Err() != nil {
				return
			}
			log.Warn().Err(err).Msg("routing hint state unavailable; using ownership lookups")
			timer := time.NewTimer(time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
}
func (r *RoutingRevocations) run(ctx context.Context, pool *pgxpool.Pool, hosts *HostDirectory) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	// LISTEN needs a session, not a transaction-pooled connection. Discard the
	// connection on reconnect so a reused session cannot retain queued messages.
	defer func() { _ = conn.Conn().Close(context.Background()); conn.Release() }()
	if _, err = conn.Exec(ctx, "LISTEN sandbox_routing_revoked"); err != nil {
		return err
	}
	nextHosts := time.Time{}
	for ctx.Err() == nil {
		if time.Now().After(nextHosts) {
			if err := hosts.refresh(ctx, DBHostDirectorySource{Pool: conn}); err != nil {
				return fmt.Errorf("host directory: %w", err)
			}
			nextHosts = time.Now().Add(hostDirectoryInterval)
		}
		if err := r.refresh(ctx, conn); err != nil {
			return err
		}
		deadline := time.Now().Add(revocationPollInterval)
		for time.Now().Before(deadline) {
			waitCtx, cancel := context.WithDeadline(ctx, deadline)
			notification, err := conn.Conn().WaitForNotification(waitCtx)
			cancel()
			if err != nil {
				if errors.Is(err, context.DeadlineExceeded) {
					break
				}
				return err
			}
			r.applyNotification(notification.Payload)
		}
	}
	return ctx.Err()
}
