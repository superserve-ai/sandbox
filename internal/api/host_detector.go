package api

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/sentrylog"
)

const (
	// heartbeatTimeout is how long a host can go without heartbeating
	// before it's marked unhealthy. Matches the design doc's "2 minutes".
	heartbeatTimeout = 2 * time.Minute

	// detectorInterval is how often we check for stale hosts.
	detectorInterval = 30 * time.Second

	// detectorRunTimeout bounds each detection pass so a slow DB can't
	// wedge the loop.
	detectorRunTimeout = 15 * time.Second
)

// StartHostDetector launches a background goroutine that periodically
// marks active hosts as unhealthy when their heartbeat goes stale.
// onUnhealthy (optional) runs after a pass that marked at least one host —
// wired to the scheduler's cache invalidation so this instance stops
// routing to the host at detection time instead of at cache expiry.
// Blocks until ctx is cancelled.
func StartHostDetector(ctx context.Context, queries *db.Queries, onUnhealthy func()) {
	log.Info().
		Dur("timeout", heartbeatTimeout).
		Dur("interval", detectorInterval).
		Msg("host detector started")

	ticker := time.NewTicker(detectorInterval)
	defer ticker.Stop()

	sentrylog.RunSafe("host-detector", func() { detectOnce(ctx, queries, onUnhealthy) })

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("host detector exiting")
			return
		case <-ticker.C:
			runCtx, cancel := context.WithTimeout(ctx, detectorRunTimeout)
			sentrylog.RunSafe("host-detector", func() { detectOnce(runCtx, queries, onUnhealthy) })
			cancel()
		}
	}
}

func detectOnce(ctx context.Context, queries *db.Queries, onUnhealthy func()) {
	cutoff := time.Now().Add(-heartbeatTimeout)
	stale, err := queries.ListStaleHosts(ctx, pgtype.Timestamptz{
		Time:  cutoff,
		Valid: true,
	})
	if err != nil {
		log.Error().Err(err).Msg("host detector: ListStaleHosts failed")
		return
	}

	marked := 0
	for _, host := range stale {
		log.Warn().Str("host_id", host.ID).
			Time("last_heartbeat", host.LastHeartbeatAt.Time).
			Msg("host detector: marking host unhealthy (heartbeat timeout)")

		if err := queries.MarkHostUnhealthy(ctx, host.ID); err != nil {
			log.Error().Err(err).Str("host_id", host.ID).Msg("host detector: MarkHostUnhealthy failed")
			continue
		}
		marked++
	}
	if marked > 0 && onUnhealthy != nil {
		onUnhealthy()
	}
}
