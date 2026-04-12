package api

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
)

const (
	// heartbeatTimeout is how long a host can go without heartbeating
	// before it's marked unhealthy. Matches the design doc's "2 minutes".
	heartbeatTimeout = 2 * time.Minute

	// detectorInterval is how often we check for stale hosts.
	detectorInterval = 30 * time.Second
)

// StartHostDetector launches a background goroutine that periodically
// marks active hosts as unhealthy when their heartbeat goes stale.
// Blocks until ctx is cancelled.
func StartHostDetector(ctx context.Context, queries *db.Queries) {
	log.Info().
		Dur("timeout", heartbeatTimeout).
		Dur("interval", detectorInterval).
		Msg("host detector started")

	ticker := time.NewTicker(detectorInterval)
	defer ticker.Stop()

	detectOnce(ctx, queries)

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("host detector exiting")
			return
		case <-ticker.C:
			detectOnce(ctx, queries)
		}
	}
}

func detectOnce(ctx context.Context, queries *db.Queries) {
	cutoff := time.Now().Add(-heartbeatTimeout)
	stale, err := queries.ListStaleHosts(ctx, pgtype.Timestamptz{
		Time:  cutoff,
		Valid: true,
	})
	if err != nil {
		log.Error().Err(err).Msg("host detector: ListStaleHosts failed")
		return
	}

	for _, host := range stale {
		log.Warn().Str("host_id", host.ID).
			Time("last_heartbeat", host.LastHeartbeatAt.Time).
			Msg("host detector: marking host unhealthy (heartbeat timeout)")

		if err := queries.MarkHostUnhealthy(ctx, host.ID); err != nil {
			log.Error().Err(err).Str("host_id", host.ID).Msg("host detector: MarkHostUnhealthy failed")
		}
	}
}
