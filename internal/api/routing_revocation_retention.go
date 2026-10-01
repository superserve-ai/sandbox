package api

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
)

func StartRoutingRevocationRetention(ctx context.Context, queries *db.Queries) {
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for ctx.Err() == nil {
			qctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := queries.PruneRoutingRevocations(qctx, time.Now())
			cancel()
			if err != nil {
				log.Warn().Err(err).Msg("routing revocation retention failed")
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}
