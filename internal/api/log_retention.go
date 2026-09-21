package api

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/sentrylog"
)

// StartLogRetention keeps net_flow and proxy_audit inside their retention
// window: hourly, the day partitions ahead are created and the days past
// the window dropped. Every replica runs it; the database serializes them.
func (h *Handlers) StartLogRetention(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			sentrylog.RunSafe("log-retention", func() {
				qctx, cancel := context.WithTimeout(ctx, time.Minute)
				defer cancel()
				if err := h.DB.MaintainLogPartitions(qctx); err != nil {
					log.Warn().Err(err).Msg("log retention: partition maintenance failed")
				}
			})
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}
