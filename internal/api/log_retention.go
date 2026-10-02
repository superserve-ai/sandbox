package api

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/sentrylog"
)

const logRetentionDays = 7

var logRetentionTables = []string{"net_flow", "proxy_audit"}

// StartLogRetention keeps the log tables inside their retention window:
// hourly, the day partitions ahead are created and the days past the window
// dropped. Every replica runs it; the database serializes them.
func (h *Handlers) StartLogRetention(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			sentrylog.RunSafe("log-retention", func() {
				for _, table := range logRetentionTables {
					qctx, cancel := context.WithTimeout(ctx, time.Minute)
					err := h.DB.MaintainLogPartitions(qctx, db.MaintainLogPartitionsParams{Parent: table, KeepDays: logRetentionDays})
					cancel()
					if err != nil {
						log.Warn().Err(err).Str("table", table).Msg("log retention: partition maintenance failed")
					}
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
