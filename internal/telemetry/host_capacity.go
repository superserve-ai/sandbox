package telemetry

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

const hostCapacityQuery = `
SELECT
	h.id,
	h.region,
	COALESCE(SUM(s.vcpu_count), 0)::bigint AS used_vcpu,
	COALESCE(SUM(s.memory_mib), 0)::bigint AS used_memory_mib,
	COALESCE(COUNT(s.id), 0)::bigint AS sandboxes
FROM host h
LEFT JOIN sandbox s
  ON s.host_id = h.id
 AND s.destroyed_at IS NULL
 AND s.status IN ('starting', 'active', 'resuming', 'pausing')
WHERE h.status = 'active'
GROUP BY h.id, h.region
ORDER BY h.id
`

const hostCapacityQueryTimeout = 5 * time.Second

// StartHostCapacitySampler records aggregate per-host sandbox resource usage.
// It derives capacity usage from trusted control-plane state rather than from
// sandbox-emitted metrics, and intentionally stays host-scoped.
func StartHostCapacitySampler(ctx context.Context, pool *pgxpool.Pool, recorder Recorder, interval time.Duration) {
	if pool == nil || recorder == nil {
		return
	}
	if interval <= 0 {
		interval = 15 * time.Second
	}

	go func() {
		sample := func() {
			sampleCtx, cancel := context.WithTimeout(ctx, hostCapacityQueryTimeoutForInterval(interval))
			defer cancel()

			rows, err := pool.Query(sampleCtx, hostCapacityQuery)
			if err != nil {
				log.Warn().Err(err).Msg("host capacity telemetry query failed")
				return
			}
			defer rows.Close()

			for rows.Next() {
				var c HostCapacity
				if err := rows.Scan(&c.HostID, &c.Region, &c.UsedVCPU, &c.UsedMemoryMiB, &c.Sandboxes); err != nil {
					log.Warn().Err(err).Msg("host capacity telemetry row scan failed")
					return
				}
				recorder.RecordHostCapacity(sampleCtx, c)
			}
			if err := rows.Err(); err != nil {
				log.Warn().Err(err).Msg("host capacity telemetry rows failed")
			}
		}

		sample()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sample()
			}
		}
	}()
}

func hostCapacityQueryTimeoutForInterval(_ time.Duration) time.Duration {
	return hostCapacityQueryTimeout
}
