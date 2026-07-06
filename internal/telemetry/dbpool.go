package telemetry

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// StartDBPoolSampler periodically records pgxpool stats until ctx is canceled.
// It emits deltas for cumulative pgx counters so OpenTelemetry counters remain
// monotonic without double-counting each sample.
func StartDBPoolSampler(ctx context.Context, pool *pgxpool.Pool, recorder Recorder, interval time.Duration) {
	if pool == nil || recorder == nil {
		return
	}
	if interval <= 0 {
		interval = 15 * time.Second
	}

	go func() {
		var prevAcquire int64
		var prevEmptyAcquire int64
		var prevCanceledAcquire int64
		var prevAcquireDuration time.Duration
		var seeded bool

		sample := func() {
			stat := pool.Stat()
			acquire := stat.AcquireCount()
			emptyAcquire := stat.EmptyAcquireCount()
			canceledAcquire := stat.CanceledAcquireCount()
			acquireDuration := stat.AcquireDuration()
			acquireDelta, emptyAcquireDelta, canceledAcquireDelta, acquireDurationDelta :=
				dbPoolDeltas(seeded, acquire, prevAcquire, emptyAcquire, prevEmptyAcquire, canceledAcquire, prevCanceledAcquire, acquireDuration, prevAcquireDuration)

			recorder.RecordDBPoolStats(ctx, DBPoolStats{
				AcquiredConns:               int64(stat.AcquiredConns()),
				IdleConns:                   int64(stat.IdleConns()),
				TotalConns:                  int64(stat.TotalConns()),
				AcquireDelta:                acquireDelta,
				EmptyAcquireDelta:           emptyAcquireDelta,
				CanceledAcquireDelta:        canceledAcquireDelta,
				AcquireDurationSecondsDelta: acquireDurationDelta.Seconds(),
			})

			prevAcquire = acquire
			prevEmptyAcquire = emptyAcquire
			prevCanceledAcquire = canceledAcquire
			prevAcquireDuration = acquireDuration
			seeded = true
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

func nonNegativeDelta(cur, prev int64) int64 {
	if cur < prev {
		return 0
	}
	return cur - prev
}

func nonNegativeDurationDelta(cur, prev time.Duration) time.Duration {
	if cur < prev {
		return 0
	}
	return cur - prev
}

func dbPoolDeltas(seeded bool, acquire, prevAcquire, emptyAcquire, prevEmptyAcquire, canceledAcquire, prevCanceledAcquire int64, acquireDuration, prevAcquireDuration time.Duration) (int64, int64, int64, time.Duration) {
	if !seeded {
		return 0, 0, 0, 0
	}
	return nonNegativeDelta(acquire, prevAcquire),
		nonNegativeDelta(emptyAcquire, prevEmptyAcquire),
		nonNegativeDelta(canceledAcquire, prevCanceledAcquire),
		nonNegativeDurationDelta(acquireDuration, prevAcquireDuration)
}
