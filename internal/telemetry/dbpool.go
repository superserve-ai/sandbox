package telemetry

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
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

// saturationStreakThreshold is how many consecutive zero-idle samples must
// accumulate before an evidenced episode is logged. One or two are normal
// under burst; a sustained streak means the pool cannot serve demand,
// whether because every connection is held (possibly by a caller that never
// releases, which lifecycle settings cannot recover) or because replacement
// connections are failing to establish and the pool is running below its
// cap.
const saturationStreakThreshold = 4

// saturationDetector decides when a saturation episode is worth logging.
// Pool statistics cannot prove a blocked acquirer from utilization alone: a
// pool with zero idle connections may be serving legitimate long-running
// work with nobody queued, while a genuinely blocked acquirer advances no
// counter until it completes or cancels. The detector resolves that
// ambiguity with memory: zero-idle samples hold the episode open (and count
// toward the threshold), cancellation evidence at ANY point in the episode
// arms it, and it fires only when armed. Legit full utilization never arms;
// a real wedge always does, because every caller here carries a deadline and
// its cancellation is evidence. Fires once per episode; a sample with idle
// connections ends the episode and re-arms. Pure state machine so the
// decision is testable without a live pool.
type saturationDetector struct {
	streak   int
	evidence bool
	fired    bool
}

// observe records one sample: zeroIdle is whether the pool had no idle
// connections at the sample instant; waited is whether any acquirer waited
// or canceled since the previous sample. Reports whether to log now.
func (d *saturationDetector) observe(zeroIdle, waited bool) bool {
	if !zeroIdle {
		d.streak = 0
		d.evidence = false
		d.fired = false
		return false
	}
	d.streak++
	if waited {
		d.evidence = true
	}
	if d.streak >= saturationStreakThreshold && d.evidence && !d.fired {
		d.fired = true
		return true
	}
	return false
}

// StartDBPoolSaturationLog watches pool health until ctx is canceled and logs
// at error level when the pool has had zero idle connections for
// saturationStreakThreshold consecutive samples with a canceled acquire
// somewhere in the episode (see saturationDetector for why both are
// required). Cancellation is deliberately the only evidence: a caller
// abandoning its wait at zero idle is unambiguous distress, where
// EmptyAcquireCount also counts routine connection construction during
// scale-up and would page on a cold burst doing legitimate work. Two
// boundaries are accepted and deliberate: a caller with no deadline blocked
// forever produces no cancel (every caller here carries one), and a fully
// unreachable database fails dials with errors counted by neither counter,
// but that mode is already loud in per-request error logs. This log exists
// for the quiet wedge: requests queuing then timing out while the database
// looks healthy. Unlike StartDBPoolSampler it is not gated on metrics
// export.
func StartDBPoolSaturationLog(ctx context.Context, pool *pgxpool.Pool, log zerolog.Logger, interval time.Duration) {
	if pool == nil {
		return
	}
	if interval <= 0 {
		interval = 15 * time.Second
	}

	go func() {
		var det saturationDetector
		// Seed so waits accumulated before this watcher started (startup
		// churn) do not count toward the first sample's deltas.
		seed := pool.Stat()
		prevEmptyAcquire := seed.EmptyAcquireCount()
		prevCanceledAcquire := seed.CanceledAcquireCount()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				stat := pool.Stat()
				emptyAcquire := stat.EmptyAcquireCount()
				canceledAcquire := stat.CanceledAcquireCount()
				emptyDelta := emptyAcquire - prevEmptyAcquire
				canceledDelta := canceledAcquire - prevCanceledAcquire
				prevEmptyAcquire = emptyAcquire
				prevCanceledAcquire = canceledAcquire
				if det.observe(stat.IdleConns() == 0, canceledDelta > 0) {
					log.Error().
						Int64("empty_acquire_delta", emptyDelta).
						Int64("canceled_acquire_delta", canceledDelta).
						Int32("acquired_conns", stat.AcquiredConns()).
						Int32("idle_conns", stat.IdleConns()).
						Int32("total_conns", stat.TotalConns()).
						Int32("max_conns", stat.MaxConns()).
						Dur("sample_interval", interval).
						Int("consecutive_samples", saturationStreakThreshold).
						Msg("db pool acquire waits sustained; pool exhausted or connections failing to establish")
				}
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
