package telemetry

import (
	"context"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/superserve-ai/sandbox/internal/abuse"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// NewAbusePolicyReporter emits background-only aggregate health. Consecutive
// failures are coalesced, with a periodic reminder and an explicit recovery.
func NewAbusePolicyReporter(ctx context.Context, log zerolog.Logger, recorder Recorder) func(string, abuse.CacheStats) {
	var mu sync.Mutex
	var previous string
	var lastLog time.Time
	return func(result string, stats abuse.CacheStats) {
		mu.Lock()
		defer mu.Unlock()
		if r, ok := recorder.(*OTelRecorder); ok {
			r.recordAbusePolicy(ctx, result, stats)
		}
		// Expiration accompanies sync_error and must not alternate the health state.
		if result == "expired" {
			return
		}
		now := time.Now()
		if result == "success" {
			if previous != "" && previous != "success" {
				log.Info().Msg("authoritative abuse policy synchronization recovered")
			}
		} else if result != previous || now.Sub(lastLog) >= time.Minute {
			log.Warn().Str("result", result).Bool("ready", stats.Ready).
				Int("deny_entries", stats.DenyEntries).Int("capacity", stats.DenyCapacity).
				Int("rejected", stats.CapacityRejected).Time("last_success", stats.LastSuccess).
				Msg("authoritative abuse policy synchronization degraded")
			lastLog = now
		}
		previous = result
	}
}

func (r *OTelRecorder) recordAbusePolicy(ctx context.Context, result string, s abuse.CacheStats) {
	result = computeLabel(result, "success", "sync_error", "capacity_rejected", "expired")
	r.abusePolicyEvents.Add(ctx, 1, metric.WithAttributes(attribute.String("result", result)))
	ready := int64(0)
	if s.Ready {
		ready = 1
	}
	age := int64(-1)
	if !s.LastSuccess.IsZero() {
		age = max(0, int64(time.Since(s.LastSuccess).Seconds()))
	}
	for name, value := range map[string]int64{
		"ready": ready, "deny_entries": int64(s.DenyEntries), "deny_capacity": int64(s.DenyCapacity),
		"trusted_teams": int64(s.TrustedTeams), "last_success_age_seconds": age,
		"capacity_rejected": int64(s.CapacityRejected), "expired": int64(s.Expired),
	} {
		r.abusePolicyState.Record(ctx, value, metric.WithAttributes(attribute.String("state", name)))
	}
}
