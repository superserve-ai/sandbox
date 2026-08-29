package api

import (
	"context"
	"time"

	"github.com/superserve-ai/sandbox/internal/telemetry"
)

// StartAbuseEnforcementTelemetry exports cache pressure asynchronously.
func StartAbuseEnforcementTelemetry(ctx context.Context, cache *abuseEnforcementCache, interval time.Duration) {
	if cache == nil || interval <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s := cache.Stats()
				level := ""
				if s.AdmissionRejections > 0 || s.CapacityEvictions > 0 || s.Utilization >= .9 {
					level = "critical"
				} else if s.Utilization >= .7 {
					level = "high"
				}
				currentTelemetryRecorder().RecordAbuseEnforcementStats(ctx, telemetry.AbuseEnforcementStats{
					DenyEntries: int64(s.DenyEntries), DenyCapacity: int64(s.DenyCapacity), TrustedTeams: int64(s.TrustedTeams),
					Utilization: s.Utilization, TTLEvictions: s.TTLEvictions, CapacityEvictions: s.CapacityEvictions, AdmissionRejections: s.AdmissionRejections, AlertLevel: level,
				})
			}
		}
	}()
}

func (h *Handlers) StartAbuseEnforcementTelemetry(ctx context.Context, interval time.Duration) {
	if h != nil {
		StartAbuseEnforcementTelemetry(ctx, &h.abuseEnforcement, interval)
	}
}
