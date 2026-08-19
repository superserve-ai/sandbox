package api

import (
	"context"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/telemetry"
)

const telemetryHostIDKey = "telemetry_host_id"

// phaseSeriesOwnedKey marks that a handler's deferred phase emission owns
// this request's samples (set by PhaseStart, read by APIKeyAuth's fallback).
const phaseSeriesOwnedKey = "phase_series_owned"

type telemetryRecorderHolder struct {
	recorder telemetry.Recorder
}

var telemetryRecorder atomic.Value

func init() {
	telemetryRecorder.Store(&telemetryRecorderHolder{recorder: telemetry.NewNoopRecorder()})
}

// SetTelemetryRecorder installs the app-level metrics recorder used by the API
// package. Nil resets to the noop recorder so tests and local runs stay safe.
func SetTelemetryRecorder(recorder telemetry.Recorder) {
	if recorder == nil {
		recorder = telemetry.NewNoopRecorder()
	}
	telemetryRecorder.Store(&telemetryRecorderHolder{recorder: recorder})
}

// SandboxIDRegion returns the low-cardinality region label for telemetry. Empty
// means the deployment is still minting legacy untagged sandbox IDs.
func SandboxIDRegion() string {
	return sandboxIDRegionFromEnv()
}

func currentTelemetryRecorder() telemetry.Recorder {
	if holder, ok := telemetryRecorder.Load().(*telemetryRecorderHolder); ok && holder != nil && holder.recorder != nil {
		return holder.recorder
	}
	return telemetry.NewNoopRecorder()
}

// SetTelemetryHostID attaches a bounded host_id label to the current request's
// route-level lifecycle metric. It is best-effort; callers should only pass
// host IDs already loaded from trusted control-plane state.
func SetTelemetryHostID(c *gin.Context, hostID string) {
	if c != nil && hostID != "" {
		c.Set(telemetryHostIDKey, hostID)
	}
}

func telemetryHostID(c *gin.Context) string {
	if c == nil {
		return ""
	}
	v, ok := c.Get(telemetryHostIDKey)
	if !ok {
		return ""
	}
	hostID, _ := v.(string)
	return hostID
}

func sandboxLogger(sandboxID, hostID string) zerolog.Logger {
	return sandboxLoggerFrom(log.Logger, sandboxID, hostID)
}

func sandboxLoggerFrom(base zerolog.Logger, sandboxID, hostID string) zerolog.Logger {
	return base.With().
		Str("sandbox_id", sandboxID).
		Str("host_id", hostID).
		Logger()
}

// PhaseStart returns the auth middleware's start stamp when present, so
// handler phase totals cover a slow auth cache miss (the auth phase must
// never exceed its own request's total). Falls back to now.
func PhaseStart(c *gin.Context) time.Time {
	// Mark the phase series as handler-owned so the auth middleware's
	// abort-path emission stays silent — only one of the two ever emits.
	c.Set(phaseSeriesOwnedKey, true)
	if v, ok := c.Get("auth_start"); ok {
		if t, ok := v.(time.Time); ok {
			return t
		}
	}
	return time.Now()
}

func RecordSandboxTransition(ctx context.Context, operation, result, hostID string, duration time.Duration) {
	currentTelemetryRecorder().RecordSandboxTransition(ctx, telemetry.SandboxTransition{
		Operation: operation,
		Result:    result,
		Region:    SandboxIDRegion(),
		HostID:    hostID,
		Duration:  duration,
	})
}

// RecordLatencyPhases emits one histogram sample per named phase of a
// control-plane operation. Phases with negative durations (clock skew across
// the async insert join) are dropped rather than recorded as zero.
func RecordLatencyPhases(ctx context.Context, op, hostID string, phases map[string]time.Duration) {
	rec := currentTelemetryRecorder()
	for phase, d := range phases {
		if d < 0 {
			continue
		}
		rec.RecordLatencyPhase(ctx, telemetry.LatencyPhase{
			Plane:    "controlplane",
			Op:       op,
			Phase:    phase,
			Region:   SandboxIDRegion(),
			HostID:   hostID,
			Duration: d,
		})
	}
}

// RecordResumeSettleWait records ResumeSandbox waiting through a racing
// finalize-pause write; result is one of the telemetry.SettleResult*
// constants. Callers should only invoke this when the loop actually waited
// (more than one read) — it is meant to run once per affected resume, not
// once per poll iteration.
func RecordResumeSettleWait(ctx context.Context, result, hostID string, waited time.Duration, reads int) {
	currentTelemetryRecorder().RecordSandboxResumeSettleWait(ctx, telemetry.SandboxResumeSettleWait{
		Result:   result,
		Region:   SandboxIDRegion(),
		HostID:   hostID,
		Duration: waited,
		Reads:    int64(reads),
	})
}

// SandboxLifecycleTelemetry records coarse user-visible sandbox lifecycle
// transitions from the routed API surface. It intentionally emits only bounded
// labels; sandbox IDs, team IDs, user IDs, request IDs, URLs, and raw errors are
// never used as metric attributes.
func SandboxLifecycleTelemetry() gin.HandlerFunc {
	return func(c *gin.Context) {
		operation, ok := sandboxLifecycleOperation(c.Request.Method, c.FullPath())
		if !ok {
			c.Next()
			return
		}

		started := time.Now()
		c.Next()

		RecordSandboxTransition(
			c.Request.Context(),
			operation,
			lifecycleResult(c.Writer.Status()),
			telemetryHostID(c),
			time.Since(started),
		)
	}
}

func sandboxLifecycleOperation(method, route string) (string, bool) {
	switch {
	case method == http.MethodPost && route == "/sandboxes":
		return "create", true
	case method == http.MethodPost && route == "/sandboxes/:sandbox_id/pause":
		return "pause", true
	case method == http.MethodPost && route == "/sandboxes/:sandbox_id/resume":
		return "resume", true
	case method == http.MethodDelete && route == "/sandboxes/:sandbox_id":
		return "delete", true
	default:
		return "", false
	}
}

func lifecycleResult(status int) string {
	switch {
	case status >= 200 && status < 400:
		return telemetry.ResultSuccess
	case status == http.StatusConflict:
		return telemetry.ResultConflict
	case status == http.StatusRequestTimeout || status == http.StatusGatewayTimeout:
		return telemetry.ResultTimeout
	default:
		return telemetry.ResultError
	}
}
