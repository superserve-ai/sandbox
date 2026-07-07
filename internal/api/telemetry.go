package api

import (
	"context"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/superserve-ai/sandbox/internal/telemetry"
)

const telemetryHostIDKey = "telemetry_host_id"

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

func RecordSandboxTransition(ctx context.Context, operation, result, hostID string, duration time.Duration) {
	currentTelemetryRecorder().RecordSandboxTransition(ctx, telemetry.SandboxTransition{
		Operation: operation,
		Result:    result,
		Region:    SandboxIDRegion(),
		HostID:    hostID,
		Duration:  duration,
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
