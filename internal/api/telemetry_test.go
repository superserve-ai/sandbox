package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/telemetry"
)

type captureTelemetryRecorder struct {
	transitions []telemetry.SandboxTransition
}

func (r *captureTelemetryRecorder) RecordSandboxTransition(_ context.Context, t telemetry.SandboxTransition) {
	r.transitions = append(r.transitions, t)
}

func (r *captureTelemetryRecorder) RecordSandboxResumeSettleWait(context.Context, telemetry.SandboxResumeSettleWait) {
}
func (r *captureTelemetryRecorder) RecordVMDCall(context.Context, telemetry.VMDCall)           {}
func (r *captureTelemetryRecorder) RecordLatencyPhase(context.Context, telemetry.LatencyPhase) {}
func (r *captureTelemetryRecorder) RecordHostCapacity(context.Context, telemetry.HostCapacity) {
}
func (r *captureTelemetryRecorder) RecordDBPoolStats(context.Context, telemetry.DBPoolStats) {}
func (r *captureTelemetryRecorder) RecordPausedNetworkPressure(context.Context, telemetry.PausedNetworkPressure) {
}
func (r *captureTelemetryRecorder) RecordLauncherState(context.Context, telemetry.LauncherState) {}

func TestSandboxLifecycleTelemetryUsesHostID(t *testing.T) {
	rec := &captureTelemetryRecorder{}
	SetTelemetryRecorder(rec)
	t.Cleanup(func() {
		SetTelemetryRecorder(nil)
	})

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(SandboxLifecycleTelemetry())
	r.POST("/sandboxes", func(c *gin.Context) {
		SetTelemetryHostID(c, "host-123")
		c.Status(http.StatusCreated)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sandboxes", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusCreated)
	}
	if len(rec.transitions) != 1 {
		t.Fatalf("recorded %d lifecycle transitions, want 1", len(rec.transitions))
	}
	got := rec.transitions[0]
	if got.Operation != "create" {
		t.Fatalf("operation = %q, want create", got.Operation)
	}
	if got.Result != telemetry.ResultSuccess {
		t.Fatalf("result = %q, want %q", got.Result, telemetry.ResultSuccess)
	}
	if got.HostID != "host-123" {
		t.Fatalf("host_id = %q, want host-123", got.HostID)
	}
	if got.Region != SandboxIDRegion() {
		t.Fatalf("region = %q, want %q", got.Region, SandboxIDRegion())
	}
	if got.Duration <= 0 {
		t.Fatalf("duration = %s, want positive", got.Duration)
	}
}

func TestSandboxLifecycleTelemetryUsesHostIDForPauseResumeDelete(t *testing.T) {
	cases := []struct {
		name      string
		method    string
		route     string
		path      string
		hostID    string
		status    int
		operation string
	}{
		{
			name:      "pause",
			method:    http.MethodPost,
			route:     "/sandboxes/:sandbox_id/pause",
			path:      "/sandboxes/sb-123/pause",
			hostID:    "host-pause",
			status:    http.StatusNoContent,
			operation: "pause",
		},
		{
			name:      "resume",
			method:    http.MethodPost,
			route:     "/sandboxes/:sandbox_id/resume",
			path:      "/sandboxes/sb-123/resume",
			hostID:    "host-resume",
			status:    http.StatusOK,
			operation: "resume",
		},
		{
			name:      "delete",
			method:    http.MethodDelete,
			route:     "/sandboxes/:sandbox_id",
			path:      "/sandboxes/sb-123",
			hostID:    "host-delete",
			status:    http.StatusNoContent,
			operation: "delete",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &captureTelemetryRecorder{}
			SetTelemetryRecorder(rec)
			t.Cleanup(func() {
				SetTelemetryRecorder(nil)
			})

			gin.SetMode(gin.TestMode)
			r := gin.New()
			r.Use(SandboxLifecycleTelemetry())
			r.POST("/sandboxes/:sandbox_id/pause", func(c *gin.Context) {
				SetTelemetryHostID(c, "host-pause")
				c.Status(http.StatusNoContent)
			})
			r.POST("/sandboxes/:sandbox_id/resume", func(c *gin.Context) {
				SetTelemetryHostID(c, "host-resume")
				c.Status(http.StatusOK)
			})
			r.DELETE("/sandboxes/:sandbox_id", func(c *gin.Context) {
				SetTelemetryHostID(c, "host-delete")
				c.Status(http.StatusNoContent)
			})

			w := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, tc.path, nil)
			r.ServeHTTP(w, req)

			if w.Code != tc.status {
				t.Fatalf("status = %d, want %d", w.Code, tc.status)
			}
			if len(rec.transitions) != 1 {
				t.Fatalf("recorded %d lifecycle transitions, want 1", len(rec.transitions))
			}
			got := rec.transitions[0]
			if got.Operation != tc.operation {
				t.Fatalf("operation = %q, want %q", got.Operation, tc.operation)
			}
			if got.Result != telemetry.ResultSuccess {
				t.Fatalf("result = %q, want %q", got.Result, telemetry.ResultSuccess)
			}
			if got.HostID != tc.hostID {
				t.Fatalf("host_id = %q, want %q", got.HostID, tc.hostID)
			}
			if got.Region != SandboxIDRegion() {
				t.Fatalf("region = %q, want %q", got.Region, SandboxIDRegion())
			}
			if got.Duration <= 0 {
				t.Fatalf("duration = %s, want positive", got.Duration)
			}
		})
	}
}

func TestLifecycleResultBucketsTimeoutsAndConflicts(t *testing.T) {
	cases := map[int]string{
		http.StatusOK:                  telemetry.ResultSuccess,
		http.StatusCreated:             telemetry.ResultSuccess,
		http.StatusConflict:            telemetry.ResultConflict,
		http.StatusRequestTimeout:      telemetry.ResultTimeout,
		http.StatusGatewayTimeout:      telemetry.ResultTimeout,
		http.StatusInternalServerError: telemetry.ResultError,
	}
	for status, want := range cases {
		if got := lifecycleResult(status); got != want {
			t.Fatalf("lifecycleResult(%d) = %q, want %q", status, got, want)
		}
	}
}

func TestSandboxLifecycleOperationMatchesContractRoutes(t *testing.T) {
	cases := []struct {
		method string
		route  string
		want   string
	}{
		{http.MethodPost, "/sandboxes", "create"},
		{http.MethodPost, "/sandboxes/:sandbox_id/pause", "pause"},
		{http.MethodPost, "/sandboxes/:sandbox_id/resume", "resume"},
		{http.MethodDelete, "/sandboxes/:sandbox_id", "delete"},
	}
	for _, tc := range cases {
		got, ok := sandboxLifecycleOperation(tc.method, tc.route)
		if !ok {
			t.Fatalf("%s %s did not match a lifecycle route", tc.method, tc.route)
		}
		if got != tc.want {
			t.Fatalf("%s %s = %q, want %q", tc.method, tc.route, got, tc.want)
		}
	}
}

func TestSandboxLoggerIncludesSandboxAndHostID(t *testing.T) {
	var buf bytes.Buffer

	l := sandboxLoggerFrom(zerolog.New(&buf), "sandbox-123", "host-123")
	l.Error().Msg("boom")

	out := buf.String()
	for _, want := range []string{`"sandbox_id":"sandbox-123"`, `"host_id":"host-123"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("log output %q missing %q", out, want)
		}
	}
}

var _ telemetry.Recorder = (*captureTelemetryRecorder)(nil)
