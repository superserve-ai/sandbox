package vm

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/preview"
)

func TestSendHeartbeatLogsAdvertisedCapabilitiesWithoutToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(proxyHealthResponse{Capabilities: []string{
				preview.HostCapabilityPorts,
				preview.HostCapabilityPortAccess,
			}})
		case "/internal/hosts/host-a/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.InfoLevel).With().Str("host_id", "host-a").Logger()
	sendHeartbeat(
		context.Background(),
		server.Client(),
		server.URL+"/internal/hosts/host-a/heartbeat",
		"super-secret-token",
		server.URL+"/health",
		logger,
	)

	got := logs.String()
	for _, want := range []string{
		`"message":"heartbeat sent"`,
		`"host_id":"host-a"`,
		`"capabilities":["preview_ports_v1","preview_port_access_v1"]`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("heartbeat log missing %s: %s", want, got)
		}
	}
	if strings.Contains(got, "super-secret-token") {
		t.Fatalf("heartbeat log leaked bearer token: %s", got)
	}
}
