package vm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/preview"
)

func TestSendHeartbeatAdvertisesVerifiedPreviewCapabilities(t *testing.T) {
	var got heartbeatRequest
	var gotPath, gotAuthorization string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(proxyHealthResponse{Capabilities: []string{
				preview.HostCapabilityPorts, preview.HostCapabilityPortAccess, preview.HostCapabilityPortTokens,
			}})
		case "/internal/hosts/host-a/heartbeat":
			gotPath = r.URL.Path
			gotAuthorization = r.Header.Get("Authorization")
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
				t.Errorf("decode heartbeat: %v", err)
			}
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	sendHeartbeat(context.Background(), server.Client(), server.URL+"/internal/hosts/host-a/heartbeat", "shared", server.URL+"/health", zerolog.Nop())

	if gotPath != "/internal/hosts/host-a/heartbeat" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotAuthorization != "Bearer shared" {
		t.Fatalf("authorization = %q", gotAuthorization)
	}
	want := []string{preview.HostCapabilityPorts, preview.HostCapabilityPortAccess, preview.HostCapabilityPortTokens}
	if !reflect.DeepEqual(got.Capabilities, want) {
		t.Fatalf("capabilities = %#v, want %#v", got.Capabilities, want)
	}
}

func TestProxyPreviewCapabilitiesRequiresAccessBeforeTokens(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(proxyHealthResponse{Capabilities: []string{
			preview.HostCapabilityPorts, preview.HostCapabilityPortTokens,
		}})
	}))
	defer server.Close()

	got, err := proxyPreviewCapabilities(context.Background(), server.Client(), server.URL)
	if err != nil {
		t.Fatalf("proxyPreviewCapabilities: %v", err)
	}
	want := []string{preview.HostCapabilityPorts}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("capabilities = %#v, want %#v", got, want)
	}
}

func TestProxyPreviewCapabilitiesPreservesPhaseOneOnlyAttestation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(proxyHealthResponse{
			Capabilities: []string{preview.HostCapabilityPorts},
		})
	}))
	defer server.Close()

	got, err := proxyPreviewCapabilities(context.Background(), server.Client(), server.URL)
	if err != nil {
		t.Fatalf("proxyPreviewCapabilities: %v", err)
	}
	want := []string{preview.HostCapabilityPorts}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("capabilities = %#v, want %#v", got, want)
	}
}

func TestSendHeartbeatOmitsCapabilityForOldOrUnavailableProxy(t *testing.T) {
	tests := []struct {
		name         string
		healthStatus int
		healthBody   string
	}{
		{name: "old proxy empty health", healthStatus: http.StatusOK},
		{name: "proxy unavailable", healthStatus: http.StatusServiceUnavailable},
		{name: "wrong protocol", healthStatus: http.StatusOK, healthBody: `{"capabilities":["other"]}`},
		{name: "access without base", healthStatus: http.StatusOK, healthBody: `{"capabilities":["preview_port_access_v1"]}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got heartbeatRequest
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/health":
					w.WriteHeader(tt.healthStatus)
					_, _ = w.Write([]byte(tt.healthBody))
				case "/internal/hosts/host-a/heartbeat":
					if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
						t.Errorf("decode heartbeat: %v", err)
					}
					w.WriteHeader(http.StatusOK)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			sendHeartbeat(context.Background(), server.Client(), server.URL+"/internal/hosts/host-a/heartbeat", "", server.URL+"/health", zerolog.Nop())
			if len(got.Capabilities) != 0 {
				t.Fatalf("capabilities = %#v, want empty", got.Capabilities)
			}
		})
	}
}
