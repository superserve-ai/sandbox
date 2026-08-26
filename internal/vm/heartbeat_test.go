package vm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
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
				preview.HostCapabilityPorts, preview.HostCapabilityPortAccess,
				preview.HostCapabilityPortTokens, preview.HostCapabilityPortBrowserAuth,
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

	sendHeartbeat(context.Background(), server.Client(), HeartbeatConfig{
		HostID:            "host-a",
		VMDAddr:           "10.0.0.2:50051",
		ProxyAddr:         "10.0.0.2:5007",
		Region:            "region-a",
		CapacityMemoryMib: 1024,
		CapacityVcpus:     8,
	}, server.URL+"/internal/hosts/host-a/heartbeat", "shared", server.URL+"/health", nil, zerolog.Nop())

	if gotPath != "/internal/hosts/host-a/heartbeat" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotAuthorization != "Bearer shared" {
		t.Fatalf("authorization = %q", gotAuthorization)
	}
	want := []string{
		preview.HostCapabilityPorts, preview.HostCapabilityPortAccess,
		preview.HostCapabilityPortTokens, preview.HostCapabilityPortBrowserAuth,
	}
	if !reflect.DeepEqual(got.Capabilities, want) {
		t.Fatalf("capabilities = %#v, want %#v", got.Capabilities, want)
	}
	if got.VMDAddr != "10.0.0.2:50051" || got.ProxyAddr != "10.0.0.2:5007" || got.Region != "region-a" {
		t.Fatalf("heartbeat description = %#v", got)
	}
	if got.CapacityMemoryMib != 1024 || got.CapacityVcpus != 8 {
		t.Fatalf("capacity = %#v", got)
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

func TestProxyPreviewCapabilitiesRequiresCompleteBrowserDependencyChain(t *testing.T) {
	tests := []struct {
		name       string
		advertised []string
		want       []string
	}{
		{
			name: "complete chain in arbitrary order",
			advertised: []string{
				preview.HostCapabilityPortBrowserAuth, preview.HostCapabilityPortTokens,
				preview.HostCapabilityPorts, preview.HostCapabilityPortAccess,
			},
			want: []string{
				preview.HostCapabilityPorts, preview.HostCapabilityPortAccess,
				preview.HostCapabilityPortTokens, preview.HostCapabilityPortBrowserAuth,
			},
		},
		{
			name: "browser without token enforcement",
			advertised: []string{
				preview.HostCapabilityPorts, preview.HostCapabilityPortAccess,
				preview.HostCapabilityPortBrowserAuth,
			},
			want: []string{preview.HostCapabilityPorts, preview.HostCapabilityPortAccess},
		},
		{
			name: "browser and tokens without access",
			advertised: []string{
				preview.HostCapabilityPorts, preview.HostCapabilityPortTokens,
				preview.HostCapabilityPortBrowserAuth,
			},
			want: []string{preview.HostCapabilityPorts},
		},
		{
			name: "browser chain without publication",
			advertised: []string{
				preview.HostCapabilityPortAccess, preview.HostCapabilityPortTokens,
				preview.HostCapabilityPortBrowserAuth,
			},
		},
		{
			name:       "browser alone",
			advertised: []string{preview.HostCapabilityPortBrowserAuth},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(proxyHealthResponse{Capabilities: tt.advertised})
			}))
			defer server.Close()

			got, err := proxyPreviewCapabilities(context.Background(), server.Client(), server.URL)
			if err != nil {
				t.Fatalf("proxyPreviewCapabilities: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("capabilities = %#v, want %#v", got, tt.want)
			}
		})
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

			sendHeartbeat(context.Background(), server.Client(), HeartbeatConfig{HostID: "host-a"}, server.URL+"/internal/hosts/host-a/heartbeat", "", server.URL+"/health", nil, zerolog.Nop())
			if len(got.Capabilities) != 0 {
				t.Fatalf("capabilities = %#v, want empty", got.Capabilities)
			}
		})
	}
}

func TestMeasureOverlayStorageUsesAllocatedBlocks(t *testing.T) {
	runDir := t.TempDir()
	sandboxID := uuid.NewString()
	if err := os.Mkdir(filepath.Join(runDir, sandboxID), 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(runDir, sandboxID, "overlay.ext4")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(64 << 20); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte{1}, 0); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	got, err := measureOverlayStorage(runDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].SandboxID != sandboxID {
		t.Fatalf("measurements = %#v", got)
	}
	if got[0].AllocatedBytes >= 64<<20 || got[0].AllocatedBytes == 0 {
		t.Fatalf("allocated bytes = %d, want nonzero and less than logical length", got[0].AllocatedBytes)
	}
}

func TestMeasureOverlayStorageSkipsMissingOverlay(t *testing.T) {
	runDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(runDir, uuid.NewString()), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := measureOverlayStorage(runDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("measurements = %#v, want empty", got)
	}
}

func TestMeasureOverlayStorageUsesLegacyRootfs(t *testing.T) {
	runDir := t.TempDir()
	sandboxID := uuid.NewString()
	if err := os.Mkdir(filepath.Join(runDir, sandboxID), 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(runDir, sandboxID, "rootfs.ext4")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(64 << 20); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte{1}, 0); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	got, err := measureOverlayStorage(runDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].SandboxID != sandboxID {
		t.Fatalf("measurements = %#v", got)
	}
	if got[0].AllocatedBytes >= 64<<20 || got[0].AllocatedBytes == 0 {
		t.Fatalf("allocated bytes = %d, want nonzero and less than logical length", got[0].AllocatedBytes)
	}
}

func TestSendHeartbeatOmitsStorageWhenNil(t *testing.T) {
	var got heartbeatRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			_ = json.NewEncoder(w).Encode(proxyHealthResponse{})
		case "/heartbeat":
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
				t.Errorf("decode heartbeat: %v", err)
			}
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	sendHeartbeat(context.Background(), server.Client(), HeartbeatConfig{HostID: "host-a"}, server.URL+"/heartbeat", "", server.URL+"/health", nil, zerolog.Nop())
	if got.Storage != nil {
		t.Fatalf("storage = %#v, want omitted", got.Storage)
	}
}

func TestSendHeartbeatRetriesWithoutStorageOnCompatibilityError(t *testing.T) {
	var got []heartbeatRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			_ = json.NewEncoder(w).Encode(proxyHealthResponse{})
		case "/heartbeat":
			var req heartbeatRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode heartbeat: %v", err)
			}
			got = append(got, req)
			if len(got) == 1 {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":{"message":"json: unknown field \"storage\""}}`))
				return
			}
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	ok, accepted := sendHeartbeat(context.Background(), server.Client(), HeartbeatConfig{HostID: "host-a"}, server.URL+"/heartbeat", "", server.URL+"/health", []heartbeatStorageMeasurement{{SandboxID: "sandbox-a", AllocatedBytes: 1}}, zerolog.Nop())
	if !ok {
		t.Fatal("heartbeat should succeed after retrying without storage")
	}
	if accepted {
		t.Fatal("storage should not be marked accepted when the control plane rejected it")
	}
	if len(got) != 2 {
		t.Fatalf("requests = %d, want 2", len(got))
	}
	if len(got[0].Storage) == 0 {
		t.Fatal("first request should carry storage")
	}
	if got[1].Storage != nil {
		t.Fatalf("second request storage = %#v, want omitted", got[1].Storage)
	}
}

func TestHeartbeatStorageCacheRetriesUnchangedSamplesAfterInterval(t *testing.T) {
	cache := &heartbeatStorageCache{}
	cache.store([]heartbeatStorageMeasurement{{SandboxID: "host-a", AllocatedBytes: 1}})
	version, _ := cache.snapshot()
	now := time.Now()

	if !cache.shouldSend(version, now) {
		t.Fatal("fresh measurements must be sent")
	}
	cache.markSent(version, now)

	if cache.shouldSend(version, now.Add(overlayStorageSampleInterval-time.Second)) {
		t.Fatal("unchanged measurements should stay suppressed until the retry interval")
	}
	if !cache.shouldSend(version, now.Add(overlayStorageSampleInterval)) {
		t.Fatal("unchanged measurements must be retried after the retry interval")
	}
}
