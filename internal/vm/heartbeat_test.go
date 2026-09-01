package vm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
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
			_ = json.NewEncoder(w).Encode(proxyHealthResponse{FilesEnabled: true, ResolverReady: true, Capabilities: []string{
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
		LifecycleReady:    func() bool { return true },
		ResolverReady:     func() bool { return true },
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
		capabilityCanCreate, capabilityCanResume, capabilityCanPause, capabilityCanDestroy,
		capabilityCanProxyTraffic,
		capabilityCanReadFiles, capabilityCanWriteFiles,
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
		want         []string
	}{
		{name: "old proxy empty health", healthStatus: http.StatusOK, want: []string{capabilityCanCreate, capabilityCanResume, capabilityCanPause, capabilityCanDestroy}},
		{name: "proxy unavailable", healthStatus: http.StatusServiceUnavailable, want: []string{capabilityCanCreate, capabilityCanResume, capabilityCanPause, capabilityCanDestroy}},
		{name: "wrong protocol", healthStatus: http.StatusOK, healthBody: `{"capabilities":["other"]}`, want: []string{capabilityCanCreate, capabilityCanResume, capabilityCanPause, capabilityCanDestroy}},
		{name: "access without base", healthStatus: http.StatusOK, healthBody: `{"capabilities":["preview_port_access_v1"]}`, want: []string{capabilityCanCreate, capabilityCanResume, capabilityCanPause, capabilityCanDestroy}},
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

			sendHeartbeat(context.Background(), server.Client(), HeartbeatConfig{HostID: "host-a", LifecycleReady: func() bool { return true }, ResolverReady: func() bool { return true }}, server.URL+"/internal/hosts/host-a/heartbeat", "", server.URL+"/health", nil, zerolog.Nop())
			if !reflect.DeepEqual(got.Capabilities, tt.want) {
				t.Fatalf("capabilities = %#v, want %#v", got.Capabilities, tt.want)
			}
		})
	}
}

func TestSendHeartbeatOmitsLifecycleCapabilitiesBeforeReady(t *testing.T) {
	var got heartbeatRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			_ = json.NewEncoder(w).Encode(proxyHealthResponse{})
			return
		}
		if r.URL.Path == "/heartbeat" {
			_ = json.NewDecoder(r.Body).Decode(&got)
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	sendHeartbeat(context.Background(), server.Client(), HeartbeatConfig{
		HostID: "host-a", LifecycleReady: func() bool { return false },
	}, server.URL+"/heartbeat", "", server.URL+"/health", nil, zerolog.Nop())

	if reflect.DeepEqual(got.Capabilities, []string{capabilityCanCreate, capabilityCanResume, capabilityCanPause, capabilityCanDestroy}) {
		t.Fatalf("lifecycle capabilities = %#v, want omitted before readiness", got.Capabilities)
	}
	for _, capability := range got.Capabilities {
		if capability == capabilityCanCreate || capability == capabilityCanResume || capability == capabilityCanPause || capability == capabilityCanDestroy {
			t.Fatalf("lifecycle capability %q published before readiness", capability)
		}
	}
}

func TestSendHeartbeatKeepsLifecycleCapabilitiesWhenResolverIsNotReady(t *testing.T) {
	var got heartbeatRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			_ = json.NewEncoder(w).Encode(proxyHealthResponse{})
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sendHeartbeat(context.Background(), server.Client(), HeartbeatConfig{
		HostID: "host-a", LifecycleReady: func() bool { return true }, ResolverReady: func() bool { return false },
	}, server.URL+"/heartbeat", "", server.URL+"/health", nil, zerolog.Nop())
	want := []string{capabilityCanCreate, capabilityCanResume, capabilityCanPause, capabilityCanDestroy}
	if !reflect.DeepEqual(got.Capabilities, want) {
		t.Fatalf("capabilities = %#v, want %#v", got.Capabilities, want)
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

	ok, accepted := sendHeartbeat(context.Background(), server.Client(), HeartbeatConfig{HostID: "host-a", LifecycleReady: func() bool { return true }, ResolverReady: func() bool { return true }}, server.URL+"/heartbeat", "", server.URL+"/health", []heartbeatStorageMeasurement{{SandboxID: "sandbox-a", AllocatedBytes: 1}}, zerolog.Nop())
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

// A publishing host must SAY so on its heartbeat. The control plane's
// three-state classification keys on this capability: without it, a host
// that publishes pressure is indistinguishable from a daemon that never
// will, so its reports are never consulted and capacity ranking sees an
// empty fleet.
//
// The consumer-side constant lives in internal/scheduler, which this
// package cannot import — hence the literal, and hence a test on each
// side of the contract.
func TestSendHeartbeatAdvertisesCapacityPressureWhenPublishing(t *testing.T) {
	capabilitiesFor := func(cfg HeartbeatConfig) []string {
		t.Helper()
		var got heartbeatRequest
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/health":
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(proxyHealthResponse{})
			default:
				if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
					t.Errorf("decode heartbeat: %v", err)
				}
				w.WriteHeader(http.StatusOK)
			}
		}))
		defer server.Close()

		cfg.HostID = "host-a"
		sendHeartbeat(context.Background(), server.Client(), cfg,
			server.URL+"/internal/hosts/host-a/heartbeat", "shared", server.URL+"/health", nil, zerolog.Nop())
		return got.Capabilities
	}

	publishing := capabilitiesFor(HeartbeatConfig{
		VMDAddr:  "10.0.0.2:50051",
		Pressure: func() HostPressure { return HostPressure{} },
	})
	if !slices.Contains(publishing, capabilityCapacityPressure) {
		t.Fatalf("capabilities = %v, missing %q; every publishing host would read as legacy",
			publishing, capabilityCapacityPressure)
	}

	// Not publishing: no advertisement, so the control plane keeps
	// treating it as a daemon that does not report.
	silent := capabilitiesFor(HeartbeatConfig{VMDAddr: "10.0.0.2:50051"})
	if slices.Contains(silent, capabilityCapacityPressure) {
		t.Fatalf("capabilities = %v; a host that publishes nothing must not claim to", silent)
	}

	// Configured to publish but with no advertised address: the report
	// has no identity to fence on, so publication never happens and the
	// capability must not be claimed either.
	unaddressed := capabilitiesFor(HeartbeatConfig{Pressure: func() HostPressure { return HostPressure{} }})
	if slices.Contains(unaddressed, capabilityCapacityPressure) {
		t.Fatalf("capabilities = %v; without an advertised address nothing is published", unaddressed)
	}
}
