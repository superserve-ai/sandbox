package vm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
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

	reportID := uuid.NewString()
	ok, accepted := sendHeartbeat(context.Background(), server.Client(), HeartbeatConfig{HostID: "host-a", StorageReportID: reportID, LifecycleReady: func() bool { return true }, ResolverReady: func() bool { return true }}, server.URL+"/heartbeat", "", server.URL+"/health", []heartbeatStorageMeasurement{{SandboxID: "sandbox-a", AllocatedBytes: 1}}, zerolog.Nop())
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
	if got[1].StorageReportID != "" {
		t.Fatalf("second request storage report ID = %q, want omitted", got[1].StorageReportID)
	}
}

func TestSendHeartbeatCompatibilityRetryOmitsStorageReportID(t *testing.T) {
	var got []heartbeatRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req heartbeatRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode heartbeat: %v", err)
		}
		got = append(got, req)
		if len(got) == 1 {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":{"message":"json: unknown field \"storage_report_id\""}}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := HeartbeatConfig{HostID: "host-a", StorageReportID: uuid.NewString()}
	storage := []heartbeatStorageMeasurement{{SandboxID: "sandbox-a", AllocatedBytes: 1}}
	ok, accepted := postHeartbeat(context.Background(), server.Client(), cfg, server.URL+"/heartbeat", "", nil, storage, zerolog.Nop(), time.Now())
	if !ok {
		t.Fatal("heartbeat should succeed after retrying without storage")
	}
	if accepted {
		t.Fatal("storage should not be marked accepted when the control plane rejected it")
	}
	if len(got) != 2 {
		t.Fatalf("requests = %d, want 2", len(got))
	}
	if got[0].StorageReportID != cfg.StorageReportID || len(got[0].Storage) == 0 {
		t.Fatalf("first request = %#v, want report ID and storage", got[0])
	}
	if got[1].StorageReportID != "" || got[1].Storage != nil {
		t.Fatalf("compatibility retry = %#v, want no report ID or storage", got[1])
	}
}

func TestPostStorageReportReusesReportIDAfterPublishFailure(t *testing.T) {
	var got []storageReportWire
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req storageReportWire
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode storage report: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		got = append(got, req)
		if len(got) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	cfg := HeartbeatConfig{HostID: "host-a", IncarnationID: "11111111-1111-4111-8111-111111111111"}
	reportID := uuid.New()
	measurements := []heartbeatStorageMeasurement{{SandboxID: "sandbox-a", AllocatedBytes: 8 * 1024 * 1024}}
	if postStorageReport(context.Background(), server.Client(), cfg, server.URL, "shared", reportID, measurements, zerolog.Nop()) {
		t.Fatal("first storage report publish unexpectedly succeeded")
	}
	if !postStorageReport(context.Background(), server.Client(), cfg, server.URL, "shared", reportID, measurements, zerolog.Nop()) {
		t.Fatal("second storage report publish failed")
	}
	if len(got) != 2 {
		t.Fatalf("publish attempts = %d, want 2", len(got))
	}
	if got[0].ReportID != reportID.String() || got[1].ReportID != reportID.String() {
		t.Fatalf("report IDs = [%q %q], want stable ID %q", got[0].ReportID, got[1].ReportID, reportID)
	}
	if got[0].IncarnationID != cfg.IncarnationID || !reflect.DeepEqual(got[0].Measurements, measurements) {
		t.Fatalf("first report = %#v, want incarnation and measurements preserved", got[0])
	}
	if !reflect.DeepEqual(got[1], got[0]) {
		t.Fatalf("retry report = %#v, want identical payload %#v", got[1], got[0])
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

func TestHeartbeatStorageRefreshAllocatesDurableIdentityAfterAcknowledgement(t *testing.T) {
	for _, incarnationID := range []string{"", uuid.NewString()} {
		t.Run(fmt.Sprintf("legacy=%t", incarnationID == ""), func(t *testing.T) {
			runDir := t.TempDir()
			cache := newHeartbeatStorageCache(runDir, zerolog.Nop(), incarnationID)
			if err := cache.store([]heartbeatStorageMeasurement{{SandboxID: "sandbox-a", AllocatedBytes: 1}}); err != nil {
				t.Fatal(err)
			}
			first := cache.pendingSnapshot()[0]
			now := time.Now()
			if err := cache.markSent(first.version, now); err != nil {
				t.Fatal(err)
			}
			if err := cache.queueForPublish(first.version, first.measurements, now.Add(overlayStorageSampleInterval-time.Nanosecond)); err != nil {
				t.Fatal(err)
			}
			if len(cache.pendingSnapshot()) != 0 {
				t.Fatal("unchanged report refreshed before the five-minute boundary")
			}
			if err := cache.queueForPublish(first.version, first.measurements, now.Add(overlayStorageSampleInterval)); err != nil {
				t.Fatal(err)
			}
			pending := cache.pendingSnapshot()
			if len(pending) != 1 || pending[0].version != first.version+1 || pending[0].reportID == first.reportID {
				t.Fatalf("periodic report = %#v, want one new version and identity after %#v", pending, first)
			}
			restarted := newHeartbeatStorageCache(runDir, zerolog.Nop(), incarnationID)
			if err := restarted.queueForPublish(pending[0].version, pending[0].measurements, now.Add(2*overlayStorageSampleInterval)); err != nil {
				t.Fatal(err)
			}
			if got := restarted.pendingSnapshot(); !reflect.DeepEqual(got, pending) {
				t.Fatalf("restart/retry changed unacknowledged identity: got %#v, want %#v", got, pending)
			}
		})
	}
}

func TestHeartbeatStorageRefreshDoesNotRequeueStaleSnapshot(t *testing.T) {
	cache := newHeartbeatStorageCache("", zerolog.Nop(), uuid.NewString())
	now := time.Now()
	if err := cache.store([]heartbeatStorageMeasurement{{SandboxID: "sandbox-a", AllocatedBytes: 1}}); err != nil {
		t.Fatal(err)
	}
	oldVersion, oldMeasurements := cache.snapshot()
	if err := cache.markSent(oldVersion, now); err != nil {
		t.Fatal(err)
	}
	if err := cache.store([]heartbeatStorageMeasurement{{SandboxID: "sandbox-a", AllocatedBytes: 2}}); err != nil {
		t.Fatal(err)
	}
	version, measurements := cache.snapshot()
	if err := cache.markSent(version, now); err != nil {
		t.Fatal(err)
	}
	if err := cache.queueForPublish(oldVersion, oldMeasurements, now.Add(overlayStorageSampleInterval)); err != nil {
		t.Fatal(err)
	}
	if got := cache.pendingSnapshot(); len(got) != 0 {
		t.Fatalf("stale snapshot appended behind newer acknowledged sample: %#v", got)
	}
	if err := cache.queueForPublish(version, measurements, now.Add(overlayStorageSampleInterval)); err != nil {
		t.Fatal(err)
	}
	if got := cache.pendingSnapshot(); len(got) != 1 || got[0].version != version+1 || !reflect.DeepEqual(got[0].measurements, measurements) {
		t.Fatalf("refresh did not preserve latest sample: %#v", got)
	}
}

func TestHeartbeatStorageRefreshPersistenceFailureKeepsAcknowledgedState(t *testing.T) {
	runDir := t.TempDir()
	cache := newHeartbeatStorageCache(runDir, zerolog.Nop(), uuid.NewString())
	if err := cache.store([]heartbeatStorageMeasurement{{SandboxID: "sandbox-a", AllocatedBytes: 1}}); err != nil {
		t.Fatal(err)
	}
	version, measurements := cache.snapshot()
	now := time.Now()
	if err := cache.markSent(version, now); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(cache.queuePath+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := cache.queueForPublish(version, measurements, now.Add(overlayStorageSampleInterval)); err == nil {
		t.Fatal("refresh succeeded despite spool write failure")
	}
	if gotVersion, gotMeasurements := cache.snapshot(); gotVersion != version || !reflect.DeepEqual(gotMeasurements, measurements) || len(cache.pendingSnapshot()) != 0 {
		t.Fatalf("failed refresh exposed unpersisted state: version=%d measurements=%#v", gotVersion, gotMeasurements)
	}
	if err := os.Remove(cache.queuePath + ".tmp"); err != nil {
		t.Fatal(err)
	}
	if err := cache.queueForPublish(version, measurements, now.Add(overlayStorageSampleInterval)); err != nil {
		t.Fatal(err)
	}
	restarted := newHeartbeatStorageCache(runDir, zerolog.Nop(), cache.incarnationID)
	if got := restarted.pendingSnapshot(); len(got) != 1 || got[0].version != version+1 {
		t.Fatalf("retried refresh was not durable: %#v", got)
	}
}

func TestHeartbeatStorageReportVersionSurvivesRestart(t *testing.T) {
	runDir := t.TempDir()
	incarnationID := "11111111-1111-4111-8111-111111111111"
	first := newHeartbeatStorageCache(runDir, zerolog.Nop(), incarnationID)
	if err := first.store([]heartbeatStorageMeasurement{{SandboxID: "sandbox-a", AllocatedBytes: 1}}); err != nil {
		t.Fatalf("persist first storage sample: %v", err)
	}
	firstVersion, _ := first.snapshot()
	firstPending := first.pendingSnapshot()
	if len(firstPending) != 1 || firstPending[0].reportID == uuid.Nil {
		t.Fatalf("first pending report = %#v, want one report with an ID", firstPending)
	}

	second := newHeartbeatStorageCache(runDir, zerolog.Nop(), incarnationID)
	if err := second.store([]heartbeatStorageMeasurement{{SandboxID: "sandbox-a", AllocatedBytes: 2}}); err != nil {
		t.Fatalf("persist post-restart storage sample: %v", err)
	}
	secondVersion, _ := second.snapshot()
	secondPending := second.pendingSnapshot()
	if len(secondPending) != 2 || secondPending[1].reportID == uuid.Nil {
		t.Fatalf("post-restart pending reports = %#v, want two reports with IDs", secondPending)
	}
	if secondVersion <= firstVersion {
		t.Fatalf("post-restart report version = %d, first version = %d", secondVersion, firstVersion)
	}

	firstID := firstPending[0].reportID
	secondID := secondPending[1].reportID
	if firstID == secondID {
		t.Fatalf("post-restart changed sample reused report ID %s", secondID)
	}
	if secondPending[0].reportID != firstID {
		t.Fatal("restart did not preserve the queued report ID for its retry")
	}
}

func TestStorageReportFileSyncsDirectoryAfterRename(t *testing.T) {
	for _, failSync := range []bool{false, true} {
		t.Run(fmt.Sprintf("sync_failure=%t", failSync), func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, storageReportQueueFilename)
			if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			syncFailure := errors.New("directory sync failed")
			synced := false
			err := writeStorageReportFile(path, []byte("new"), func(parent string) error {
				synced = true
				if parent != dir {
					t.Fatalf("synced directory = %q, want %q", parent, dir)
				}
				data, err := os.ReadFile(path)
				if err != nil || string(data) != "new\n" {
					t.Fatalf("state at directory sync = %q, %v; want renamed replacement", data, err)
				}
				if _, err := os.Stat(path + ".tmp"); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("temporary file still exists at directory sync: %v", err)
				}
				if failSync {
					return syncFailure
				}
				return syncDir(parent)
			})
			if !synced || (failSync && !errors.Is(err, syncFailure)) || (!failSync && err != nil) {
				t.Fatalf("directory synced=%v, error=%v, want sync failure=%v", synced, err, failSync)
			}
		})
	}
}

func TestStorageReportDirectorySyncFailureRetainsAcknowledgementRetry(t *testing.T) {
	runDir := t.TempDir()
	cache := newHeartbeatStorageCache(runDir, zerolog.Nop(), uuid.NewString())
	if err := cache.store([]heartbeatStorageMeasurement{{SandboxID: "sandbox-a", AllocatedBytes: 1}}); err != nil {
		t.Fatal(err)
	}
	pending := cache.pendingSnapshot()
	syncFailure := errors.New("directory sync failed")
	err := cache.updatePersistedState(func(state *heartbeatStorageCache) error {
		if err := state.markSentLocked(pending[0].version, time.Now(), false); err != nil {
			return err
		}
		data, err := json.Marshal(storageReportQueueState{
			IncarnationID: state.incarnationID,
			ReportSpace:   state.reportSpace.String(),
			Version:       state.version,
			Measurements:  state.measurements,
			Pending:       storageReportQueueEntries(state.pending),
		})
		if err != nil {
			return err
		}
		return writeStorageReportFile(state.queuePath, data, func(string) error { return syncFailure })
	})
	if !errors.Is(err, syncFailure) {
		t.Fatalf("acknowledgement error = %v, want directory sync failure", err)
	}
	if got := cache.pendingSnapshot(); !reflect.DeepEqual(got, pending) {
		t.Fatalf("pending after directory sync failure = %#v, want stable retry %#v", got, pending)
	}
	if err := cache.markSent(pending[0].version, time.Now()); err != nil {
		t.Fatalf("retry acknowledgement persistence: %v", err)
	}
	restarted := newHeartbeatStorageCache(runDir, zerolog.Nop(), cache.incarnationID)
	if got := restarted.pendingSnapshot(); len(got) != 0 {
		t.Fatalf("pending after durable acknowledgement and restart = %#v, want none", got)
	}
}

func TestHeartbeatStorageCacheStateDefersDiskRestore(t *testing.T) {
	runDir := t.TempDir()
	incarnationID := "11111111-1111-4111-8111-111111111111"
	persisted := newHeartbeatStorageCache(runDir, zerolog.Nop(), incarnationID)
	if err := persisted.store([]heartbeatStorageMeasurement{{SandboxID: "sandbox-a", AllocatedBytes: 1}}); err != nil {
		t.Fatalf("persist storage sample: %v", err)
	}

	deferred := newHeartbeatStorageCacheState(runDir, zerolog.Nop(), incarnationID)
	version, measurements := deferred.snapshot()
	if version != 0 || len(measurements) != 0 {
		t.Fatalf("deferred cache restored disk state during construction: version=%d measurements=%#v", version, measurements)
	}
	deferred.restore()
	version, measurements = deferred.snapshot()
	if version == 0 || len(measurements) != 1 {
		t.Fatalf("restored cache state = version %d measurements %#v, want persisted sample", version, measurements)
	}
}

func TestHeartbeatStorageCacheDropsSnapshotOnIncarnationChange(t *testing.T) {
	runDir := t.TempDir()
	previousIncarnation := "11111111-1111-4111-8111-111111111111"
	currentIncarnation := "22222222-2222-4222-8222-222222222222"
	previous := newHeartbeatStorageCache(runDir, zerolog.Nop(), previousIncarnation)
	if err := previous.store([]heartbeatStorageMeasurement{{SandboxID: "sandbox-a", AllocatedBytes: 1}}); err != nil {
		t.Fatalf("persist previous incarnation sample: %v", err)
	}

	current := newHeartbeatStorageCache(runDir, zerolog.Nop(), currentIncarnation)
	version, measurements := current.snapshot()
	if version == 0 {
		t.Fatal("incarnation change reset the monotonic report version")
	}
	if len(measurements) != 0 {
		t.Fatalf("measurements after incarnation change = %#v, want empty", measurements)
	}
	if current.sentVersion != 0 || !current.sentAt.IsZero() {
		t.Fatalf("sent state after incarnation change = version %d at %v, want reset", current.sentVersion, current.sentAt)
	}
	if current.shouldSend(version, time.Now()) {
		t.Fatal("stale measurements became eligible for publication after incarnation change")
	}
}

func TestHeartbeatStorageReportIDsChangeAcrossFreshCache(t *testing.T) {
	incarnationID := "11111111-1111-4111-8111-111111111111"
	first := newHeartbeatStorageCache("", zerolog.Nop(), incarnationID)
	if err := first.store([]heartbeatStorageMeasurement{{SandboxID: "sandbox-a", AllocatedBytes: 1}}); err != nil {
		t.Fatalf("store first sample: %v", err)
	}
	second := newHeartbeatStorageCache("", zerolog.Nop(), incarnationID)
	if err := second.store([]heartbeatStorageMeasurement{{SandboxID: "sandbox-a", AllocatedBytes: 2}}); err != nil {
		t.Fatalf("store restarted sample: %v", err)
	}
	firstID := first.pendingSnapshot()[0].reportID
	secondID := second.pendingSnapshot()[0].reportID
	if firstID == uuid.Nil || secondID == uuid.Nil || firstID == secondID {
		t.Fatalf("fresh cache report IDs = [%s %s], want distinct nonzero IDs", firstID, secondID)
	}
}

func TestHeartbeatStorageQueueRetainsDistinctSamplesAcrossRestart(t *testing.T) {
	runDir := t.TempDir()
	incarnationID := "11111111-1111-4111-8111-111111111111"
	first := newHeartbeatStorageCache(runDir, zerolog.Nop(), incarnationID)
	if err := first.store([]heartbeatStorageMeasurement{{SandboxID: "sandbox-a", AllocatedBytes: 1}}); err != nil {
		t.Fatalf("persist first storage sample: %v", err)
	}
	firstVersion, _ := first.snapshot()
	if err := first.store([]heartbeatStorageMeasurement{{SandboxID: "sandbox-a", AllocatedBytes: 2}}); err != nil {
		t.Fatalf("persist second storage sample: %v", err)
	}
	secondVersion, _ := first.snapshot()

	second := newHeartbeatStorageCache(runDir, zerolog.Nop(), incarnationID)
	pending := second.pendingSnapshot()
	if len(pending) != 2 {
		t.Fatalf("pending reports after restart = %d, want 2", len(pending))
	}
	if pending[0].version != firstVersion || pending[1].version != secondVersion {
		t.Fatalf("pending versions = [%d %d], want [%d %d]", pending[0].version, pending[1].version, firstVersion, secondVersion)
	}
	if err := second.markSent(firstVersion, time.Now()); err != nil {
		t.Fatalf("acknowledge first report: %v", err)
	}
	if got := len(second.pendingSnapshot()); got != 1 {
		t.Fatalf("pending reports after first ack = %d, want 1", got)
	}
	third := newHeartbeatStorageCache(runDir, zerolog.Nop(), incarnationID)
	pending = third.pendingSnapshot()
	if len(pending) != 1 || pending[0].version != secondVersion {
		t.Fatalf("pending reports after ack/restart = %#v, want version %d", pending, secondVersion)
	}
}

func TestLegacyHeartbeatDrainsPendingStorageInVersionOrder(t *testing.T) {
	cache := newHeartbeatStorageCache("", zerolog.Nop())
	for _, bytes := range []int64{1, 2} {
		if err := cache.store([]heartbeatStorageMeasurement{{SandboxID: "sandbox-a", AllocatedBytes: bytes}}); err != nil {
			t.Fatalf("store storage sample: %v", err)
		}
	}
	// A later empty sample must not prevent earlier queued changes from draining.
	if err := cache.store(nil); err != nil {
		t.Fatalf("store empty sample: %v", err)
	}

	for _, bytes := range []int64{1, 2} {
		pending, ok := cache.oldestPendingSnapshot()
		if !ok || len(pending.measurements) != 1 || pending.measurements[0].AllocatedBytes != bytes {
			t.Fatalf("oldest pending report = %#v, present = %v; want %d bytes", pending, ok, bytes)
		}
		// An unsuccessful handoff leaves the same report available for retry.
		retry, ok := cache.oldestPendingSnapshot()
		if !ok || retry.reportID != pending.reportID || retry.version != pending.version {
			t.Fatalf("retry report = %#v, present = %v; want %#v", retry, ok, pending)
		}
		if err := cache.markSent(pending.version, time.Now()); err != nil {
			t.Fatalf("acknowledge report: %v", err)
		}
	}
	if pending, ok := cache.oldestPendingSnapshot(); ok {
		t.Fatalf("pending report after both acknowledgements = %#v", pending)
	}
}

func TestHeartbeatStorageCacheReadersDoNotWaitForBlockedSpoolFile(t *testing.T) {
	cache := newHeartbeatStorageCache(t.TempDir(), zerolog.Nop())
	first := []heartbeatStorageMeasurement{{SandboxID: "sandbox-a", AllocatedBytes: 1}}
	if err := cache.store(first); err != nil {
		t.Fatal(err)
	}
	// A FIFO with no reader blocks the actual spool write until the test
	// releases it, without requiring a slow filesystem or timing a fsync.
	spoolTemp := cache.queuePath + ".tmp"
	if err := syscall.Mkfifo(spoolTemp, 0o600); err != nil {
		t.Fatal(err)
	}
	stored := make(chan error, 1)
	go func() {
		stored <- cache.store([]heartbeatStorageMeasurement{{SandboxID: "sandbox-a", AllocatedBytes: 2}})
	}()
	deadline := time.Now().Add(time.Second)
	for cache.persistMu.TryLock() {
		cache.persistMu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("storage writer did not start")
		}
		time.Sleep(time.Millisecond)
	}
	read := make(chan []heartbeatStorageMeasurement, 1)
	go func() {
		_, measurements := cache.snapshot()
		read <- measurements
	}()
	var got []heartbeatStorageMeasurement
	blocked := false
	select {
	case got = <-read:
	case <-time.After(time.Second):
		blocked = true
	}
	reader, err := os.Open(spoolTemp)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, reader)
	_ = reader.Close()
	// FIFO writes cannot be fsynced; the previous durable sample must survive.
	if err := <-stored; err == nil {
		t.Error("spool persistence unexpectedly accepted a FIFO")
	}
	if blocked {
		<-read
		t.Fatal("heartbeat cache snapshot waited for a blocked spool file")
	}
	if !reflect.DeepEqual(got, first) {
		t.Fatalf("snapshot during spool write = %#v, want %#v", got, first)
	}
}

func TestHeartbeatStorageCacheAcknowledgementDuringPersistence(t *testing.T) {
	runDir := t.TempDir()
	cache := newHeartbeatStorageCache(runDir, zerolog.Nop())
	defer cache.acknowledgementWrites.Wait()
	first := []heartbeatStorageMeasurement{{SandboxID: "sandbox-a", AllocatedBytes: 1}}
	if err := cache.store(first); err != nil {
		t.Fatal(err)
	}
	firstVersion, _ := cache.snapshot()

	persisting := make(chan struct{})
	release := make(chan struct{})
	stored := make(chan error, 1)
	go func() {
		stored <- cache.updatePersistedState(func(state *heartbeatStorageCache) error {
			close(persisting)
			<-release
			return state.storeState([]heartbeatStorageMeasurement{{SandboxID: "sandbox-a", AllocatedBytes: 2}})
		})
	}()
	<-persisting
	read := make(chan struct{})
	go func() {
		version, measurements := cache.snapshot()
		if version != firstVersion || !reflect.DeepEqual(measurements, first) {
			t.Errorf("snapshot during persistence = %d, %#v; want previous durable sample", version, measurements)
		}
		cache.markSentInMemory(firstVersion, time.Now())
		close(read)
	}()
	select {
	case <-read:
	case <-time.After(time.Second):
		close(release)
		<-stored
		<-read
		t.Fatal("heartbeat cache reads or acknowledgement waited for spool persistence")
	}
	close(release)
	if err := <-stored; err != nil {
		t.Fatal(err)
	}
	cache.acknowledgementWrites.Wait()
	pending := cache.pendingSnapshot()
	if len(pending) != 1 || pending[0].version <= firstVersion || pending[0].measurements[0].AllocatedBytes != 2 {
		t.Fatalf("pending after concurrent sample and acknowledgement = %#v, want only new sample", pending)
	}
	// The actual acknowledgement flush must preserve the newly committed
	// sample, including across restart.
	restarted := newHeartbeatStorageCache(runDir, zerolog.Nop())
	if got := restarted.pendingSnapshot(); !reflect.DeepEqual(got, pending) {
		t.Fatalf("pending after restart = %#v, want %#v", got, pending)
	}
}

func TestStorageReportLoopDrainsPendingAfterLatestSampleBecomesEmpty(t *testing.T) {
	cache := newHeartbeatStorageCache("", zerolog.Nop(), uuid.NewString())
	if err := cache.store([]heartbeatStorageMeasurement{{SandboxID: "sandbox-a", AllocatedBytes: 1}}); err != nil {
		t.Fatal(err)
	}
	if err := cache.store(nil); err != nil {
		t.Fatal(err)
	}
	version, measurements := cache.snapshot()
	if len(measurements) != 0 || !cache.shouldSend(version, time.Now()) {
		t.Fatal("empty latest sample hid an earlier pending storage report")
	}
	published := make(chan storageReportWire, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var report storageReportWire
		if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
			t.Error(err)
		}
		published <- report
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		storageReportLoop(ctx, server.Client(), HeartbeatConfig{HostID: "host-a", IncarnationID: cache.incarnationID}, server.URL, "", cache, make(chan struct{}), zerolog.Nop())
		close(done)
	}()
	defer func() {
		cancel()
		<-done
	}()
	select {
	case report := <-published:
		if len(report.Measurements) != 1 || report.Measurements[0].AllocatedBytes != 1 {
			t.Fatalf("published report = %#v, want pending sample", report)
		}
	case <-time.After(time.Second):
		t.Fatal("pending storage report was not published with an empty latest sample")
	}
}

func TestHeartbeatStorageQueueBoundsUnsentSnapshots(t *testing.T) {
	runDir := t.TempDir()
	incarnationID := "11111111-1111-4111-8111-111111111111"
	cache := newHeartbeatStorageCache(runDir, zerolog.Nop(), incarnationID)
	for i := 0; i < storageReportQueueMaxEntries+5; i++ {
		if err := cache.store([]heartbeatStorageMeasurement{{SandboxID: fmt.Sprintf("sandbox-%d", i), AllocatedBytes: int64(i)}}); err != nil {
			t.Fatalf("persist storage sample %d: %v", i, err)
		}
	}

	pending := cache.pendingSnapshot()
	if len(pending) != storageReportQueueMaxEntries {
		t.Fatalf("pending reports = %d, want queue bound %d", len(pending), storageReportQueueMaxEntries)
	}
	if pending[0].version != 6 {
		t.Fatalf("oldest retained report version = %d, want oldest snapshots discarded", pending[0].version)
	}
	info, err := os.Stat(filepath.Join(runDir, storageReportQueueFilename))
	if err != nil {
		t.Fatalf("stat storage report queue: %v", err)
	}
	if info.Size() > storageReportQueueMaxBytes {
		t.Fatalf("storage report queue size = %d, exceeds %d-byte bound", info.Size(), storageReportQueueMaxBytes)
	}

	restarted := newHeartbeatStorageCache(runDir, zerolog.Nop(), incarnationID)
	if got := len(restarted.pendingSnapshot()); got != storageReportQueueMaxEntries {
		t.Fatalf("restarted pending reports = %d, want queue bound %d", got, storageReportQueueMaxEntries)
	}
}

func TestHeartbeatStorageQueueIgnoresOversizedSpool(t *testing.T) {
	runDir := t.TempDir()
	queuePath := filepath.Join(runDir, storageReportQueueFilename)
	file, err := os.Create(queuePath)
	if err != nil {
		t.Fatalf("create storage report queue: %v", err)
	}
	if err := file.Truncate(storageReportQueueMaxBytes + 1); err != nil {
		_ = file.Close()
		t.Fatalf("grow storage report queue: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close storage report queue: %v", err)
	}

	cache := newHeartbeatStorageCache(runDir, zerolog.Nop(), "11111111-1111-4111-8111-111111111111")
	if got := len(cache.pendingSnapshot()); got != 0 {
		t.Fatalf("pending reports from oversized spool = %d, want 0", got)
	}
}

func TestHeartbeatCancellationDoesNotWaitForStorageWorker(t *testing.T) {
	runDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(runDir, storageReportQueueFilename), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	writer := &heartbeatRestoreBlockingWriter{entered: make(chan struct{}), release: make(chan struct{})}
	releaseRestore := sync.OnceFunc(func() { close(writer.release) })
	var attempts atomic.Int32
	secondHeartbeat := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			_ = json.NewEncoder(w).Encode(proxyHealthResponse{})
			return
		}
		if attempts.Add(1) == 2 {
			close(secondHeartbeat)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	joined := make(chan struct{})
	defer func() {
		cancel()
		// Release the artificial stall before joining, including on early failure.
		releaseRestore()
		select {
		case <-joined:
		case <-time.After(3 * time.Second):
			t.Error("storage workers did not finish after releasing restore")
		}
	}()
	go func() {
		waitForStorage := runHeartbeat(ctx, HeartbeatConfig{
			ControlPlaneURL: server.URL,
			ProxyHealthURL:  server.URL + "/health",
			HostID:          "host-a",
			RunDir:          runDir,
			Interval:        10 * time.Millisecond,
		}, zerolog.New(writer))
		close(stopped)
		waitForStorage()
		close(joined)
	}()
	select {
	case <-writer.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("storage restore did not start")
	}
	select {
	case <-secondHeartbeat:
	case <-time.After(3 * time.Second):
		t.Fatal("blocked storage restore interrupted heartbeats")
	}
	cancel()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("heartbeat cancellation waited for storage restore")
	}
	select {
	case <-joined:
		t.Fatal("storage join returned while restore was still blocked")
	case <-time.After(20 * time.Millisecond):
	}
	releaseRestore()
	select {
	case <-joined:
	case <-time.After(3 * time.Second):
		t.Fatal("storage join did not finish after restore was released")
	}
}

type heartbeatRestoreBlockingWriter struct {
	entered chan struct{}
	release chan struct{}
}

func (w *heartbeatRestoreBlockingWriter) Write(p []byte) (int, error) {
	if strings.Contains(string(p), "storage report queue state invalid") {
		close(w.entered)
		<-w.release
	}
	return len(p), nil
}

func TestStartHeartbeatRefreshesAcknowledgedLegacyStorageWithNewIdentity(t *testing.T) {
	runDir := t.TempDir()
	sandboxDir := filepath.Join(runDir, uuid.NewString())
	if err := os.Mkdir(sandboxDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sandboxDir, "overlay.ext4"), []byte("storage"), 0o600); err != nil {
		t.Fatal(err)
	}
	measurements, err := measureOverlayStorage(runDir)
	if err != nil {
		t.Fatal(err)
	}
	cache := newHeartbeatStorageCache(runDir, zerolog.Nop())
	if err := cache.store(measurements); err != nil {
		t.Fatal(err)
	}
	first := cache.pendingSnapshot()[0]
	if err := cache.markSent(first.version, time.Now().Add(-overlayStorageSampleInterval)); err != nil {
		t.Fatal(err)
	}
	published := make(chan heartbeatRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			_ = json.NewEncoder(w).Encode(proxyHealthResponse{})
		case "/internal/hosts/host-a/heartbeat":
			var request heartbeatRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Error(err)
			}
			if len(request.Storage) > 0 {
				// The new identity must be on disk before the legacy heartbeat
				// carries it, even though preparation runs off the liveness loop.
				restored := newHeartbeatStorageCache(runDir, zerolog.Nop())
				pending := restored.pendingSnapshot()
				if len(pending) != 1 || pending[0].reportID.String() != request.StorageReportID {
					t.Errorf("legacy refresh not durable before POST: pending=%#v request=%#v", pending, request)
				}
				select {
				case published <- request:
				default:
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]bool{"storage_accepted": true})
		case "/internal/hosts/host-a/storage-reports":
			t.Error("incarnationless VMD used dedicated storage endpoint")
			w.WriteHeader(http.StatusBadRequest)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		waitForStorage := runHeartbeat(ctx, HeartbeatConfig{
			ControlPlaneURL: server.URL,
			ProxyHealthURL:  server.URL + "/health",
			HostID:          "host-a",
			RunDir:          runDir,
			Interval:        10 * time.Millisecond,
		}, zerolog.Nop())
		waitForStorage()
		close(done)
	}()
	defer func() {
		cancel()
		<-done
	}()
	select {
	case report := <-published:
		if report.StorageReportID == first.reportID.String() || !reflect.DeepEqual(report.Storage, first.measurements) {
			t.Fatalf("legacy refresh = %#v, want unchanged measurements with new identity", report)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("acknowledged legacy sample was not refreshed")
	}
}

func TestStartHeartbeatUsesLegacyStorageForIncarnationlessVMD(t *testing.T) {
	runDir := t.TempDir()
	sandboxID := "11111111-1111-4111-8111-111111111111"
	sandboxDir := filepath.Join(runDir, sandboxID)
	if err := os.Mkdir(sandboxDir, 0o700); err != nil {
		t.Fatalf("create sandbox directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sandboxDir, "overlay.ext4"), []byte("storage"), 0o600); err != nil {
		t.Fatalf("create overlay: %v", err)
	}

	legacyStorage := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			_ = json.NewEncoder(w).Encode(proxyHealthResponse{})
		case "/internal/hosts/host-a/heartbeat":
			var req heartbeatRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode heartbeat: %v", err)
			}
			if len(req.Storage) > 0 {
				select {
				case legacyStorage <- struct{}{}:
				default:
				}
			}
			w.WriteHeader(http.StatusOK)
		case "/internal/hosts/host-a/storage-reports":
			t.Errorf("incarnationless VMD used dedicated storage endpoint")
			w.WriteHeader(http.StatusBadRequest)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		waitForStorage := runHeartbeat(ctx, HeartbeatConfig{
			ControlPlaneURL: server.URL,
			ProxyHealthURL:  server.URL + "/health",
			HostID:          "host-a",
			RunDir:          runDir,
			Interval:        10 * time.Millisecond,
		}, zerolog.Nop())
		waitForStorage()
		close(done)
	}()
	defer func() {
		cancel()
		<-done
	}()

	select {
	case <-legacyStorage:
		cancel()
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("incarnationless heartbeat did not carry legacy storage")
	}
	<-done
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

func TestHeartbeatLogsEndpointAcknowledgementOnceAfterAcceptance(t *testing.T) {
	for _, mode := range []string{"incomplete", "complete", "bound-default", "bound-cleared"} {
		complete := mode != "incomplete"
		t.Run(mode, func(t *testing.T) {
			var attempts atomic.Int32
			third := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/health" {
					_, _ = w.Write([]byte(`{"capabilities":[]}`))
					return
				}
				n := attempts.Add(1)
				if n == 1 {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				if n == 3 {
					close(third)
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			writer := &heartbeatReceiptWriter{attempts: &attempts, events: make(chan heartbeatReceiptEvent, 64)}
			cfg := HeartbeatConfig{ControlPlaneURL: server.URL, ProxyHealthURL: server.URL + "/health", HostID: "host-a", RunDir: t.TempDir(), Interval: 10 * time.Millisecond}
			if complete {
				cfg.VMDAddr, cfg.ProxyAddr, cfg.Region = "192.0.2.1:50051", "192.0.2.1:5009", "test-region"
				cfg.CapacityMemoryMib, cfg.CapacityVcpus = 1024, 1
			}
			if strings.HasPrefix(mode, "bound-") {
				cfg.IncarnationID = "11111111-1111-4111-8111-111111111111"
				cfg.HostID = "default"
				if mode == "bound-cleared" {
					cfg.ProxyAddr = ""
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() {
				waitForStorage := runHeartbeat(ctx, cfg, zerolog.New(writer))
				waitForStorage()
				close(done)
			}()
			defer func() {
				cancel()
				<-done
			}()
			select {
			case <-third:
			case <-time.After(3 * time.Second):
				t.Fatal("heartbeats did not retry")
			}
			cancel()
			<-done
			count := 0
			for len(writer.events) > 0 {
				event := <-writer.events
				if strings.Contains(event.line, "host endpoint heartbeat accepted") {
					count++
					if event.attempt < 2 || !strings.Contains(event.line, cfg.ProxyAddr) {
						t.Fatalf("invalid acknowledgement: %+v", event)
					}
				}
			}
			want := 0
			if complete {
				want = 1
			}
			if count != want {
				t.Fatalf("acknowledgements = %d, want %d", count, want)
			}
		})
	}
}

type heartbeatReceiptEvent struct {
	line    string
	attempt int32
}
type heartbeatReceiptWriter struct {
	attempts *atomic.Int32
	events   chan heartbeatReceiptEvent
}

func (w *heartbeatReceiptWriter) Write(p []byte) (int, error) {
	w.events <- heartbeatReceiptEvent{line: string(p), attempt: w.attempts.Load()}
	return len(p), nil
}

func TestHeartbeatPreservesInstalledIncarnation(t *testing.T) {
	cfg := HeartbeatConfig{IncarnationID: "54ab780a-cd77-4aef-8cd0-c2dd9c5032ef", VMDAddr: "192.0.2.10:50051", ProxyAddr: "192.0.2.10:5009", Region: "example-region", CapacityMemoryMib: 1024, CapacityVcpus: 2}
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req heartbeatRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode heartbeat: %v", err)
		}
		if req.IncarnationID != cfg.IncarnationID || req.VMDAddr != cfg.VMDAddr || req.ProxyAddr != cfg.ProxyAddr ||
			req.Region != cfg.Region || req.CapacityMemoryMib != cfg.CapacityMemoryMib || req.CapacityVcpus != cfg.CapacityVcpus {
			t.Errorf("heartbeat lost installation identity or description: %+v", req)
		}
		if attempts.Add(1) == 1 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	for i := range 2 {
		ok, _ := postHeartbeat(context.Background(), server.Client(), cfg, server.URL, "", nil, nil, zerolog.Nop(), time.Now())
		if ok != (i == 1) {
			t.Fatalf("heartbeat %d accepted = %t", i, ok)
		}
	}
	if attempts.Load() != 2 {
		t.Fatalf("requests = %d, want 2 without an identity-less fallback", attempts.Load())
	}
}
