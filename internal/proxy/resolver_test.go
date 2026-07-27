package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/superserve-ai/sandbox/internal/preview"
)

func attestPreviewProtocol(w http.ResponseWriter) {
	w.Header().Set(preview.VMDProtocolHeader, preview.HostCapabilityPorts)
}

func TestVMDResolverRejectsOldVMDResponseWithoutProtocolAttestation(t *testing.T) {
	var gotHeader, gotCapabilities, gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get(preview.ProxyProtocolHeader)
		gotCapabilities = r.Header.Get(preview.ProxyCapabilitiesHeader)
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		// This is the response shape from a VMD predating preview publication.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"vm_ip":      "10.0.0.2",
			"status":     "running",
			"started_at": int64(123),
		})
	}))
	defer server.Close()

	_, err := NewVMDResolver(server.URL).Lookup(context.Background(), "vm-strict-on-old-vmd")
	if !errors.Is(err, ErrVMDPreviewProtocolUnsupported) {
		t.Fatalf("Lookup error = %v, want ErrVMDPreviewProtocolUnsupported", err)
	}
	if gotPath != "/instances/vm-strict-on-old-vmd" {
		t.Fatalf("path = %q, want /instances/vm-strict-on-old-vmd", gotPath)
	}
	if gotHeader != preview.HostCapabilityPorts {
		t.Fatalf("%s = %q, want %q", preview.ProxyProtocolHeader, gotHeader, preview.HostCapabilityPorts)
	}
	if gotCapabilities != preview.HostCapabilityPortAccess {
		t.Fatalf("%s = %q, want %q", preview.ProxyCapabilitiesHeader, gotCapabilities, preview.HostCapabilityPortAccess)
	}
	if got := err.Error(); !strings.Contains(got, preview.VMDProtocolHeader) {
		t.Fatalf("error %q does not identify missing protocol header", got)
	}
}

func TestVMDResolverAcceptsAttestedLegacyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attestPreviewProtocol(w)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"vm_ip":      "10.0.0.2",
			"status":     "running",
			"started_at": int64(123),
		})
	}))
	defer server.Close()

	info, err := NewVMDResolver(server.URL).Lookup(context.Background(), "vm-legacy")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if info.VMIP != "10.0.0.2" || info.PreviewAccess != "" || info.PreviewPorts != nil {
		t.Fatalf("legacy response decoded as %#v", info)
	}
}

func TestVMDResolverDecodesParallelPortAccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attestPreviewProtocol(w)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"vm_ip":               "10.0.0.2",
			"status":              "running",
			"preview_access":      "private",
			"preview_ports":       map[string]bool{"3000": true, "3001": true, "bad": true},
			"preview_port_access": map[string]string{"3000": "public", "3001": "future", "9999": "private", "bad": "public"},
		})
	}))
	defer server.Close()

	info, err := NewVMDResolver(server.URL).Lookup(context.Background(), "vm-mixed")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(info.PreviewPorts) != 2 || info.PreviewPortAccess[3000] != preview.AccessPublic || info.PreviewPortAccess[3001] != "future" {
		t.Fatalf("decoded policy = ports %#v access %#v", info.PreviewPorts, info.PreviewPortAccess)
	}
	if _, ok := info.PreviewPortAccess[9999]; ok {
		t.Fatalf("access for unpublished port survived decode: %#v", info.PreviewPortAccess)
	}
}

func TestVMDResolverDoesNotCacheSuccessfulPolicy(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attestPreviewProtocol(w)
		call := calls.Add(1)
		ports := map[string]bool{"3000": true}
		if call > 1 {
			ports = map[string]bool{"8080": true}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"vm_ip":          "10.0.0.2",
			"status":         "running",
			"started_at":     int64(123),
			"preview_access": "public",
			"preview_ports":  ports,
		})
	}))
	defer server.Close()

	resolver := NewVMDResolver(server.URL)
	first, err := resolver.Lookup(context.Background(), "vm-current")
	if err != nil {
		t.Fatalf("first Lookup: %v", err)
	}
	second, err := resolver.Lookup(context.Background(), "vm-current")
	if err != nil {
		t.Fatalf("second Lookup: %v", err)
	}

	if calls.Load() != 2 {
		t.Fatalf("VMD calls = %d, want 2 successful reads", calls.Load())
	}
	if _, ok := first.PreviewPorts[3000]; !ok {
		t.Fatalf("first policy = %#v, want port 3000", first.PreviewPorts)
	}
	if _, ok := second.PreviewPorts[8080]; !ok {
		t.Fatalf("second policy = %#v, want revised port 8080", second.PreviewPorts)
	}
	if _, stale := second.PreviewPorts[3000]; stale {
		t.Fatalf("second policy retained stale port 3000: %#v", second.PreviewPorts)
	}
	resolver.mu.Lock()
	cached := len(resolver.cache)
	resolver.mu.Unlock()
	if cached != 0 {
		t.Fatalf("successful lookup left %d cache entries, want 0", cached)
	}
}

func TestVMDResolverInvalidateStartsFreshLookupDuringInflightSuccess(t *testing.T) {
	var calls atomic.Int32
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attestPreviewProtocol(w)
		call := calls.Add(1)
		port := "8080"
		if call == 1 {
			close(firstStarted)
			<-releaseFirst
			port = "3000"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"vm_ip":          "10.0.0.2",
			"status":         "running",
			"started_at":     int64(123),
			"preview_access": "public",
			"preview_ports":  map[string]bool{port: true},
		})
	}))
	defer server.Close()

	resolver := NewVMDResolver(server.URL)
	firstResult := make(chan error, 1)
	go func() {
		_, err := resolver.Lookup(context.Background(), "vm-inflight")
		firstResult <- err
	}()
	<-firstStarted

	resolver.Invalidate("vm-inflight")
	secondResult := make(chan struct {
		info InstanceInfo
		err  error
	}, 1)
	go func() {
		info, err := resolver.Lookup(context.Background(), "vm-inflight")
		secondResult <- struct {
			info InstanceInfo
			err  error
		}{info: info, err: err}
	}()

	select {
	case got := <-secondResult:
		if got.err != nil {
			close(releaseFirst)
			t.Fatalf("fresh Lookup: %v", got.err)
		}
		if _, ok := got.info.PreviewPorts[8080]; !ok {
			close(releaseFirst)
			t.Fatalf("fresh Lookup joined stale in-flight policy: %#v", got.info.PreviewPorts)
		}
	case <-time.After(2 * time.Second):
		close(releaseFirst)
		t.Fatal("fresh Lookup remained attached to the invalidated in-flight request")
	}

	close(releaseFirst)
	if err := <-firstResult; err != nil {
		t.Fatalf("original Lookup: %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("VMD calls = %d, want a fresh call after invalidation", calls.Load())
	}

	// The older successful request completed last. It must not have reinserted
	// port 3000 for the following lookup.
	third, err := resolver.Lookup(context.Background(), "vm-inflight")
	if err != nil {
		t.Fatalf("third Lookup: %v", err)
	}
	if _, ok := third.PreviewPorts[8080]; !ok {
		t.Fatalf("third policy = %#v, want current port 8080", third.PreviewPorts)
	}
	if calls.Load() != 3 {
		t.Fatalf("VMD calls = %d, want every completed success re-read", calls.Load())
	}
}

func TestVMDResolverCachesOnlyNegativeLookups(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		http.Error(w, "instance not found", http.StatusNotFound)
	}))
	defer server.Close()

	resolver := NewVMDResolver(server.URL)
	for i := 0; i < 2; i++ {
		_, err := resolver.Lookup(context.Background(), "vm-missing")
		if !errors.Is(err, ErrInstanceNotFound) {
			t.Fatalf("Lookup %d error = %v, want ErrInstanceNotFound", i+1, err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("VMD calls = %d, want one cached miss", calls.Load())
	}

	resolver.Invalidate("vm-missing")
	_, err := resolver.Lookup(context.Background(), "vm-missing")
	if !errors.Is(err, ErrInstanceNotFound) {
		t.Fatalf("Lookup after Invalidate error = %v, want ErrInstanceNotFound", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("VMD calls = %d, want Invalidate to clear cached miss", calls.Load())
	}
}

func TestVMDResolverInflightMissCannotReinsertAfterInvalidate(t *testing.T) {
	var calls atomic.Int32
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		call := calls.Add(1)
		if call == 1 {
			close(firstStarted)
			<-releaseFirst
			http.Error(w, "old instance miss", http.StatusNotFound)
			return
		}
		attestPreviewProtocol(w)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"vm_ip":          "10.0.0.2",
			"status":         "running",
			"started_at":     int64(123),
			"preview_access": "public",
			"preview_ports":  map[string]bool{"8080": true},
		})
	}))
	defer server.Close()

	resolver := NewVMDResolver(server.URL)
	oldResult := make(chan error, 1)
	go func() {
		_, err := resolver.Lookup(context.Background(), "vm-reappeared")
		oldResult <- err
	}()
	<-firstStarted

	resolver.Invalidate("vm-reappeared")
	fresh, err := resolver.Lookup(context.Background(), "vm-reappeared")
	if err != nil {
		close(releaseFirst)
		t.Fatalf("fresh Lookup: %v", err)
	}
	if _, ok := fresh.PreviewPorts[8080]; !ok {
		close(releaseFirst)
		t.Fatalf("fresh policy = %#v, want port 8080", fresh.PreviewPorts)
	}

	// Let the older 404 arrive after the newer success. Its pre-invalidation
	// epoch must prevent it from populating the negative cache.
	close(releaseFirst)
	if err := <-oldResult; !errors.Is(err, ErrInstanceNotFound) {
		t.Fatalf("old Lookup error = %v, want ErrInstanceNotFound", err)
	}
	third, err := resolver.Lookup(context.Background(), "vm-reappeared")
	if err != nil {
		t.Fatalf("Lookup after late miss: %v", err)
	}
	if _, ok := third.PreviewPorts[8080]; !ok {
		t.Fatalf("policy after late miss = %#v, want port 8080", third.PreviewPorts)
	}
	if calls.Load() != 3 {
		t.Fatalf("VMD calls = %d, want late miss ignored and a third fresh read", calls.Load())
	}
}

func TestVMDResolverNegativeCacheIsBounded(t *testing.T) {
	resolver := NewVMDResolver("http://127.0.0.1:1")
	for i := 0; i < maxCacheSize+100; i++ {
		resolver.storeNegative(fmt.Sprintf("missing-%d", i), 0)
	}
	resolver.mu.Lock()
	size := len(resolver.cache)
	resolver.mu.Unlock()
	if size != maxCacheSize {
		t.Fatalf("negative cache size = %d, want %d", size, maxCacheSize)
	}
}
