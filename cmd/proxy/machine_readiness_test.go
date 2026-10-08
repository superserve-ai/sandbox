package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
	"github.com/superserve-ai/sandbox/internal/auth"
	"github.com/superserve-ai/sandbox/internal/proxy"
)

func TestMachineReadinessProbeRejectsLegacyOnlyPeerDisabledProxy(t *testing.T) {
	vmd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(auth.VMDMachineIdentityHeader, auth.MachineIdentityRevision)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer vmd.Close()
	local := proxy.NewHandler([]string{"sandbox.test"}, proxy.NewVMDResolver(vmd.URL), zerolog.Nop()).WithAuth([]byte("machine-readiness-test-key-0123456"))
	public, private := newDataPlaneMuxes(local, nil, false)
	for _, listener := range []http.Handler{public, private, newRedirectMux(local, public)} {
		response := httptest.NewRecorder()
		listener.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://proxy-machine-readiness.invalid/health", nil))
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("legacy-only proxy reported machine readiness: %d", response.Code)
		}
		var health proxyHealthResponse
		if err := json.Unmarshal(response.Body.Bytes(), &health); err != nil {
			t.Fatal(err)
		}
		if !health.ResolverReady || health.MachineIdentityReady || health.MachineIdentityRevision != proxy.MachineIdentityRevision {
			t.Fatalf("incorrect machine health contract: %+v", health)
		}
	}
	response := httptest.NewRecorder()
	public.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://proxy-readiness.invalid/health", nil))
	if response.Code != http.StatusOK {
		t.Fatal("machine prerequisite changed ordinary resolver health")
	}
	response = httptest.NewRecorder()
	public.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://localhost/health", nil))
	if response.Code != http.StatusOK {
		t.Fatal("machine prerequisite changed legacy health response")
	}
}

func TestMachineDatabaseReadinessDoesNotEnablePeerRouting(t *testing.T) {
	resolver := &listenerResolver{}
	local := proxy.NewHandler([]string{"sandbox.test"}, resolver, zerolog.Nop())
	peerCalls, databaseReadinessCalls := 0, 0
	router := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { peerCalls++; w.WriteHeader(http.StatusBadGateway) })
	databaseReady := func(context.Context) bool { databaseReadinessCalls++; return false }
	public, private := newDataPlaneMuxesWithReadiness(local, router, false, databaseReady)
	for _, listener := range []http.Handler{public, private} {
		response := httptest.NewRecorder()
		listener.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://8080-12345678-1234-1234-1234-123456789abc.sandbox.test/", nil))
		if response.Code != http.StatusNotFound {
			t.Fatalf("local request routed incorrectly: %d", response.Code)
		}
		listener.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://localhost/health", nil))
	}
	if resolver.calls != 2 || peerCalls != 0 || databaseReadinessCalls != 0 {
		t.Fatalf("lookups: local=%d peer=%d routing DB=%d", resolver.calls, peerCalls, databaseReadinessCalls)
	}
}
