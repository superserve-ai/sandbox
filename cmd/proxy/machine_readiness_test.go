package main

import (
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
