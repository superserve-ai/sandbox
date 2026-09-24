package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/preview"
	"github.com/superserve-ai/sandbox/internal/proxy"
)

func TestProxyHealthAdvertisesPreviewPortProtocol(t *testing.T) {
	h := proxy.NewHandler([]string{"sandbox.test"}, nil, zerolog.Nop())
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Host = "127.0.0.1:5007"

	newProxyMux(h).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	var health proxyHealthResponse
	if err := json.Unmarshal(w.Body.Bytes(), &health); err != nil {
		t.Fatalf("decode health response: %v", err)
	}
	want := []string{preview.HostCapabilityPorts, preview.HostCapabilityPortAccess}
	if !reflect.DeepEqual(health.Capabilities, want) {
		t.Fatalf("capabilities = %#v, want %#v", health.Capabilities, want)
	}
}

type listenerResolver struct{ calls int }

func (r *listenerResolver) Lookup(context.Context, string) (proxy.InstanceInfo, error) {
	r.calls++
	return proxy.InstanceInfo{}, proxy.ErrInstanceNotFound
}

func (*listenerResolver) Invalidate(string) {}

func TestDataPlaneListenerRoutingIsolation(t *testing.T) {
	domains := []string{"sandbox.test"}
	resolver := &listenerResolver{}
	local := proxy.NewHandler(domains, resolver, zerolog.Nop())
	ownershipCalls := 0
	ownership := proxy.RouteLookupFunc(func(context.Context, string) (proxy.SandboxRoute, error) {
		ownershipCalls++
		return proxy.SandboxRoute{}, errors.New("ownership unavailable")
	})
	router := proxy.NewRoutingHandler(domains, "host-a", ownership, nil, local, zerolog.Nop())
	publicMux, localMux := newDataPlaneMuxes(local, router, true)

	for _, tc := range []struct {
		name                     string
		handler                  http.Handler
		status, ownership, local int
	}{
		{"public", publicMux, http.StatusBadGateway, 1, 0},
		{"peer target", localMux, http.StatusNotFound, 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ownershipCalls, resolver.calls = 0, 0
			req := httptest.NewRequest(http.MethodGet, "http://8080-12345678-1234-1234-1234-123456789abc.sandbox.test/", nil)
			w := httptest.NewRecorder()
			tc.handler.ServeHTTP(w, req)
			if w.Code != tc.status {
				t.Fatalf("status = %d, want %d: %s", w.Code, tc.status, w.Body.String())
			}
			if ownershipCalls != tc.ownership || resolver.calls != tc.local {
				t.Fatalf("ownership/local lookups = %d/%d, want %d/%d", ownershipCalls, resolver.calls, tc.ownership, tc.local)
			}
		})
	}
}

func TestProxyHealthAdvertisesPreviewTokensOnlyWithAuthSeed(t *testing.T) {
	h := proxy.NewHandler([]string{"sandbox.test"}, nil, zerolog.Nop()).
		WithAuth([]byte("preview-test-seed-that-is-at-least-thirty-two-bytes"))
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Host = "127.0.0.1:5007"

	newProxyMux(h).ServeHTTP(w, req)

	var health proxyHealthResponse
	if err := json.Unmarshal(w.Body.Bytes(), &health); err != nil {
		t.Fatalf("decode health response: %v", err)
	}
	want := []string{
		preview.HostCapabilityPorts,
		preview.HostCapabilityPortAccess,
		preview.HostCapabilityPortTokens,
		preview.HostCapabilityPortBrowserAuth,
	}
	if !reflect.DeepEqual(health.Capabilities, want) {
		t.Fatalf("capabilities = %#v, want %#v", health.Capabilities, want)
	}
}

func TestProxyHealthReportsFilesEnabled(t *testing.T) {
	seed := []byte("preview-test-seed-that-is-at-least-thirty-two-bytes")
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[enabled], func(t *testing.T) {
			h := proxy.NewHandler([]string{"sandbox.test"}, nil, zerolog.Nop()).WithAuth(seed)
			if enabled {
				h.WithFiles()
			}
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/health", nil)
			req.Host = "127.0.0.1:5007"
			newProxyMux(h).ServeHTTP(w, req)
			var health proxyHealthResponse
			if err := json.Unmarshal(w.Body.Bytes(), &health); err != nil {
				t.Fatalf("decode health response: %v", err)
			}
			if health.FilesEnabled != enabled {
				t.Fatalf("files_enabled = %v, want %v", health.FilesEnabled, enabled)
			}
		})
	}
}

func TestProxyDomains(t *testing.T) {
	tests := []struct {
		name    string
		domains string // PROXY_DOMAINS
		domain  string // PROXY_DOMAIN
		want    []string
	}{
		{
			name: "default when nothing configured",
			want: []string{"sandbox.superserve.ai"},
		},
		{
			name:   "single PROXY_DOMAIN fallback",
			domain: "usw-sandbox.superserve.ai",
			want:   []string{"usw-sandbox.superserve.ai"},
		},
		{
			name:    "comma-separated list",
			domains: "sandbox.superserve.ai,usw-sandbox.superserve.ai",
			want:    []string{"sandbox.superserve.ai", "usw-sandbox.superserve.ai"},
		},
		{
			name:    "whitespace and empty entries tolerated",
			domains: " sandbox.superserve.ai , ,usw-sandbox.superserve.ai ",
			want:    []string{"sandbox.superserve.ai", "usw-sandbox.superserve.ai"},
		},
		{
			name:    "PROXY_DOMAINS wins over PROXY_DOMAIN",
			domains: "usw-sandbox.superserve.ai",
			domain:  "sandbox.superserve.ai",
			want:    []string{"usw-sandbox.superserve.ai"},
		},
		{
			name:    "blank PROXY_DOMAINS falls back",
			domains: " , ",
			domain:  "usw-sandbox.superserve.ai",
			want:    []string{"usw-sandbox.superserve.ai"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("PROXY_DOMAINS", tt.domains)
			t.Setenv("PROXY_DOMAIN", tt.domain)
			if got := proxyDomains(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("proxyDomains() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPeerIngressDisabledWithoutCredentials(t *testing.T) {
	if peerIngressEnabled("") {
		t.Fatal("peer ingress enabled without a listen address")
	}
}

func TestPeerIngressEnabledRequiresExplicitAddress(t *testing.T) {
	if !peerIngressEnabled("192.0.2.10:5008") {
		t.Fatal("peer ingress not enabled with an explicit listen address")
	}
}

func TestPeerTransportRequiredOnlyWhenParticipating(t *testing.T) {
	for _, tc := range []struct {
		name, routing, peerAddr string
		want                    bool
	}{
		{"legacy host routing disabled", "0", "", false},
		{"legacy host routing unset", "", "", false},
		{"outbound routing enabled", "1", "", true},
		{"peer ingress enabled", "0", "10.0.0.3:5009", true},
		{"routing and ingress enabled", "1", "10.0.0.3:5009", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := peerTransportRequired(tc.routing, tc.peerAddr); got != tc.want {
				t.Fatalf("peerTransportRequired(%q, %q) = %v, want %v", tc.routing, tc.peerAddr, got, tc.want)
			}
		})
	}
}

func TestPropagateRedirectErrorCancelsLifecycle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	report := make(chan error, 1)
	want := errors.New("redirect bind failed")

	propagateRedirectError(want, report, cancel)
	select {
	case <-ctx.Done():
	default:
		t.Fatal("redirect failure did not cancel the proxy lifecycle")
	}
	if got := <-report; !errors.Is(got, want) {
		t.Fatalf("reported redirect error = %v, want %v", got, want)
	}
}

func TestPropagateRedirectErrorIgnoresCleanShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	report := make(chan error, 1)

	propagateRedirectError(http.ErrServerClosed, report, cancel)
	select {
	case <-ctx.Done():
		t.Fatal("clean redirect shutdown canceled the proxy lifecycle")
	case err := <-report:
		t.Fatalf("clean redirect shutdown reported an error: %v", err)
	default:
	}
}

func TestLocalPeerTargetRejectsPublicAndRedirectListeners(t *testing.T) {
	for _, target := range []string{"0.0.0.0:5010", "192.0.2.1:5010", "[::]:5010", "127.0.0.1:0", "127.0.0.1:5007", "127.0.0.1:5008"} {
		t.Run(target, func(t *testing.T) {
			ln, err := bindLocalPeerTarget(target, ":5007", ":5008")
			if err == nil {
				ln.Close()
				t.Fatal("accepted non-local or shared peer target")
			}
		})
	}
}

func TestLocalPeerTargetServesLocalHandler(t *testing.T) {
	available, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := available.Addr().String()
	available.Close()
	ln, err := bindLocalPeerTarget(addr, ":5007", ":5008")
	if err != nil {
		t.Fatal(err)
	}
	h := proxy.NewHandler([]string{"sandbox.test"}, nil, zerolog.Nop())
	srv := proxy.NewServer(addr, newProxyMux(h))
	defer srv.Close()
	go func() { _ = srv.Serve(ln) }()
	client := &http.Client{Timeout: time.Second}
	resp, err := client.Get("http://" + addr + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var health proxyHealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || len(health.Capabilities) == 0 {
		t.Fatalf("local handler response = %d, %+v", resp.StatusCode, health)
	}
}

func TestPeerListenerRejectsPublicAndRedirectPorts(t *testing.T) {
	for _, tc := range []struct {
		peer, public, redirect string
		wantError              bool
	}{
		{"10.0.0.2:5010", ":5007", ":5008", true},
		{"10.0.0.2:5008", ":5007", ":5008", true},
		{"10.0.0.2:5007", ":5007", ":5008", true},
		{"10.0.0.2:5009", ":5007", ":05009", true},
		{"[fd00::2]:5008", "[::]:5007", "[::]:5008", true},
		{"10.0.0.2:5009", ":5007", ":5008", false},
	} {
		if err := validatePeerListener(tc.peer, tc.public, tc.redirect); (err != nil) != tc.wantError {
			t.Errorf("validatePeerListener(%q, %q, %q) = %v", tc.peer, tc.public, tc.redirect, err)
		}
	}
}

func TestReadinessIncludesImmutableGenerationAndDependencyFailure(t *testing.T) {
	t.Setenv("PROXY_GENERATION", "generation-one")
	handler := proxy.NewHandler([]string{"sandbox.test"}, nil, zerolog.Nop())
	mux := newProxyMuxWithReadiness(handler, handler, func(context.Context) bool { return false })
	t.Setenv("PROXY_GENERATION", "generation-two")
	request := httptest.NewRequest(http.MethodGet, "http://proxy-readiness.invalid/health", nil)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d", response.Code)
	}
	var body proxyHealthResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Generation != "generation-one" || body.ResolverReady {
		t.Fatalf("unexpected readiness: %+v", body)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("readiness must not be cached")
	}
}

func TestBareDomainReadinessPreservesPreviewAndRedirectRouting(t *testing.T) {
	t.Setenv("PROXY_GENERATION", "generation-one")
	handler := proxy.NewHandler([]string{"east.example.test"}, nil, zerolog.Nop())
	dataPlane := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})
	mux := newProxyMuxWithReadiness(handler, dataPlane, nil)
	redirect := newRedirectMux(handler, mux)
	request := httptest.NewRequest(http.MethodGet, "http://east.example.test/health", nil)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	var body proxyHealthResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("bare domain health did not reach readiness: %v", err)
	}
	if body.Generation != "generation-one" || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Proxy-Resolver-Ready") != "false" {
		t.Fatalf("wrong readiness response: %s", response.Body.String())
	}
	for _, resolverReady := range []bool{false, true} {
		// The readiness handler includes all enabled resolver dependencies.
		readiness := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Proxy-Generation", "generation-one")
			w.Header().Set("X-Proxy-Resolver-Ready", strconv.FormatBool(resolverReady))
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			if !resolverReady {
				w.WriteHeader(http.StatusServiceUnavailable)
			}
			_, _ = w.Write([]byte(`{"resolver_ready":true}`))
		})
		redirect := newRedirectMux(handler, readiness)
		request := httptest.NewRequest(http.MethodGet, "http://east.example.test/health", nil)
		response := httptest.NewRecorder()
		redirect.ServeHTTP(response, request)
		if response.Code != http.StatusMovedPermanently || response.Header().Get("Location") != "https://east.example.test/health" {
			t.Fatalf("bare domain redirect changed: %d, %s", response.Code, response.Header().Get("Location"))
		}
		if response.Header().Get("X-Proxy-Generation") != "generation-one" || response.Header().Get("X-Proxy-Resolver-Ready") != strconv.FormatBool(resolverReady) {
			t.Fatalf("missing redirect readiness: %v", response.Header())
		}
		response = httptest.NewRecorder()
		redirect.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://proxy-readiness.invalid/health", nil))
		if !resolverReady && response.Code != http.StatusServiceUnavailable {
			t.Fatalf("LB health bypassed failed readiness: %d", response.Code)
		}
	}
	request = httptest.NewRequest(http.MethodGet, "http://preview.east.example.test/health", nil)
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("preview health bypassed data plane: %d", response.Code)
	}
	response = httptest.NewRecorder()
	redirect.ServeHTTP(response, request)
	if response.Code != http.StatusMovedPermanently || response.Header().Get("Location") != "https://preview.east.example.test/health" {
		t.Fatalf("preview redirect changed: %d, %s", response.Code, response.Header().Get("Location"))
	}
}

func TestBareDomainReadinessConfiguredStagingAndProductionForms(t *testing.T) {
	for _, domain := range []string{"staging.example.test", "production.example.test"} {
		t.Run(domain, func(t *testing.T) {
			t.Setenv("PROXY_GENERATION", "generation-one")
			handler := proxy.NewHandler([]string{domain}, nil, zerolog.Nop())
			dataPlane := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusAccepted)
			})
			mux := newProxyMuxWithReadiness(handler, dataPlane, nil)
			redirect := newRedirectMux(handler, mux)

			response := httptest.NewRecorder()
			mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet,
				"https://"+domain+"/health", nil))
			if response.Code != http.StatusOK || response.Header().Get("X-Proxy-Generation") != "generation-one" ||
				response.Header().Get("X-Proxy-Resolver-Ready") != "false" {
				t.Fatalf("bare HTTPS readiness = %d, headers=%v", response.Code, response.Header())
			}

			response = httptest.NewRecorder()
			redirect.ServeHTTP(response, httptest.NewRequest(http.MethodGet,
				"http://"+domain+"/health", nil))
			if response.Code != http.StatusMovedPermanently ||
				response.Header().Get("Location") != "https://"+domain+"/health" ||
				response.Header().Get("X-Proxy-Generation") != "generation-one" ||
				response.Header().Get("X-Proxy-Resolver-Ready") != "false" {
				t.Fatalf("bare HTTP readiness redirect = %d, headers=%v", response.Code, response.Header())
			}

			preview := "preview." + domain
			response = httptest.NewRecorder()
			mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet,
				"https://"+preview+"/health", nil))
			if response.Code != http.StatusAccepted || response.Header().Get("X-Proxy-Generation") != "" {
				t.Fatalf("preview HTTPS route was treated as infrastructure readiness: %d, headers=%v",
					response.Code, response.Header())
			}
		})
	}
}
