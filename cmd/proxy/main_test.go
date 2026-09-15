package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
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
