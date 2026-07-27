package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

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
	}
	if !reflect.DeepEqual(health.Capabilities, want) {
		t.Fatalf("capabilities = %#v, want %#v", health.Capabilities, want)
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
