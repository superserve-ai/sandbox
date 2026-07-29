package vm

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/preview"
)

func TestLocalHTTPRequiresProxyProtocolForStrictInstance(t *testing.T) {
	mgr := &Manager{vms: map[string]*VMInstance{
		"legacy-empty": {
			ID: "legacy-empty", Status: StatusRunning, IP: "10.0.0.2", CreatedAt: time.Unix(1, 0),
		},
		"legacy-explicit": {
			ID: "legacy-explicit", Status: StatusRunning, IP: "10.0.0.3", CreatedAt: time.Unix(2, 0),
			PreviewAccess: preview.AccessLegacyPublic,
		},
		"strict": {
			ID: "strict", Status: StatusRunning, IP: "10.0.0.4", CreatedAt: time.Unix(3, 0),
			PreviewAccess: preview.AccessPublic,
			PreviewPorts:  map[int32]PreviewPortPolicy{3000: {Access: preview.AccessPublic}},
		},
		"mixed": {
			ID: "mixed", Status: StatusRunning, IP: "10.0.0.5", CreatedAt: time.Unix(4, 0),
			// Restrictive rollback fallback plus an explicit-public exception.
			PreviewAccess: preview.AccessPrivate,
			PreviewPorts: map[int32]PreviewPortPolicy{
				3000: {Access: preview.AccessPublic},
				3001: {Access: preview.AccessPrivate},
			},
		},
		"legacy-inconsistent": {
			ID: "legacy-inconsistent", Status: StatusRunning, IP: "10.0.0.6", CreatedAt: time.Unix(5, 0),
			PreviewAccess: preview.AccessLegacyPublic,
			PreviewPorts: map[int32]PreviewPortPolicy{
				3000: {Access: preview.AccessPrivate},
			},
		},
		"tokenized": {
			ID: "tokenized", Status: StatusRunning, IP: "10.0.0.7", CreatedAt: time.Unix(6, 0),
			PreviewAccess: preview.AccessPrivate,
			PreviewPorts: map[int32]PreviewPortPolicy{
				3000: {Access: preview.AccessPrivateTokenV1, TokenVersion: 9},
			},
			PreviewPolicyRevision: 12, PreviewTokenPolicyRevision: 12,
		},
	}}
	srv := NewLocalHTTPServer(mgr, zerolog.Nop())

	for _, instanceID := range []string{"legacy-empty", "legacy-explicit"} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/instances/"+instanceID, nil)
		srv.handleInstance(w, req) // old proxy: no protocol marker
		if w.Code != http.StatusOK {
			t.Fatalf("legacy instance %q status = %d, want 200", instanceID, w.Code)
		}
		if got := w.Header().Get(preview.VMDProtocolHeader); got != preview.HostCapabilityPorts {
			t.Fatalf("legacy instance %q %s = %q, want %q", instanceID, preview.VMDProtocolHeader, got, preview.HostCapabilityPorts)
		}
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/instances/strict", nil)
	srv.handleInstance(w, req) // old proxy: fail closed
	if w.Code != http.StatusNotFound {
		t.Fatalf("unmarked strict lookup status = %d, want 404", w.Code)
	}
	if got := w.Header().Get(preview.VMDProtocolHeader); got != "" {
		t.Fatalf("rejected strict lookup attested protocol with %q", got)
	}

	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/instances/strict", nil)
	req.Header.Set(preview.ProxyProtocolHeader, preview.HostCapabilityPorts)
	srv.handleInstance(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("marked strict lookup status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get(preview.VMDProtocolHeader); got != preview.HostCapabilityPorts {
		t.Fatalf("strict lookup %s = %q, want %q", preview.VMDProtocolHeader, got, preview.HostCapabilityPorts)
	}
	var got instanceResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode strict response: %v", err)
	}
	if got.PreviewAccess != preview.AccessPublic || !got.PreviewPorts["3000"] {
		t.Fatalf("strict response = %#v", got)
	}

	// A Phase 1 proxy carries only the exact base marker and must not receive a
	// mixed/private policy whose parallel map it would ignore.
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/instances/mixed", nil)
	req.Header.Set(preview.ProxyProtocolHeader, preview.HostCapabilityPorts)
	srv.handleInstance(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("old proxy mixed lookup status = %d, want 404", w.Code)
	}

	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/instances/mixed", nil)
	req.Header.Set(preview.ProxyProtocolHeader, preview.HostCapabilityPorts)
	req.Header.Set(preview.ProxyCapabilitiesHeader, preview.HostCapabilityPortAccess)
	srv.handleInstance(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("phase2 mixed lookup status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode mixed response: %v", err)
	}
	if got.PreviewAccess != preview.AccessPrivate || !got.PreviewPorts["3000"] ||
		got.PreviewPortAccess["3000"] != preview.AccessPublic || got.PreviewPortAccess["3001"] != preview.AccessPrivate {
		t.Fatalf("mixed response = %#v", got)
	}

	// Lookup defensively scans the ports before returning a legacy/empty mode.
	// This covers an inconsistent control-plane snapshot during rollback: a new
	// proxy may see the record, but it must see a private fallback, never legacy.
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/instances/legacy-inconsistent", nil)
	req.Header.Set(preview.ProxyProtocolHeader, preview.HostCapabilityPorts)
	req.Header.Set(preview.ProxyCapabilitiesHeader, preview.HostCapabilityPortAccess)
	srv.handleInstance(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("inconsistent legacy lookup status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode inconsistent legacy response: %v", err)
	}
	if got.PreviewAccess != preview.AccessPrivate {
		t.Fatalf("inconsistent legacy fallback = %q, want private", got.PreviewAccess)
	}

	// A Phase 2 proxy cannot receive a tokenized snapshot or its generations.
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/instances/tokenized", nil)
	req.Header.Set(preview.ProxyProtocolHeader, preview.HostCapabilityPorts)
	req.Header.Set(preview.ProxyCapabilitiesHeader, preview.HostCapabilityPortAccess)
	srv.handleInstance(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("phase2 tokenized lookup status = %d, want 404", w.Code)
	}

	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/instances/tokenized", nil)
	req.Header.Set(preview.ProxyProtocolHeader, preview.HostCapabilityPorts)
	req.Header.Set(preview.ProxyCapabilitiesHeader,
		preview.HostCapabilityPortAccess+", "+preview.HostCapabilityPortTokens)
	srv.handleInstance(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("phase3 tokenized lookup status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode tokenized response: %v", err)
	}
	if got.PreviewPortAccess["3000"] != preview.AccessPrivateTokenV1 ||
		got.PreviewPortTokenVersions["3000"] != 9 {
		t.Fatalf("tokenized response = %#v", got)
	}
}

func TestLocalHTTPRequiresCompleteBrowserProxyCapabilities(t *testing.T) {
	const browserPort = int32(4173)
	mgr := &Manager{vms: map[string]*VMInstance{
		"browser": {
			ID: "browser", Status: StatusRunning, IP: "10.0.0.8", CreatedAt: time.Unix(7, 0),
			PreviewAccess: preview.AccessPrivate,
			PreviewPorts: map[int32]PreviewPortPolicy{
				browserPort: {Access: preview.AccessPrivateBrowserV1, TokenVersion: 11},
			},
			PreviewPolicyRevision: 14, PreviewTokenPolicyRevision: 14,
		},
	}}
	srv := NewLocalHTTPServer(mgr, zerolog.Nop())

	tests := []struct {
		name string
		caps []string
		want int
	}{
		{name: "no additive capabilities", want: http.StatusNotFound},
		{name: "access only", caps: []string{preview.HostCapabilityPortAccess}, want: http.StatusNotFound},
		{name: "tokens only", caps: []string{preview.HostCapabilityPortTokens}, want: http.StatusNotFound},
		{name: "browser only", caps: []string{preview.HostCapabilityPortBrowserAuth}, want: http.StatusNotFound},
		{name: "access and tokens phase3 rollback", caps: []string{preview.HostCapabilityPortAccess, preview.HostCapabilityPortTokens}, want: http.StatusNotFound},
		{name: "access and browser without tokens", caps: []string{preview.HostCapabilityPortAccess, preview.HostCapabilityPortBrowserAuth}, want: http.StatusNotFound},
		{name: "tokens and browser without access", caps: []string{preview.HostCapabilityPortTokens, preview.HostCapabilityPortBrowserAuth}, want: http.StatusNotFound},
		{name: "complete phase4 chain", caps: []string{preview.HostCapabilityPortBrowserAuth, preview.HostCapabilityPortTokens, preview.HostCapabilityPortAccess}, want: http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/instances/browser", nil)
			req.Header.Set(preview.ProxyProtocolHeader, preview.HostCapabilityPorts)
			req.Header.Set(preview.ProxyCapabilitiesHeader, strings.Join(tt.caps, ", "))
			srv.handleInstance(w, req)
			if w.Code != tt.want {
				t.Fatalf("status = %d, want %d; body: %s", w.Code, tt.want, w.Body.String())
			}
			if tt.want != http.StatusOK {
				if got := w.Header().Get(preview.VMDProtocolHeader); got != "" {
					t.Fatalf("rejected browser lookup attested protocol with %q", got)
				}
				return
			}

			var got instanceResponse
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatalf("decode browser response: %v", err)
			}
			port := strconv.Itoa(int(browserPort))
			if got.PreviewPortAccess[port] != preview.AccessPrivateBrowserV1 ||
				got.PreviewPortTokenVersions[port] != 11 {
				t.Fatalf("browser response = %#v", got)
			}
		})
	}
}
