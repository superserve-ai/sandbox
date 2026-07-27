package vm

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
			PreviewPorts:  map[int32]struct{}{3000: {}},
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
}
