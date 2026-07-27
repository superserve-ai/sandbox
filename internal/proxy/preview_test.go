package proxy

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/auth"
	"github.com/superserve-ai/sandbox/internal/preview"
)

func enforcePreviewForTest(w http.ResponseWriter, port int, info InstanceInfo) bool {
	req := httptest.NewRequest(http.MethodGet, "http://unused/", nil)
	return enforcePreviewPublication(w, req, "66ca164d-964b-43da-b81a-004d51598d6a", port, info, nil)
}

func TestPreviewPublicationLegacyAllowsAnyPort(t *testing.T) {
	for _, access := range []string{"", preview.AccessLegacyPublic} {
		w := httptest.NewRecorder()
		if !enforcePreviewForTest(w, 3000, InstanceInfo{
			PreviewAccess:     access,
			PreviewPorts:      map[int]struct{}{3001: {}},
			PreviewPortAccess: map[int]string{3001: preview.AccessPrivate},
		}) {
			t.Fatalf("access %q denied a legacy port", access)
		}
	}
}

func TestPreviewPublicationLegacyHonorsExactNonPublicRecord(t *testing.T) {
	for _, mode := range []string{preview.AccessPrivate, "future-mode"} {
		w := httptest.NewRecorder()
		if enforcePreviewForTest(w, 3000, InstanceInfo{
			PreviewAccess:     preview.AccessLegacyPublic,
			PreviewPorts:      map[int]struct{}{3000: {}},
			PreviewPortAccess: map[int]string{3000: mode},
		}) {
			t.Fatalf("legacy snapshot routed exact %q port", mode)
		}
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("mode %q status = %d, want 401", mode, w.Code)
		}
	}
}

func TestPreviewPublicationStrictRequiresPublishedPort(t *testing.T) {
	info := InstanceInfo{
		PreviewAccess:     preview.AccessPublic,
		PreviewPorts:      map[int]struct{}{3001: {}},
		PreviewPortAccess: map[int]string{3001: preview.AccessPublic},
	}
	w := httptest.NewRecorder()
	if enforcePreviewForTest(w, 3000, info) {
		t.Fatal("unpublished port was allowed")
	}
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}

	w = httptest.NewRecorder()
	if !enforcePreviewForTest(w, 3001, info) {
		t.Fatalf("published public port denied with status %d", w.Code)
	}
}

func TestPreviewPublicationPerPortModes(t *testing.T) {
	info := InstanceInfo{
		// The hardened rollback fallback is private for a mixed policy, but the
		// Phase 2 proxy still honors each explicit per-port exception.
		PreviewAccess: preview.AccessPrivate,
		PreviewPorts:  map[int]struct{}{3000: {}, 3001: {}, 3002: {}, 3003: {}},
		PreviewPortAccess: map[int]string{
			3000: preview.AccessPublic,
			3001: preview.AccessPrivate,
			3002: "future-mode",
		},
	}

	w := httptest.NewRecorder()
	if !enforcePreviewForTest(w, 3000, info) {
		t.Fatalf("explicit public port denied with status %d", w.Code)
	}
	for _, port := range []int{3001, 3002, 3003} {
		w = httptest.NewRecorder()
		if enforcePreviewForTest(w, port, info) {
			t.Fatalf("port %d unexpectedly routed", port)
		}
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("port %d status = %d, want 401", port, w.Code)
		}
	}
}

func TestPreviewPublicationUnknownPolicyFailsClosedEvenWhenPublished(t *testing.T) {
	w := httptest.NewRecorder()
	info := InstanceInfo{
		PreviewAccess:     "future-mode",
		PreviewPorts:      map[int]struct{}{3000: {}},
		PreviewPortAccess: map[int]string{3000: preview.AccessPublic},
	}
	if enforcePreviewForTest(w, 3000, info) {
		t.Fatal("unknown policy routed a published port")
	}
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestPreviewHeaderTokenAuthenticationMatrix(t *testing.T) {
	const (
		sandboxID = "66ca164d-964b-43da-b81a-004d51598d6a"
		otherID   = "bc8d5bbb-a259-43a4-8fb3-9a5167d5b43a"
		port      = 3000
		version   = int64(7)
	)
	seed := []byte("preview-test-seed-that-is-at-least-thirty-two-bytes")
	mint := func(claims auth.PreviewClaims) string {
		t.Helper()
		token, err := auth.ComputePreviewToken(seed, claims)
		if err != nil {
			t.Fatalf("ComputePreviewToken: %v", err)
		}
		return token
	}
	valid := mint(auth.PreviewClaims{SandboxID: sandboxID, Port: port, Version: version})
	wrongSandbox := mint(auth.PreviewClaims{SandboxID: otherID, Port: port, Version: version})
	wrongPort := mint(auth.PreviewClaims{SandboxID: sandboxID, Port: port + 1, Version: version})
	wrongVersion := mint(auth.PreviewClaims{SandboxID: sandboxID, Port: port, Version: version + 1})
	expired := mint(auth.PreviewClaims{
		SandboxID: sandboxID, Port: port, Version: version, ExpiresAt: time.Now().Add(-time.Second).Unix(),
	})
	tamperedSuffix := "A"
	if valid[len(valid)-1] == 'A' {
		tamperedSuffix = "B"
	}
	tampered := valid[:len(valid)-1] + tamperedSuffix

	tokenized := InstanceInfo{
		PreviewAccess:            preview.AccessPrivate,
		PreviewPorts:             map[int]struct{}{port: {}},
		PreviewPortAccess:        map[int]string{port: preview.AccessPrivateTokenV1},
		PreviewPortTokenVersions: map[int]int64{port: version},
	}

	tests := []struct {
		name   string
		info   InstanceInfo
		seed   []byte
		values []string
		want   bool
	}{
		{name: "correct", info: tokenized, seed: seed, values: []string{valid}, want: true},
		{name: "missing", info: tokenized, seed: seed},
		{name: "missing seed", info: tokenized, values: []string{valid}},
		{name: "wrong sandbox", info: tokenized, seed: seed, values: []string{wrongSandbox}},
		{name: "wrong port", info: tokenized, seed: seed, values: []string{wrongPort}},
		{name: "wrong version", info: tokenized, seed: seed, values: []string{wrongVersion}},
		{name: "expired", info: tokenized, seed: seed, values: []string{expired}},
		{name: "tampered", info: tokenized, seed: seed, values: []string{tampered}},
		{name: "multiple including valid", info: tokenized, seed: seed, values: []string{valid, "malformed"}},
		{name: "sentinel zero version", info: InstanceInfo{
			PreviewAccess:     preview.AccessPrivate,
			PreviewPorts:      map[int]struct{}{port: {}},
			PreviewPortAccess: map[int]string{port: preview.AccessPrivateTokenV1},
		}, seed: seed, values: []string{valid}},
		{name: "raw private remains closed", info: InstanceInfo{
			PreviewAccess:            preview.AccessPrivate,
			PreviewPorts:             map[int]struct{}{port: {}},
			PreviewPortAccess:        map[int]string{port: preview.AccessPrivate},
			PreviewPortTokenVersions: map[int]int64{port: version},
		}, seed: seed, values: []string{valid}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://unused/", nil)
			for _, value := range tt.values {
				req.Header.Add(auth.PreviewTokenHeader, value)
			}
			w := httptest.NewRecorder()
			got := enforcePreviewPublication(w, req, sandboxID, port, tt.info, tt.seed)
			if got != tt.want {
				t.Fatalf("allowed = %v, want %v; status=%d body=%q", got, tt.want, w.Code, w.Body.String())
			}
			if !tt.want && w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", w.Code)
			}
		})
	}
}

func TestPreviewTokenOnlyBypassesGenuineCORSPreflight(t *testing.T) {
	const sandboxID = "66ca164d-964b-43da-b81a-004d51598d6a"
	seed := []byte("preview-test-seed-that-is-at-least-thirty-two-bytes")
	info := InstanceInfo{
		PreviewAccess:            preview.AccessPrivate,
		PreviewPorts:             map[int]struct{}{3000: {}},
		PreviewPortAccess:        map[int]string{3000: preview.AccessPrivateTokenV1},
		PreviewPortTokenVersions: map[int]int64{3000: 1},
	}
	tests := []struct {
		name   string
		origin string
		acrm   string
		want   bool
	}{
		{name: "real preflight", origin: "https://console.example", acrm: http.MethodGet, want: true},
		{name: "plain options"},
		{name: "origin only", origin: "https://console.example"},
		{name: "request method only", acrm: http.MethodGet},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodOptions, "http://unused/", nil)
			req.Header.Set("Origin", tt.origin)
			req.Header.Set("Access-Control-Request-Method", tt.acrm)
			w := httptest.NewRecorder()
			if got := enforcePreviewPublication(w, req, sandboxID, 3000, info, seed); got != tt.want {
				t.Fatalf("allowed = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPreviewCredentialHeaderIsScrubbedBeforePublicAndPrivateUpstreams(t *testing.T) {
	const sandboxID = "66ca164d-964b-43da-b81a-004d51598d6a"
	seed := []byte("preview-test-seed-that-is-at-least-thirty-two-bytes")
	received := make(chan http.Header, 2)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	port := upstream.Listener.Addr().(*net.TCPAddr).Port

	resolver := &stubResolver{}
	handler := NewHandler([]string{"sandbox.test"}, resolver, zerolog.Nop()).WithAuth(seed)
	request := func(info InstanceInfo, tokenValues ...string) {
		t.Helper()
		resolver.info = info
		req := httptest.NewRequest(http.MethodGet, "http://unused/", nil)
		req.Host = fmt.Sprintf("%d-%s.sandbox.test", port, sandboxID)
		for _, value := range tokenValues {
			req.Header.Add(auth.PreviewTokenHeader, value)
		}
		// Direct map insertion exercises differently-cased entries too.
		req.Header["x-superserve-preview-token"] = append(req.Header["x-superserve-preview-token"], "must-not-leak")
		if len(tokenValues) != 0 {
			// The differently-cased extra value would intentionally make private
			// auth ambiguous, so remove it until after auth via a public request.
			delete(req.Header, "x-superserve-preview-token")
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204; body=%q", w.Code, w.Body.String())
		}
		headers := <-received
		if values := headerValues(headers, auth.PreviewTokenHeader); len(values) != 0 {
			t.Fatalf("upstream received reserved header values %#v", values)
		}
	}

	request(InstanceInfo{
		VMIP: "127.0.0.1", Status: "running", StartedAt: 1,
		PreviewAccess:     preview.AccessPublic,
		PreviewPorts:      map[int]struct{}{port: {}},
		PreviewPortAccess: map[int]string{port: preview.AccessPublic},
	})
	token, err := auth.ComputePreviewToken(seed, auth.PreviewClaims{
		SandboxID: sandboxID, Port: port, Version: 3,
	})
	if err != nil {
		t.Fatalf("ComputePreviewToken: %v", err)
	}
	request(InstanceInfo{
		VMIP: "127.0.0.1", Status: "running", StartedAt: 1,
		PreviewAccess:            preview.AccessPrivate,
		PreviewPorts:             map[int]struct{}{port: {}},
		PreviewPortAccess:        map[int]string{port: preview.AccessPrivateTokenV1},
		PreviewPortTokenVersions: map[int]int64{port: 3},
	}, token)
}
