package proxy

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/auth"
	"github.com/superserve-ai/sandbox/internal/preview"
)

func enforcePreviewForTest(w http.ResponseWriter, port int, info InstanceInfo) bool {
	req := httptest.NewRequest(http.MethodGet, "http://unused/", nil)
	return enforcePreviewPublication(w, req, "66ca164d-964b-43da-b81a-004d51598d6a", port, info, nil, false)
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
		{name: "comma-coalesced including valid", info: tokenized, seed: seed, values: []string{"stale, " + valid}},
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
			got := enforcePreviewPublication(w, req, sandboxID, port, tt.info, tt.seed, false)
			if got != tt.want {
				t.Fatalf("allowed = %v, want %v; status=%d body=%q", got, tt.want, w.Code, w.Body.String())
			}
			if !tt.want && w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", w.Code)
			}
		})
	}
}

func TestPreviewTokenOnlyHandlesGenuineCORSPreflightLocally(t *testing.T) {
	const sandboxID = "66ca164d-964b-43da-b81a-004d51598d6a"
	seed := []byte("preview-test-seed-that-is-at-least-thirty-two-bytes")
	info := InstanceInfo{
		PreviewAccess:            preview.AccessPrivate,
		PreviewPorts:             map[int]struct{}{3000: {}},
		PreviewPortAccess:        map[int]string{3000: preview.AccessPrivateTokenV1},
		PreviewPortTokenVersions: map[int]int64{3000: 1},
	}
	tests := []struct {
		name          string
		origin        string
		acrm          string
		originAllowed bool
		wantStatus    int
	}{
		{name: "allowed preflight", origin: "https://console.example", acrm: http.MethodGet, originAllowed: true, wantStatus: http.StatusNoContent},
		{name: "disallowed preflight", origin: "https://attacker.example", acrm: http.MethodGet, wantStatus: http.StatusUnauthorized},
		{name: "plain options", wantStatus: http.StatusUnauthorized},
		{name: "origin only", origin: "https://console.example", wantStatus: http.StatusUnauthorized},
		{name: "request method only", acrm: http.MethodGet, wantStatus: http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodOptions, "http://unused/", nil)
			req.Header.Set("Origin", tt.origin)
			req.Header.Set("Access-Control-Request-Method", tt.acrm)
			req.Header.Set("Access-Control-Request-Headers", auth.PreviewTokenHeader+", Content-Type")
			w := httptest.NewRecorder()
			if got := enforcePreviewPublication(w, req, sandboxID, 3000, info, seed, tt.originAllowed); got {
				t.Fatal("preflight or unauthenticated OPTIONS request was forwarded")
			}
			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", w.Code, tt.wantStatus)
			}
			if tt.wantStatus == http.StatusNoContent {
				assertPrivatePreviewPreflightResponse(t, w, req)
			}
		})
	}
}

func assertPrivatePreviewPreflightResponse(t *testing.T, w *httptest.ResponseRecorder, req *http.Request) {
	t.Helper()
	for name, want := range map[string]string{
		"Access-Control-Allow-Origin":      req.Header.Get("Origin"),
		"Access-Control-Allow-Methods":     req.Header.Get("Access-Control-Request-Method"),
		"Access-Control-Allow-Headers":     req.Header.Get("Access-Control-Request-Headers"),
		"Access-Control-Allow-Credentials": "true",
		"Access-Control-Max-Age":           "600",
	} {
		if got := w.Header().Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	vary := strings.Join(w.Header().Values("Vary"), ", ")
	for _, want := range []string{"Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers"} {
		if !strings.Contains(vary, want) {
			t.Errorf("Vary = %q, want %q", vary, want)
		}
	}
	if w.Body.Len() != 0 {
		t.Errorf("preflight body = %q, want empty", w.Body.String())
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

func browserPreviewTestPolicy(port int, version int64) InstanceInfo {
	return InstanceInfo{
		PreviewAccess:            preview.AccessPrivate,
		PreviewPorts:             map[int]struct{}{port: {}},
		PreviewPortAccess:        map[int]string{port: preview.AccessPrivateBrowserV1},
		PreviewPortTokenVersions: map[int]int64{port: version},
	}
}

func mintPreviewTestToken(t *testing.T, seed []byte, sandboxID string, port int, version int64) string {
	t.Helper()
	token, err := auth.ComputePreviewToken(seed, auth.PreviewClaims{
		SandboxID: sandboxID,
		Port:      port,
		Version:   version,
	})
	if err != nil {
		t.Fatalf("ComputePreviewToken: %v", err)
	}
	return token
}

func TestPreviewBrowserSentinelAcceptsIndependentCarrierValues(t *testing.T) {
	const (
		sandboxID = "66ca164d-964b-43da-b81a-004d51598d6a"
		port      = 3000
		version   = int64(7)
	)
	seed := []byte("preview-test-seed-that-is-at-least-thirty-two-bytes")
	valid := mintPreviewTestToken(t, seed, sandboxID, port, version)
	info := browserPreviewTestPolicy(port, version)

	tests := []struct {
		name  string
		build func(*http.Request)
	}{
		{name: "header after stale header", build: func(r *http.Request) {
			r.Header.Add(auth.PreviewTokenHeader, "stale")
			r.Header.Add(auth.PreviewTokenHeader, valid)
		}},
		{name: "header after stale comma-coalesced value", build: func(r *http.Request) {
			r.Header.Set(auth.PreviewTokenHeader, "stale, "+valid)
		}},
		{name: "cookie after malformed and stale cookie", build: func(r *http.Request) {
			r.Header.Add("Cookie", "malformed; "+auth.PreviewTokenCookie+"=stale; "+auth.PreviewTokenCookie+"="+valid)
		}},
		{name: "query after stale query", build: func(r *http.Request) {
			r.URL.RawQuery = auth.PreviewTokenQueryParam + "=stale&" + auth.PreviewTokenQueryParam + "=" + url.QueryEscape(valid)
		}},
		{name: "fresh cookie despite stale header", build: func(r *http.Request) {
			r.Header.Set(auth.PreviewTokenHeader, "stale")
			r.Header.Add("Cookie", auth.PreviewTokenCookie+"="+valid)
		}},
		{name: "fresh query despite stale cookie", build: func(r *http.Request) {
			r.Header.Add("Cookie", auth.PreviewTokenCookie+"=stale")
			r.URL.RawQuery = auth.PreviewTokenQueryParam + "=" + url.QueryEscape(valid)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// POST exercises direct query acceptance rather than the GET
			// bootstrap, which is covered separately below.
			req := httptest.NewRequest(http.MethodPost, "http://unused/path", nil)
			tt.build(req)
			w := httptest.NewRecorder()
			if !enforcePreviewPublication(w, req, sandboxID, port, info, seed, false) {
				t.Fatalf("browser carrier denied: status=%d body=%q", w.Code, w.Body.String())
			}
		})
	}
}

func TestPreviewBrowserSentinelDoesNotWeakenPhaseThreeCarrierBoundary(t *testing.T) {
	const (
		sandboxID = "66ca164d-964b-43da-b81a-004d51598d6a"
		port      = 3000
		version   = int64(7)
	)
	seed := []byte("preview-test-seed-that-is-at-least-thirty-two-bytes")
	valid := mintPreviewTestToken(t, seed, sandboxID, port, version)
	phaseThree := InstanceInfo{
		PreviewAccess:            preview.AccessPrivate,
		PreviewPorts:             map[int]struct{}{port: {}},
		PreviewPortAccess:        map[int]string{port: preview.AccessPrivateTokenV1},
		PreviewPortTokenVersions: map[int]int64{port: version},
	}

	for _, carrier := range []string{"cookie", "query"} {
		t.Run(carrier, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "http://unused/path", nil)
			if carrier == "cookie" {
				req.Header.Add("Cookie", auth.PreviewTokenCookie+"="+valid)
			} else {
				req.URL.RawQuery = auth.PreviewTokenQueryParam + "=" + url.QueryEscape(valid)
			}
			w := httptest.NewRecorder()
			if enforcePreviewPublication(w, req, sandboxID, port, phaseThree, seed, false) {
				t.Fatalf("Phase 3 sentinel accepted %s carrier", carrier)
			}
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", w.Code)
			}
		})
	}

	// A browser sentinel with no exact generation is also closed.
	info := browserPreviewTestPolicy(port, 0)
	req := httptest.NewRequest(http.MethodGet, "http://unused/path", nil)
	req.Header.Set(auth.PreviewTokenHeader, valid)
	w := httptest.NewRecorder()
	if enforcePreviewPublication(w, req, sandboxID, port, info, seed, false) || w.Code != http.StatusUnauthorized {
		t.Fatalf("zero-generation browser policy = allowed/status %d", w.Code)
	}
}

func TestPreviewBrowserQueryBootstrapIsSecureAndSameOrigin(t *testing.T) {
	const (
		sandboxID = "66ca164d-964b-43da-b81a-004d51598d6a"
		port      = 3000
		version   = int64(7)
	)
	seed := []byte("preview-test-seed-that-is-at-least-thirty-two-bytes")
	valid := mintPreviewTestToken(t, seed, sandboxID, port, version)
	info := browserPreviewTestPolicy(port, version)

	req := httptest.NewRequest(http.MethodGet, "http://unused/", nil)
	req.Host = "3000-" + sandboxID + ".sandbox.test"
	// A signed query must bootstrap even when another carrier already
	// authenticates the request, otherwise the live token remains in browser
	// history and referrers.
	req.Header.Set(auth.PreviewTokenHeader, valid)
	req.Header.Add("Cookie", auth.PreviewTokenCookie+"="+valid)
	// A double-slash path would turn the old relative Location into a
	// network-path redirect. Raw unrelated query bytes must not be normalized.
	req.URL.Path = "//evil.example/dash"
	req.URL.RawPath = "//evil.example/%64ash"
	req.URL.RawQuery = "keep=%2f&" + auth.PreviewTokenQueryParam + "=stale&space=a+b&" +
		"superserve%5fpreview_token=" + url.QueryEscape(valid) + "&bad=%zz"
	w := httptest.NewRecorder()
	if enforcePreviewPublication(w, req, sandboxID, port, info, seed, false) {
		t.Fatal("bootstrap request was forwarded instead of redirected")
	}
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body=%q", w.Code, w.Body.String())
	}

	location, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if location.Scheme != "https" || location.Host != req.Host || location.Path != "//evil.example/dash" {
		t.Fatalf("unsafe redirect Location = %q", location.String())
	}
	if location.RawPath != req.URL.RawPath {
		t.Fatalf("redirect raw path = %q, want %q", location.RawPath, req.URL.RawPath)
	}
	if location.RawQuery != "keep=%2f&space=a+b&bad=%zz" {
		t.Fatalf("redirect query = %q, want raw unrelated values preserved", location.RawQuery)
	}
	if strings.Contains(w.Header().Get("Location"), valid) || strings.Contains(w.Header().Get("Location"), auth.PreviewTokenQueryParam) {
		t.Fatalf("redirect retained preview credential: %q", w.Header().Get("Location"))
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("bootstrap security headers = Cache-Control %q Referrer-Policy %q", w.Header().Get("Cache-Control"), w.Header().Get("Referrer-Policy"))
	}

	setCookie, err := http.ParseSetCookie(w.Header().Get("Set-Cookie"))
	if err != nil {
		t.Fatalf("ParseSetCookie: %v", err)
	}
	if setCookie.Name != auth.PreviewTokenCookie || setCookie.Value != valid || setCookie.Path != "/" ||
		!setCookie.Secure || !setCookie.HttpOnly || setCookie.SameSite != http.SameSiteNoneMode ||
		!setCookie.Partitioned || setCookie.Domain != "" {
		t.Fatalf("bootstrap cookie is not host-only/secure: %+v", setCookie)
	}
}

func TestPreviewBrowserQueryBootstrapRejectsInvalidTokenWithoutCookie(t *testing.T) {
	const sandboxID = "66ca164d-964b-43da-b81a-004d51598d6a"
	seed := []byte("preview-test-seed-that-is-at-least-thirty-two-bytes")
	req := httptest.NewRequest(http.MethodGet, "http://unused/?"+auth.PreviewTokenQueryParam+"=invalid", nil)
	w := httptest.NewRecorder()
	if enforcePreviewPublication(w, req, sandboxID, 3000, browserPreviewTestPolicy(3000, 1), seed, false) {
		t.Fatal("invalid signed link was allowed")
	}
	if w.Code != http.StatusUnauthorized || w.Header().Get("Set-Cookie") != "" {
		t.Fatalf("invalid bootstrap status/cookie = %d / %q", w.Code, w.Header().Get("Set-Cookie"))
	}
}

func TestPreviewBrowserQueryBootstrapPreservesEmptyQueryComponent(t *testing.T) {
	const (
		sandboxID = "66ca164d-964b-43da-b81a-004d51598d6a"
		port      = 3000
	)
	seed := []byte("preview-test-seed-that-is-at-least-thirty-two-bytes")
	valid := mintPreviewTestToken(t, seed, sandboxID, port, 1)
	req := httptest.NewRequest(http.MethodGet, "http://unused/path", nil)
	req.Host = "3000-" + sandboxID + ".sandbox.test"
	req.URL.RawQuery = auth.PreviewTokenQueryParam + "=" + url.QueryEscape(valid) + "&"

	w := httptest.NewRecorder()
	if enforcePreviewPublication(w, req, sandboxID, port, browserPreviewTestPolicy(port, 1), seed, false) {
		t.Fatal("bootstrap request was forwarded instead of redirected")
	}
	want := "https://" + req.Host + "/path?"
	if got := w.Header().Get("Location"); got != want {
		t.Fatalf("Location = %q, want preserved empty query component %q", got, want)
	}
}

func TestPreviewBrowserQueryRedirectExceptions(t *testing.T) {
	const (
		sandboxID = "66ca164d-964b-43da-b81a-004d51598d6a"
		port      = 3000
	)
	seed := []byte("preview-test-seed-that-is-at-least-thirty-two-bytes")
	valid := mintPreviewTestToken(t, seed, sandboxID, port, 1)
	info := browserPreviewTestPolicy(port, 1)

	tests := []struct {
		name       string
		method     string
		upgrade    string
		connection string
		wantDirect bool
	}{
		{name: "post", method: http.MethodPost, wantDirect: true},
		{name: "real websocket", method: http.MethodGet, upgrade: "websocket", connection: "keep-alive, Upgrade", wantDirect: true},
		{name: "upgrade without connection", method: http.MethodGet, upgrade: "websocket"},
		{name: "unrelated upgrade", method: http.MethodGet, upgrade: "h2c", connection: "upgrade"},
		{name: "ordinary get", method: http.MethodGet},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "http://unused/path?"+auth.PreviewTokenQueryParam+"="+url.QueryEscape(valid), nil)
			req.Header.Set("Upgrade", tt.upgrade)
			req.Header.Set("Connection", tt.connection)
			w := httptest.NewRecorder()
			got := enforcePreviewPublication(w, req, sandboxID, port, info, seed, false)
			if got != tt.wantDirect {
				t.Fatalf("direct = %v, want %v; status=%d", got, tt.wantDirect, w.Code)
			}
			if !tt.wantDirect && w.Code != http.StatusFound {
				t.Fatalf("status = %d, want 302", w.Code)
			}
		})
	}
}

func TestPreviewBrowserHandlesGenuineCORSPreflightLocally(t *testing.T) {
	const sandboxID = "66ca164d-964b-43da-b81a-004d51598d6a"
	seed := []byte("preview-test-seed-that-is-at-least-thirty-two-bytes")
	info := browserPreviewTestPolicy(3000, 1)
	for _, tt := range []struct {
		name          string
		origin        string
		acrm          string
		originAllowed bool
		wantStatus    int
	}{
		{name: "allowed", origin: "https://console.example", acrm: http.MethodGet, originAllowed: true, wantStatus: http.StatusNoContent},
		{name: "disallowed", origin: "https://attacker.example", acrm: http.MethodGet, wantStatus: http.StatusUnauthorized},
		{name: "plain options", wantStatus: http.StatusUnauthorized},
		{name: "origin only", origin: "https://console.example", wantStatus: http.StatusUnauthorized},
		{name: "method only", acrm: http.MethodGet, wantStatus: http.StatusUnauthorized},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodOptions, "http://unused/path", nil)
			req.Header.Set("Origin", tt.origin)
			req.Header.Set("Access-Control-Request-Method", tt.acrm)
			req.Header.Set("Access-Control-Request-Headers", auth.PreviewTokenHeader)
			w := httptest.NewRecorder()
			if got := enforcePreviewPublication(w, req, sandboxID, 3000, info, seed, tt.originAllowed); got {
				t.Fatal("preflight or unauthenticated OPTIONS request was forwarded")
			}
			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", w.Code, tt.wantStatus)
			}
			if tt.wantStatus == http.StatusNoContent {
				assertPrivatePreviewPreflightResponse(t, w, req)
			}
		})
	}
}

func TestPrivatePreviewCORSPreflightNeverReachesUpstream(t *testing.T) {
	const sandboxID = "66ca164d-964b-43da-b81a-004d51598d6a"
	seed := []byte("preview-test-seed-that-is-at-least-thirty-two-bytes")
	upstreamCalled := make(chan struct{}, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled <- struct{}{}
		http.Error(w, "private application response", http.StatusTeapot)
	}))
	defer upstream.Close()
	port := upstream.Listener.Addr().(*net.TCPAddr).Port

	resolver := &stubResolver{}
	handler := NewHandler([]string{"sandbox.test"}, resolver, zerolog.Nop()).
		WithAuth(seed).
		WithTerminal([]string{"https://console.example"})
	for _, mode := range []string{preview.AccessPrivateTokenV1, preview.AccessPrivateBrowserV1} {
		t.Run(mode, func(t *testing.T) {
			resolver.info = InstanceInfo{
				VMIP:                     "127.0.0.1",
				Status:                   "running",
				StartedAt:                1,
				PreviewAccess:            preview.AccessPrivate,
				PreviewPorts:             map[int]struct{}{port: {}},
				PreviewPortAccess:        map[int]string{port: mode},
				PreviewPortTokenVersions: map[int]int64{port: 1},
			}
			for _, tt := range []struct {
				name       string
				origin     string
				wantStatus int
			}{
				{name: "allowed origin", origin: "https://console.example", wantStatus: http.StatusNoContent},
				{name: "forged origin", origin: "https://attacker.example", wantStatus: http.StatusUnauthorized},
			} {
				t.Run(tt.name, func(t *testing.T) {
					req := httptest.NewRequest(http.MethodOptions, "http://unused/private", nil)
					req.Host = fmt.Sprintf("%d-%s.sandbox.test", port, sandboxID)
					req.Header.Set("Origin", tt.origin)
					req.Header.Set("Access-Control-Request-Method", http.MethodPost)
					req.Header.Set("Access-Control-Request-Headers", auth.PreviewTokenHeader)
					w := httptest.NewRecorder()

					handler.ServeHTTP(w, req)

					if w.Code != tt.wantStatus {
						t.Fatalf("status = %d, want %d; body=%q", w.Code, tt.wantStatus, w.Body.String())
					}
					if tt.wantStatus == http.StatusNoContent {
						assertPrivatePreviewPreflightResponse(t, w, req)
					} else if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
						t.Fatalf("denied preflight exposed Access-Control-Allow-Origin %q", got)
					}
					select {
					case <-upstreamCalled:
						t.Fatal("unauthenticated preflight reached the private application")
					default:
					}
				})
			}
		})
	}

	resolver.info = InstanceInfo{
		VMIP:                     "127.0.0.1",
		Status:                   "running",
		StartedAt:                1,
		PreviewAccess:            preview.AccessPrivate,
		PreviewPorts:             map[int]struct{}{port: {}},
		PreviewPortAccess:        map[int]string{port: preview.AccessPrivateBrowserV1},
		PreviewPortTokenVersions: map[int]int64{port: 1},
	}
	token := mintPreviewTestToken(t, seed, sandboxID, port, 1)
	req := httptest.NewRequest(http.MethodOptions, "http://unused/application-options", nil)
	req.Host = fmt.Sprintf("%d-%s.sandbox.test", port, sandboxID)
	req.Header.Set(auth.PreviewTokenHeader, token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusTeapot {
		t.Fatalf("authenticated application OPTIONS status = %d, want 418", w.Code)
	}
	select {
	case <-upstreamCalled:
	default:
		t.Fatal("authenticated application OPTIONS did not reach the private application")
	}
}

func TestScrubPreviewCredentialsPreservesUnrelatedRawValues(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://unused/path", nil)
	req.URL.RawQuery = "before=%2f&" + auth.PreviewTokenQueryParam + "=one&bad=%zz&superserve%5fpreview_token=two&after=a+b"
	req.Header[auth.PreviewTokenHeader] = []string{"one", "two"}
	req.Header["x-superserve-preview-token"] = []string{"three"}
	req.Header["Cookie"] = []string{
		`quoted="application value"; ` + auth.PreviewTokenCookie + `=one; malformed; keep=1`,
		auth.PreviewTokenCookie + `=two; similar_` + auth.PreviewTokenCookie + `=keep-too`,
	}
	req.Header["cOoKiE"] = []string{`other=%zz; ` + auth.PreviewTokenCookie + `=three`}

	scrubPreviewCredentials(req)
	if got := headerValues(req.Header, auth.PreviewTokenHeader); len(got) != 0 {
		t.Fatalf("reserved header survived: %#v", got)
	}
	if req.URL.RawQuery != "before=%2f&bad=%zz&after=a+b" {
		t.Fatalf("raw query = %q", req.URL.RawQuery)
	}
	cookies := strings.Join(headerValues(req.Header, "Cookie"), " | ")
	if values := previewCookieTokens(req.Header); len(values) != 0 {
		t.Fatalf("reserved cookie survived: %#v in %q", values, cookies)
	}
	for _, want := range []string{`quoted="application value"`, "malformed", "keep=1", "similar_" + auth.PreviewTokenCookie + "=keep-too", "other=%zz"} {
		if !strings.Contains(cookies, want) {
			t.Fatalf("unrelated cookie %q lost from %q", want, cookies)
		}
	}
}

func TestScrubPreviewCredentialsPreservesBareQueryDelimiter(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://unused/path?", nil)
	if !req.URL.ForceQuery {
		t.Fatal("test request did not retain its bare query delimiter")
	}
	scrubPreviewCredentials(req)
	if req.URL.RawQuery != "" || !req.URL.ForceQuery {
		t.Fatalf("credential-free query changed to RawQuery=%q ForceQuery=%v", req.URL.RawQuery, req.URL.ForceQuery)
	}

	req.URL.RawQuery = auth.PreviewTokenQueryParam + "=secret&"
	req.URL.ForceQuery = false
	scrubPreviewCredentials(req)
	if req.URL.RawQuery != "" || !req.URL.ForceQuery {
		t.Fatalf("empty component after credential scrub = RawQuery=%q ForceQuery=%v", req.URL.RawQuery, req.URL.ForceQuery)
	}
}

func TestPreviewCredentialsAreScrubbedBeforePublicAndBrowserUpstreams(t *testing.T) {
	const sandboxID = "66ca164d-964b-43da-b81a-004d51598d6a"
	seed := []byte("preview-test-seed-that-is-at-least-thirty-two-bytes")
	type captured struct {
		header   http.Header
		rawQuery string
	}
	received := make(chan captured, 2)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- captured{header: r.Header.Clone(), rawQuery: r.URL.RawQuery}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	port := upstream.Listener.Addr().(*net.TCPAddr).Port

	resolver := &stubResolver{}
	handler := NewHandler([]string{"sandbox.test"}, resolver, zerolog.Nop()).WithAuth(seed)
	valid := mintPreviewTestToken(t, seed, sandboxID, port, 3)
	request := func(info InstanceInfo, authenticate bool) {
		t.Helper()
		resolver.info = info
		req := httptest.NewRequest(http.MethodPost, "http://unused/path", nil)
		req.Host = fmt.Sprintf("%d-%s.sandbox.test", port, sandboxID)
		req.URL.RawQuery = "keep=%2f&" + auth.PreviewTokenQueryParam + "=" + url.QueryEscape(valid)
		req.Header.Add("Cookie", "app_session=keep; "+auth.PreviewTokenCookie+"=stale")
		req.Header["x-superserve-preview-token"] = []string{"stale"}
		if authenticate {
			req.Header.Add(auth.PreviewTokenHeader, valid)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204; body=%q", w.Code, w.Body.String())
		}
		got := <-received
		if len(headerValues(got.header, auth.PreviewTokenHeader)) != 0 || strings.Contains(got.rawQuery, auth.PreviewTokenQueryParam) {
			t.Fatalf("upstream received reserved header/query: %#v %q", got.header, got.rawQuery)
		}
		cookieHeader := strings.Join(headerValues(got.header, "Cookie"), ";")
		if strings.Contains(cookieHeader, auth.PreviewTokenCookie) || !strings.Contains(cookieHeader, "app_session=keep") {
			t.Fatalf("upstream cookies = %q", cookieHeader)
		}
		if got.rawQuery != "keep=%2f" {
			t.Fatalf("upstream query = %q", got.rawQuery)
		}
	}

	request(InstanceInfo{
		VMIP: "127.0.0.1", Status: "running", StartedAt: 1,
		PreviewAccess:     preview.AccessPublic,
		PreviewPorts:      map[int]struct{}{port: {}},
		PreviewPortAccess: map[int]string{port: preview.AccessPublic},
	}, false)
	private := browserPreviewTestPolicy(port, 3)
	private.VMIP, private.Status, private.StartedAt = "127.0.0.1", "running", 1
	request(private, true)
}
