package proxy

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// newExecTestEnv mirrors newFilesTestEnv but wires WithExec instead of
// WithFiles, so the /exec and /exec/stream paths reach the upstream and
// /files paths 404 in this harness. Keeps test isolation: a misconfigured
// allowlist regression in either feature is caught by its own tests.
func newExecTestEnv(t *testing.T) *filesTestEnv {
	t.Helper()

	seedKey := []byte("test-seed-key-that-is-at-least-32-bytes-long!!")

	env := &filesTestEnv{
		t:         t,
		seedKey:   seedKey,
		sandboxID: "sbx-" + strings.Repeat("e", 8),
		domain:    "sandbox.test",
	}

	env.upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		env.upstreamMu.Lock()
		env.lastReq = capturedRequest{
			method:             r.Method,
			path:               r.URL.Path,
			host:               r.Host,
			hasToken:           r.Header.Get("X-Access-Token") != "",
			hasSandboxIDHeader: r.Header.Get(headerSandboxID) != "",
			fwdFor:             r.Header.Get("X-Forwarded-For"),
			received:           true,
		}
		env.upstreamMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"stdout":"","stderr":"","exit_code":0}`))
	}))
	t.Cleanup(env.upstream.Close)

	upURL, _ := url.Parse(env.upstream.URL)
	env.resolver = &stubResolver{
		info: InstanceInfo{
			VMIP:      upURL.Hostname(),
			Status:    "running",
			StartedAt: time.Now().UnixNano(),
		},
	}

	env.handler = NewHandler([]string{env.domain}, env.resolver, zerolog.Nop())
	env.handler.WithAuth(seedKey).WithExec()

	// Redirect transport at the per-sandbox cache so the boxd-internal
	// VMIP:boxdPort dial lands on the httptest upstream instead.
	upHost := upURL.Host
	env.handler.transports = &transportCache{items: map[string]*transportEntry{}}
	redirTransport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, upHost)
		},
		DisableKeepAlives: true,
	}
	env.handler.transports.items[env.sandboxID] = &transportEntry{
		lifecycleKey: env.resolver.info.lifecycleKey(),
		transport:    redirTransport,
		lastUsed:     time.Now(),
	}

	return env
}

func (e *filesTestEnv) buildExecRequest(path, token, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "http://unused"+path, strings.NewReader(body))
	req.Host = "boxd-" + e.sandboxID + "." + e.domain
	if token != "" {
		req.Header.Set("X-Access-Token", token)
	}
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestExec_ValidToken_ForwardsToUpstream(t *testing.T) {
	env := newExecTestEnv(t)
	req := env.buildExecRequest("/exec", env.validToken(), `{"command":"echo"}`)
	w := httptest.NewRecorder()

	env.handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	env.upstreamMu.Lock()
	defer env.upstreamMu.Unlock()
	if !env.lastReq.received {
		t.Fatal("upstream did not receive the request")
	}
	if env.lastReq.method != http.MethodPost {
		t.Errorf("upstream method = %q, want POST", env.lastReq.method)
	}
	if env.lastReq.path != "/exec" {
		t.Errorf("upstream path = %q, want /exec", env.lastReq.path)
	}
	if env.lastReq.hasToken {
		t.Error("X-Access-Token was forwarded to upstream — should be scrubbed")
	}
}

func TestExecStream_ValidToken_ForwardsToUpstream(t *testing.T) {
	env := newExecTestEnv(t)
	req := env.buildExecRequest("/exec/stream", env.validToken(), `{"command":"echo"}`)
	w := httptest.NewRecorder()

	env.handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	env.upstreamMu.Lock()
	defer env.upstreamMu.Unlock()
	if !env.lastReq.received || env.lastReq.path != "/exec/stream" {
		t.Errorf("upstream path = %q, want /exec/stream", env.lastReq.path)
	}
}

func TestExec_MissingToken_401(t *testing.T) {
	env := newExecTestEnv(t)
	req := env.buildExecRequest("/exec", "", `{"command":"echo"}`)
	w := httptest.NewRecorder()

	env.handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
	env.upstreamMu.Lock()
	defer env.upstreamMu.Unlock()
	if env.lastReq.received {
		t.Error("upstream was contacted despite missing token")
	}
}

func TestExec_BadToken_401(t *testing.T) {
	env := newExecTestEnv(t)
	req := env.buildExecRequest("/exec", "not-a-valid-token", `{"command":"echo"}`)
	w := httptest.NewRecorder()

	env.handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestExec_WrongMethod_405(t *testing.T) {
	env := newExecTestEnv(t)
	req := httptest.NewRequest(http.MethodGet, "http://unused/exec", nil)
	req.Host = "boxd-" + env.sandboxID + "." + env.domain
	req.Header.Set("X-Access-Token", env.validToken())
	w := httptest.NewRecorder()

	env.handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

// When the proxy is started without WithExec, the path 404s — same
// invisible-feature treatment as /files and /terminal.
func TestExec_NotEnabled_404(t *testing.T) {
	seedKey := []byte("test-seed-key-that-is-at-least-32-bytes-long!!")
	domain := "sandbox.test"
	sandboxID := "sbx-" + strings.Repeat("z", 8)

	h := NewHandler([]string{domain}, &stubResolver{info: InstanceInfo{VMIP: "127.0.0.1", Status: "running"}}, zerolog.Nop())
	h.WithAuth(seedKey) // WithExec deliberately not called

	req := httptest.NewRequest(http.MethodPost, "http://unused/exec", strings.NewReader(`{"command":"echo"}`))
	req.Host = "boxd-" + sandboxID + "." + domain
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (feature should not leak)", w.Code)
	}
}

func TestExec_WithoutWithAuth_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic when WithExec called before WithAuth")
		}
	}()
	h := NewHandler([]string{"sandbox.test"}, &stubResolver{}, zerolog.Nop())
	h.WithExec()
}

func TestExec_SharedHost_ForwardsToUpstream(t *testing.T) {
	env := newExecTestEnv(t)
	req := httptest.NewRequest(http.MethodPost, "http://unused/exec", strings.NewReader(`{"command":"echo"}`))
	req.Host = env.domain
	req.Header.Set(headerSandboxID, env.sandboxID)
	req.Header.Set("X-Access-Token", env.validToken())
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	env.handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	env.upstreamMu.Lock()
	defer env.upstreamMu.Unlock()
	if !env.lastReq.received {
		t.Fatal("upstream did not receive the request")
	}
	if env.lastReq.path != "/exec" {
		t.Errorf("upstream path = %q, want /exec", env.lastReq.path)
	}
	if env.lastReq.hasToken {
		t.Error("X-Access-Token was forwarded to upstream — should be scrubbed")
	}
	if env.lastReq.hasSandboxIDHeader {
		t.Error("X-Superserve-Sandbox-Id was forwarded to upstream — should be scrubbed")
	}
}
