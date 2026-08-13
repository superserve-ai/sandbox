package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/auth"
)

type desktopProxyTestEnv struct {
	seedKey   []byte
	handler   *Handler
	upstream  *httptest.Server
	sandboxID string
	domain    string
	lastReq   capturedRequest
}

func newDesktopProxyTestEnv(t *testing.T) *desktopProxyTestEnv {
	t.Helper()

	env := &desktopProxyTestEnv{
		seedKey:   []byte("test-seed-key-that-is-at-least-32-bytes-long!!"),
		sandboxID: "sbx-" + strings.Repeat("d", 8),
		domain:    "sandbox.test",
	}
	env.upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		env.lastReq = capturedRequest{
			method:             r.Method,
			path:               r.URL.Path,
			host:               r.Host,
			hasToken:           r.Header.Get(accessTokenHeader) != "",
			hasSandboxIDHeader: r.Header.Get(headerSandboxID) != "",
			fwdFor:             r.Header.Get("X-Forwarded-For"),
			body:               string(body),
			received:           true,
		}
		w.Header().Set("Content-Type", "application/proto")
		_, _ = w.Write([]byte("response"))
	}))
	t.Cleanup(env.upstream.Close)

	upURL, _ := url.Parse(env.upstream.URL)
	resolver := &stubResolver{info: InstanceInfo{
		VMIP:      upURL.Hostname(),
		Status:    "running",
		StartedAt: time.Now().UnixNano(),
	}}
	env.handler = NewHandler([]string{env.domain}, resolver, zerolog.Nop())
	env.handler.WithAuth(env.seedKey).WithDesktop()

	upHost := upURL.Host
	env.handler.transports = &transportCache{items: map[string]*transportEntry{}}
	env.handler.transports.items[env.sandboxID] = &transportEntry{
		lifecycleKey: resolver.info.lifecycleKey(),
		transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var dialer net.Dialer
				return dialer.DialContext(ctx, network, upHost)
			},
			DisableKeepAlives: true,
		},
		lastUsed: time.Now(),
	}
	return env
}

func (e *desktopProxyTestEnv) request(method, path, token string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, "http://unused"+path, body)
	req.Host = "boxd-" + e.sandboxID + "." + e.domain
	if token != "" {
		req.Header.Set(accessTokenHeader, token)
	}
	return req
}

func (e *desktopProxyTestEnv) validToken() string {
	return auth.ComputeAccessToken(e.seedKey, e.sandboxID)
}

func TestDesktopProxy_AllowsOnlyDesktopRPCs(t *testing.T) {
	paths := []string{
		desktopScreenshotPath,
		desktopStreamPath,
		desktopSendPointerPath,
		desktopSendKeyPath,
		desktopScrollPath,
		desktopResizePath,
		desktopSendActionsPath,
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			env := newDesktopProxyTestEnv(t)
			req := env.request(http.MethodPost, path, env.validToken(), strings.NewReader("request"))
			req.Header.Set(headerSandboxID, "spoofed")
			w := httptest.NewRecorder()
			env.handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
			}
			if !env.lastReq.received || env.lastReq.path != path || env.lastReq.body != "request" {
				t.Fatalf("upstream request = %+v", env.lastReq)
			}
			if env.lastReq.hasToken || env.lastReq.hasSandboxIDHeader || env.lastReq.fwdFor != "" {
				t.Fatalf("private headers leaked upstream: %+v", env.lastReq)
			}
		})
	}

	env := newDesktopProxyTestEnv(t)
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, env.request(http.MethodPost, "/superserve.boxd.v1.ProcessService/Start", env.validToken(), nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("non-desktop RPC status = %d, want 404", w.Code)
	}
}

func TestDesktopProxy_AuthAndMethodChecks(t *testing.T) {
	env := newDesktopProxyTestEnv(t)

	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, env.request(http.MethodPost, desktopSendKeyPath, "", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("missing token status = %d, want 401", w.Code)
	}

	w = httptest.NewRecorder()
	env.handler.ServeHTTP(w, env.request(http.MethodPost, desktopSendKeyPath, "wrong", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("invalid token status = %d, want 401", w.Code)
	}

	w = httptest.NewRecorder()
	env.handler.ServeHTTP(w, env.request(http.MethodGet, desktopSendKeyPath, env.validToken(), nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET status = %d, want 405", w.Code)
	}
}

func TestDesktopProxy_DisabledAndConfigurationOrder(t *testing.T) {
	env := newDesktopProxyTestEnv(t)
	env.handler.desktopEnabled = false
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, env.request(http.MethodPost, desktopSendKeyPath, env.validToken(), nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("disabled status = %d, want 404", w.Code)
	}

	h := NewHandler([]string{"sandbox.test"}, &stubResolver{}, zerolog.Nop())
	defer func() {
		if recover() == nil {
			t.Fatal("expected WithDesktop before WithAuth to panic")
		}
	}()
	h.WithDesktop()
}

func TestDesktopProxy_OversizedBodyRejected413(t *testing.T) {
	env := newDesktopProxyTestEnv(t)

	// Declared Content-Length above the cap: rejected before proxying.
	req := env.request(http.MethodPost, desktopSendActionsPath, env.validToken(),
		strings.NewReader("tiny"))
	req.ContentLength = maxDesktopRequestBytes + 1
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("declared-oversize status = %d, want 413", w.Code)
	}
	if env.lastReq.received {
		t.Fatal("oversized request must not reach the upstream")
	}

	// Undeclared (chunked) oversize: MaxBytesReader trips mid-copy and must
	// surface as 413 through the ErrorHandler, not a 502 retry loop.
	env2 := newDesktopProxyTestEnv(t)
	big := strings.NewReader(strings.Repeat("x", maxDesktopRequestBytes+1))
	req2 := env2.request(http.MethodPost, desktopSendActionsPath, env2.validToken(), big)
	req2.ContentLength = -1 // force chunked
	w2 := httptest.NewRecorder()
	env2.handler.ServeHTTP(w2, req2)
	if w2.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("chunked-oversize status = %d, want 413; body: %s", w2.Code, w2.Body.String())
	}
}

func TestDesktopProxy_UsageDebounce(t *testing.T) {
	env := newDesktopProxyTestEnv(t)
	info := InstanceInfo{VMIP: "10.0.0.1"}

	var events int
	// captureUsage is a no-op without analytics; count via the debounce map
	// state instead: same (sandbox, event) within the window records once.
	env.handler.captureDesktopUsage("sbx-a", "desktop_screenshot", info)
	env.handler.captureDesktopUsage("sbx-a", "desktop_screenshot", info)
	env.handler.captureDesktopUsage("sbx-a", "desktop_input", info)
	env.handler.captureDesktopUsage("sbx-b", "desktop_screenshot", info)
	events = len(env.handler.desktopUsageLast)
	if events != 3 {
		t.Fatalf("debounce map entries = %d, want 3 (sbx-a/screenshot, sbx-a/input, sbx-b/screenshot)", events)
	}

	// A stale entry re-emits: backdate and confirm the timestamp refreshes.
	key := "sbx-a\x00desktop_screenshot"
	stale := time.Now().Add(-2 * desktopUsageWindow)
	env.handler.desktopUsageMu.Lock()
	env.handler.desktopUsageLast[key] = stale
	env.handler.desktopUsageMu.Unlock()
	env.handler.captureDesktopUsage("sbx-a", "desktop_screenshot", info)
	env.handler.desktopUsageMu.Lock()
	refreshed := env.handler.desktopUsageLast[key].After(stale)
	env.handler.desktopUsageMu.Unlock()
	if !refreshed {
		t.Fatal("expected a stale debounce entry to re-emit and refresh its timestamp")
	}
}
