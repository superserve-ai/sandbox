package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/auth"
)

type fakePreviewPortAuthorizer struct {
	mu      sync.Mutex
	calls   []previewPortAuthCall
	allowed bool
	err     error
}

type previewPortAuthCall struct {
	sandboxID string
	port      int
	status    string
}

func (f *fakePreviewPortAuthorizer) Allowed(_ context.Context, sandboxID string, port int, info InstanceInfo) (bool, error) {
	f.mu.Lock()
	f.calls = append(f.calls, previewPortAuthCall{
		sandboxID: sandboxID,
		port:      port,
		status:    info.Status,
	})
	allowed := f.allowed
	err := f.err
	f.mu.Unlock()
	return allowed, err
}

func (f *fakePreviewPortAuthorizer) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

type previewPortTestEnv struct {
	t          *testing.T
	handler    *Handler
	upstream   *httptest.Server
	resolver   *stubResolver
	authorizer *fakePreviewPortAuthorizer
	sandboxID  string
	domain     string
	upstreamMu sync.Mutex
	lastReq    capturedRequest
}

func newPreviewPortTestEnv(t *testing.T, allowed bool, authErr error) *previewPortTestEnv {
	t.Helper()

	env := &previewPortTestEnv{
		t:          t,
		sandboxID:  "sbx-" + "preview123",
		domain:     "sandbox.test",
		authorizer: &fakePreviewPortAuthorizer{allowed: allowed, err: authErr},
	}

	env.upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		env.upstreamMu.Lock()
		env.lastReq = capturedRequest{
			method:   r.Method,
			path:     r.URL.Path,
			rawQuery: r.URL.RawQuery,
			host:     r.Host,
			received: true,
		}
		env.upstreamMu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
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

	env.handler = NewHandler(env.domain, env.resolver, zerolog.Nop()).
		WithPreviewPortAuthorizer(env.authorizer)
	env.handler.transports = &transportCache{items: map[string]*transportEntry{}}
	env.handler.transports.items[env.sandboxID] = &transportEntry{
		lifecycleKey: env.resolver.info.lifecycleKey(),
		transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, upURL.Host)
			},
			DisableKeepAlives: true,
		},
		lastUsed: time.Now(),
	}

	return env
}

func (e *previewPortTestEnv) buildPortRequest(port int) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://unused/", nil)
	req.Host = fmt.Sprintf("%d-%s.%s", port, e.sandboxID, e.domain)
	return req
}

func (e *previewPortTestEnv) validToken() string {
	return auth.ComputeAccessToken([]byte("test-seed-key-that-is-at-least-32-bytes-long!!"), e.sandboxID)
}

func TestPreviewPortAllowed_ProxiesSuccessfully(t *testing.T) {
	env := newPreviewPortTestEnv(t, true, nil)
	req := env.buildPortRequest(3000)
	w := httptest.NewRecorder()

	env.handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if got := env.authorizer.callCount(); got != 1 {
		t.Fatalf("authorizer calls = %d, want 1", got)
	}
	env.upstreamMu.Lock()
	defer env.upstreamMu.Unlock()
	if !env.lastReq.received {
		t.Fatal("upstream did not receive the request")
	}
	if env.lastReq.method != http.MethodGet {
		t.Errorf("upstream method = %q, want GET", env.lastReq.method)
	}
}

func TestPreviewPortDenied_Returns404(t *testing.T) {
	env := newPreviewPortTestEnv(t, false, nil)
	req := env.buildPortRequest(3000)
	w := httptest.NewRecorder()

	env.handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
	if got := env.authorizer.callCount(); got != 1 {
		t.Fatalf("authorizer calls = %d, want 1", got)
	}
	env.upstreamMu.Lock()
	defer env.upstreamMu.Unlock()
	if env.lastReq.received {
		t.Fatal("upstream was contacted despite denial")
	}
}

func TestPreviewPortAuthorizerError_Returns503(t *testing.T) {
	env := newPreviewPortTestEnv(t, false, errors.New("authorization backend down"))
	req := env.buildPortRequest(3000)
	w := httptest.NewRecorder()

	env.handler.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
	if got := env.authorizer.callCount(); got != 1 {
		t.Fatalf("authorizer calls = %d, want 1", got)
	}
	env.upstreamMu.Lock()
	defer env.upstreamMu.Unlock()
	if env.lastReq.received {
		t.Fatal("upstream was contacted despite authorizer error")
	}
}

func TestPreviewPort_BoxdTrafficDoesNotInvokePreviewAuthorizer(t *testing.T) {
	env := newPreviewPortTestEnv(t, true, nil)
	env.handler.WithAuth([]byte("test-seed-key-that-is-at-least-32-bytes-long!!")).WithFiles()

	req := httptest.NewRequest(http.MethodGet, "http://unused/files?path=%2Ftmp%2Fboxd.txt", nil)
	req.Host = "boxd-" + env.sandboxID + "." + env.domain
	req.Header.Set("X-Access-Token", env.validToken())
	w := httptest.NewRecorder()

	env.handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if got := env.authorizer.callCount(); got != 0 {
		t.Fatalf("authorizer calls = %d, want 0", got)
	}
}

func TestPreviewPort_PrivilegedPortsBlockedBeforeAuthorization(t *testing.T) {
	authz := &fakePreviewPortAuthorizer{}
	h := NewHandler("sandbox.test", &stubResolver{}, zerolog.Nop()).
		WithPreviewPortAuthorizer(authz)

	req := httptest.NewRequest(http.MethodGet, "http://unused/", nil)
	req.Host = "80-sbx-preview123.sandbox.test"
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	if got := authz.callCount(); got != 0 {
		t.Fatalf("authorizer calls = %d, want 0", got)
	}
}

func TestPreviewPortSandboxNotFoundUnchanged(t *testing.T) {
	authz := &fakePreviewPortAuthorizer{}
	h := NewHandler("sandbox.test", &stubResolver{err: ErrInstanceNotFound}, zerolog.Nop()).
		WithPreviewPortAuthorizer(authz)

	req := httptest.NewRequest(http.MethodGet, "http://unused/", nil)
	req.Host = "3000-sbx-preview123.sandbox.test"
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
	if got := authz.callCount(); got != 0 {
		t.Fatalf("authorizer calls = %d, want 0", got)
	}
}

func TestPreviewPortSandboxNonRunningUnchanged(t *testing.T) {
	authz := &fakePreviewPortAuthorizer{}
	h := NewHandler("sandbox.test", &stubResolver{info: InstanceInfo{VMIP: "127.0.0.1", Status: "paused"}}, zerolog.Nop()).
		WithPreviewPortAuthorizer(authz)

	req := httptest.NewRequest(http.MethodGet, "http://unused/", nil)
	req.Host = "3000-sbx-preview123.sandbox.test"
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
	if got := authz.callCount(); got != 0 {
		t.Fatalf("authorizer calls = %d, want 0", got)
	}
}
