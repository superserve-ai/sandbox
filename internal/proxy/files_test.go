package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/auth"
)

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

type stubResolver struct {
	info   InstanceInfo
	err    error
	invMu  sync.Mutex
	invIDs []string
}

func (s *stubResolver) Lookup(_ context.Context, _ string) (InstanceInfo, error) {
	if s.err != nil {
		return InstanceInfo{}, s.err
	}
	return s.info, nil
}

func (s *stubResolver) Invalidate(instanceID string) {
	s.invMu.Lock()
	s.invIDs = append(s.invIDs, instanceID)
	s.invMu.Unlock()
}

type filesTestEnv struct {
	t          *testing.T
	seedKey    []byte
	handler    *Handler
	upstream   *httptest.Server
	sandboxID  string
	domain     string
	resolver   *stubResolver
	upstreamMu sync.Mutex
	lastReq    capturedRequest
}

type capturedRequest struct {
	method      string
	path        string
	rawQuery    string
	host        string
	hasToken    bool
	fwdFor      string
	body        string
	received    bool
}

func newFilesTestEnv(t *testing.T) *filesTestEnv {
	t.Helper()

	seedKey := []byte("test-seed-key-that-is-at-least-32-bytes-long!!")

	env := &filesTestEnv{
		t:         t,
		seedKey:   seedKey,
		sandboxID: "sbx-" + strings.Repeat("a", 8),
		domain:    "sandbox.test",
	}

	env.upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		env.upstreamMu.Lock()
		env.lastReq = capturedRequest{
			method:   r.Method,
			path:     r.URL.Path,
			rawQuery: r.URL.RawQuery,
			host:     r.Host,
			hasToken: r.Header.Get("X-Access-Token") != "",
			fwdFor:   r.Header.Get("X-Forwarded-For"),
			body:     string(bodyBytes),
			received: true,
		}
		env.upstreamMu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
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

	env.handler = NewHandler(env.domain, env.resolver, zerolog.Nop())
	env.handler.WithAuth(seedKey).WithTerminal([]string{"*"}).WithFiles()

	upHost := upURL.Host
	env.handler.transports = &transportCache{
		items: map[string]*transportEntry{},
	}
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

func (e *filesTestEnv) validToken() string {
	return auth.ComputeAccessToken(e.seedKey, e.sandboxID)
}

func (e *filesTestEnv) buildRequest(method, filePath, token string, body io.Reader) *http.Request {
	q := url.Values{}
	if filePath != "" {
		q.Set("path", filePath)
	}
	target := "http://unused/files"
	if len(q) > 0 {
		target += "?" + q.Encode()
	}
	req := httptest.NewRequest(method, target, body)
	req.Host = "boxd-" + e.sandboxID + "." + e.domain
	if token != "" {
		req.Header.Set("X-Access-Token", token)
	}
	return req
}

// ---------------------------------------------------------------------------
// Happy paths
// ---------------------------------------------------------------------------

func TestFiles_UploadHeaderCarrier_ForwardsToUpstream(t *testing.T) {
	env := newFilesTestEnv(t)
	tok := env.validToken()

	req := env.buildRequest(http.MethodPost, "/home/u/app.txt", tok,
		strings.NewReader("file contents"))
	req.Header.Set("Content-Type", "application/octet-stream")

	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if !env.lastReq.received {
		t.Fatal("upstream never received the request")
	}
	if env.lastReq.method != http.MethodPost {
		t.Errorf("upstream method = %q, want POST", env.lastReq.method)
	}
	if env.lastReq.path != "/files" {
		t.Errorf("upstream path = %q, want /files", env.lastReq.path)
	}
	if !strings.Contains(env.lastReq.rawQuery, "path=%2Fhome%2Fu%2Fapp.txt") {
		t.Errorf("upstream query missing path param: %q", env.lastReq.rawQuery)
	}
	if env.lastReq.body != "file contents" {
		t.Errorf("upstream body = %q, want 'file contents'", env.lastReq.body)
	}
	if env.lastReq.hasToken {
		t.Error("X-Access-Token leaked to upstream")
	}
	if env.lastReq.fwdFor != "" {
		t.Errorf("X-Forwarded-For leaked: %q", env.lastReq.fwdFor)
	}
	if !strings.HasPrefix(env.lastReq.host, "boxd-") {
		t.Errorf("Host = %q, want public sandbox label", env.lastReq.host)
	}
}

// ---------------------------------------------------------------------------
// Auth rejections
// ---------------------------------------------------------------------------

func TestFiles_MissingToken_Unauthorized(t *testing.T) {
	env := newFilesTestEnv(t)
	req := env.buildRequest(http.MethodGet, "/f.txt", "", nil)
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestFiles_WrongTokenRejected(t *testing.T) {
	env := newFilesTestEnv(t)
	req := env.buildRequest(http.MethodGet, "/f.txt", "totally-wrong-token", nil)
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestFiles_WrongSandboxTokenRejected(t *testing.T) {
	env := newFilesTestEnv(t)
	wrongToken := auth.ComputeAccessToken(env.seedKey, "different-sandbox-id")
	req := env.buildRequest(http.MethodGet, "/f.txt", wrongToken, nil)
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestFiles_TokenReusable(t *testing.T) {
	env := newFilesTestEnv(t)
	tok := env.validToken()

	// First request
	req1 := env.buildRequest(http.MethodGet, "/f.txt", tok, nil)
	w1 := httptest.NewRecorder()
	env.handler.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("first call status = %d, want 200", w1.Code)
	}

	// Same token again — should still work (not single-use anymore)
	req2 := env.buildRequest(http.MethodGet, "/f.txt", tok, nil)
	w2 := httptest.NewRecorder()
	env.handler.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("second call status = %d, want 200 (token should be reusable)", w2.Code)
	}
}

func TestFiles_SandboxNotRunningReturns503(t *testing.T) {
	env := newFilesTestEnv(t)
	env.resolver.info.Status = "paused"
	tok := env.validToken()
	req := env.buildRequest(http.MethodGet, "/f.txt", tok, nil)
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
}

func TestFiles_SandboxNotFoundReturns404(t *testing.T) {
	env := newFilesTestEnv(t)
	env.resolver.err = ErrInstanceNotFound
	tok := env.validToken()
	req := env.buildRequest(http.MethodGet, "/f.txt", tok, nil)
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Boxd-port lockdown
// ---------------------------------------------------------------------------

func TestFiles_NonFilesPathBlocked(t *testing.T) {
	env := newFilesTestEnv(t)
	tok := env.validToken()

	paths := []string{
		"/superserve.boxd.v1.ProcessService/Start",
		"/superserve.boxd.v1.FilesystemService/ListDir",
		"/health",
		"/",
	}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://unused"+p, nil)
			req.Host = "boxd-" + env.sandboxID + "." + env.domain
			req.Header.Set("X-Access-Token", tok)

			w := httptest.NewRecorder()
			env.handler.ServeHTTP(w, req)
			if w.Code != http.StatusNotFound {
				t.Errorf("path %q: status = %d, want 404", p, w.Code)
			}
		})
	}
}

func TestFiles_PathTraversalRejected(t *testing.T) {
	env := newFilesTestEnv(t)
	tok := env.validToken()

	cases := []string{
		"/home/user/../../../etc/bad.txt",
		"/home/user/x/../y",
		"../x",
		"..",
	}
	for _, p := range cases {
		t.Run(p, func(t *testing.T) {
			req := env.buildRequest(http.MethodPost, p, tok,
				strings.NewReader("content"))
			w := httptest.NewRecorder()
			env.handler.ServeHTTP(w, req)
			if w.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", w.Code)
			}
		})
	}
}

func TestFiles_MissingPathParam(t *testing.T) {
	env := newFilesTestEnv(t)
	tok := env.validToken()

	req := env.buildRequest(http.MethodPost, "", tok,
		strings.NewReader("content"))
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestFiles_MethodNotAllowed(t *testing.T) {
	env := newFilesTestEnv(t)
	tok := env.validToken()
	req := env.buildRequest(http.MethodDelete, "/f.txt", tok, nil)
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", w.Code)
	}
	if got := w.Header().Get("Allow"); got != "GET, POST, OPTIONS" {
		t.Errorf("Allow = %q, want 'GET, POST, OPTIONS'", got)
	}
}

func TestFiles_DisabledReturns404(t *testing.T) {
	env := newFilesTestEnv(t)
	env.handler.filesEnabled = false

	tok := env.validToken()
	req := env.buildRequest(http.MethodGet, "/f.txt", tok, nil)
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}
