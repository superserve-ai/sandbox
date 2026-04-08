package proxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
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
// Test harness: stub resolver + fake upstream boxd + wired Handler
// ---------------------------------------------------------------------------

// stubResolver is the minimum Resolver implementation the files handler
// needs: one fixed instance ID → one InstanceInfo mapping, plus a settable
// error and an Invalidate no-op.
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

// filesTestEnv bundles everything a single files test case needs: the
// signing key so tests can mint tokens, the proxy Handler being
// exercised, a fake upstream standing in for boxd's /files endpoint, and
// a capture slot for the last request the upstream saw (tests assert on
// headers, query string, method, and body here).
type filesTestEnv struct {
	t          *testing.T
	signer     *auth.Signer
	handler    *Handler
	upstream   *httptest.Server
	sandboxID  string
	domain     string
	resolver   *stubResolver
	upstreamMu sync.Mutex
	lastReq    capturedRequest
}

// capturedRequest snapshots a request hitting the fake upstream so the
// test goroutine can assert on it after rp.ServeHTTP returns.
type capturedRequest struct {
	method       string
	path         string
	rawQuery     string
	host         string
	hasAuth      bool
	fwdFor       string
	body         string
	contentType  string
	received     bool
}

func newFilesTestEnv(t *testing.T) *filesTestEnv {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}
	signer := auth.NewSigner(priv)
	verifier := auth.NewVerifier(pub)

	env := &filesTestEnv{
		t:         t,
		signer:    signer,
		sandboxID: "sbx-" + strings.Repeat("a", 8),
		domain:    "sandbox.test",
	}

	// Fake upstream: captures whatever request reaches it, returns a
	// small deterministic payload so tests can distinguish "forwarded"
	// from "blocked".
	env.upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		env.upstreamMu.Lock()
		env.lastReq = capturedRequest{
			method:      r.Method,
			path:        r.URL.Path,
			rawQuery:    r.URL.RawQuery,
			host:        r.Host,
			hasAuth:     r.Header.Get("Authorization") != "",
			fwdFor:      r.Header.Get("X-Forwarded-For"),
			body:        string(bodyBytes),
			contentType: r.Header.Get("Content-Type"),
			received:    true,
		}
		env.upstreamMu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(env.upstream.Close)

	// Point the resolver at the upstream. We parse the URL to lift its
	// host so the proxy's reverse-proxy target resolves to the
	// upstream's listener. The proxy always targets `{VMIP}:{boxdPort}`
	// — we embed the entire host:port into VMIP and accept that the
	// port is appended again by the director. To keep this simple, the
	// upstream is mounted as an httptest.Server whose ClientConnection
	// is used directly via a custom transport. Easier alternative:
	// override the whole ReverseProxy path. We take the easier road:
	// rebuild InstanceInfo.VMIP to be the upstream's host (including
	// its real port) and set a custom transport cache entry that
	// ignores the port we append.
	//
	// Simpler still: use the upstream's host:port as VMIP and rely on
	// the fact that the proxy will dial "VMIP:boxdPort" (a made-up
	// address). That won't work. Instead, plug a custom transport that
	// always routes to the upstream regardless of target.
	upURL, _ := url.Parse(env.upstream.URL)
	env.resolver = &stubResolver{
		info: InstanceInfo{
			VMIP:      upURL.Hostname(),
			Status:    "running",
			StartedAt: time.Now().UnixNano(),
		},
	}

	env.handler = NewHandler(env.domain, env.resolver, zerolog.Nop())
	env.handler.WithFiles(verifier, DefaultNonceCache())

	// Override the transport cache with one that forces every outbound
	// connection to the upstream. This short-circuits the fact that
	// "VMIP:boxdPort" isn't a real address — the upstream lives on a
	// random ephemeral port that the proxy would never guess.
	upHost := upURL.Host
	env.handler.transports = &transportCache{
		items: map[string]*transportEntry{},
	}
	// Inject a pre-built entry that will be returned for any instance
	// ID the test asks about. The lifecycle key must match
	// InstanceInfo.lifecycleKey(), otherwise transports.get replaces
	// the entry on first call.
	// The reverse proxy builds its target from InstanceInfo.VMIP and
	// the hardcoded boxdPort, producing an address the upstream doesn't
	// actually listen on (the upstream is on a random ephemeral port).
	// Override DialContext so every outbound connection lands on the
	// real upstream regardless of what address the director asked for.
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

// mintToken produces a signed token for the test's sandbox and scope.
// When override is non-empty, it's used as the sandbox ID in the token
// (to drive the "token for sandbox A replayed against sandbox B" case).
func (e *filesTestEnv) mintToken(scope auth.Scope, override string) string {
	e.t.Helper()
	sid := e.sandboxID
	if override != "" {
		sid = override
	}
	tok, err := e.signer.Mint(time.Now(), sid, "team-test", scope)
	if err != nil {
		e.t.Fatalf("mint: %v", err)
	}
	return tok
}

// buildRequest constructs a request addressed at the files endpoint
// through the proxy's host label. The test chooses the carrier (header
// or query), path query, and optional body.
func (e *filesTestEnv) buildRequest(method, filePath, token string, carrier tokenCarrier, body io.Reader) *http.Request {
	q := url.Values{}
	if filePath != "" {
		q.Set("path", filePath)
	}
	if token != "" && carrier == carrierQuery {
		q.Set("token", token)
	}
	target := "http://unused/files"
	if len(q) > 0 {
		target += "?" + q.Encode()
	}
	req := httptest.NewRequest(method, target, body)
	req.Host = "49983-" + e.sandboxID + "." + e.domain
	if token != "" && carrier == carrierHeader {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

type tokenCarrier int

const (
	carrierHeader tokenCarrier = iota
	carrierQuery
)

// ---------------------------------------------------------------------------
// Happy paths
// ---------------------------------------------------------------------------

func TestFiles_UploadHeaderCarrier_ForwardsToUpstream(t *testing.T) {
	env := newFilesTestEnv(t)
	tok := env.mintToken(auth.ScopeFiles, "")

	req := env.buildRequest(http.MethodPost, "/home/u/app.txt", tok, carrierHeader,
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
	// Auth header must be scrubbed before the upstream sees it — boxd
	// has no business holding the bearer token.
	if env.lastReq.hasAuth {
		t.Error("Authorization header leaked to upstream")
	}
	// X-Forwarded-For must be stripped so a caller can't spoof origin.
	if env.lastReq.fwdFor != "" {
		t.Errorf("X-Forwarded-For leaked: %q", env.lastReq.fwdFor)
	}
	// Host header preserved so boxd logs the public name, not the VM IP.
	if !strings.HasPrefix(env.lastReq.host, "49983-") {
		t.Errorf("Host = %q, want public sandbox label", env.lastReq.host)
	}
}

func TestFiles_DownloadQueryCarrier_StripsTokenBeforeForwarding(t *testing.T) {
	env := newFilesTestEnv(t)
	tok := env.mintToken(auth.ScopeFiles, "")

	req := env.buildRequest(http.MethodGet, "/etc/motd", tok, carrierQuery, nil)

	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if strings.Contains(env.lastReq.rawQuery, "token=") {
		t.Errorf("token leaked to upstream query: %q", env.lastReq.rawQuery)
	}
	if !strings.Contains(env.lastReq.rawQuery, "path=%2Fetc%2Fmotd") {
		t.Errorf("path param lost: %q", env.lastReq.rawQuery)
	}
}

// ---------------------------------------------------------------------------
// Auth rejections
// ---------------------------------------------------------------------------

func TestFiles_MissingToken_Unauthorized(t *testing.T) {
	env := newFilesTestEnv(t)
	req := env.buildRequest(http.MethodGet, "/f.txt", "", carrierHeader, nil)
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if env.lastReq.received {
		t.Error("upstream was called despite missing token")
	}
}

func TestFiles_WrongScopeRejected(t *testing.T) {
	env := newFilesTestEnv(t)
	tok := env.mintToken(auth.ScopeTerminal, "")
	req := env.buildRequest(http.MethodGet, "/f.txt", tok, carrierHeader, nil)
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if env.lastReq.received {
		t.Error("upstream was called with a terminal-scope token")
	}
}

func TestFiles_WrongSandboxRejected(t *testing.T) {
	// Token minted for a different sandbox must be refused — this is
	// the cross-sandbox replay defense.
	env := newFilesTestEnv(t)
	tok := env.mintToken(auth.ScopeFiles, "sbx-"+strings.Repeat("b", 8))
	req := env.buildRequest(http.MethodGet, "/f.txt", tok, carrierHeader, nil)
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body: %s", w.Code, w.Body.String())
	}
}

func TestFiles_NonceReplayRejected(t *testing.T) {
	env := newFilesTestEnv(t)
	tok := env.mintToken(auth.ScopeFiles, "")

	req1 := env.buildRequest(http.MethodGet, "/f.txt", tok, carrierHeader, nil)
	w1 := httptest.NewRecorder()
	env.handler.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("first call status = %d, want 200", w1.Code)
	}

	// Replay the exact same token. The nonce cache must reject it.
	req2 := env.buildRequest(http.MethodGet, "/f.txt", tok, carrierHeader, nil)
	w2 := httptest.NewRecorder()
	env.handler.ServeHTTP(w2, req2)
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("replay status = %d, want 401", w2.Code)
	}
}

func TestFiles_SandboxNotRunningReturns503(t *testing.T) {
	env := newFilesTestEnv(t)
	env.resolver.info.Status = "paused"
	tok := env.mintToken(auth.ScopeFiles, "")
	req := env.buildRequest(http.MethodGet, "/f.txt", tok, carrierHeader, nil)
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
}

func TestFiles_SandboxNotFoundReturns404(t *testing.T) {
	env := newFilesTestEnv(t)
	env.resolver.err = ErrInstanceNotFound
	tok := env.mintToken(auth.ScopeFiles, "")
	req := env.buildRequest(http.MethodGet, "/f.txt", tok, carrierHeader, nil)
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Boxd-port lockdown
// ---------------------------------------------------------------------------

// TestFiles_NonFilesPathBlocked asserts that anything on port 49983 other
// than /files returns 404 even with a valid token. The proxy must never
// forward arbitrary paths to boxd because the connect-rpc
// ProcessService / FilesystemService also live on that port and have no
// scope-based auth of their own.
func TestFiles_NonFilesPathBlocked(t *testing.T) {
	env := newFilesTestEnv(t)
	tok := env.mintToken(auth.ScopeFiles, "")

	// Try a few representative paths that correspond to real boxd
	// connect-rpc endpoints and generic probes.
	paths := []string{
		"/superserve.boxd.v1.ProcessService/Start",
		"/superserve.boxd.v1.FilesystemService/ListDir",
		"/health",
		"/",
	}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://unused"+p, nil)
			req.Host = "49983-" + env.sandboxID + "." + env.domain
			req.Header.Set("Authorization", "Bearer "+tok)

			w := httptest.NewRecorder()
			env.handler.ServeHTTP(w, req)
			if w.Code != http.StatusNotFound {
				t.Errorf("path %q: status = %d, want 404", p, w.Code)
			}
		})
	}
	if env.lastReq.received {
		t.Error("upstream was called for a non-/files path on boxd port")
	}
}

func TestFiles_MethodNotAllowed(t *testing.T) {
	env := newFilesTestEnv(t)
	tok := env.mintToken(auth.ScopeFiles, "")
	req := env.buildRequest(http.MethodDelete, "/f.txt", tok, carrierHeader, nil)
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", w.Code)
	}
	if got := w.Header().Get("Allow"); got != "GET, POST" {
		t.Errorf("Allow = %q, want 'GET, POST'", got)
	}
}

// TestFiles_DisabledReturns404 ensures a proxy started without WithFiles
// returns an opaque 404 on boxd-port traffic rather than leaking that the
// feature exists but is off.
func TestFiles_DisabledReturns404(t *testing.T) {
	env := newFilesTestEnv(t)
	env.handler.filesEnabled = false

	tok := env.mintToken(auth.ScopeFiles, "")
	req := env.buildRequest(http.MethodGet, "/f.txt", tok, carrierHeader, nil)
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}
