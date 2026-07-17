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
// Test harness — numeric preview ports (not the boxd label). Requests target
// port 3000 (see request()); publish 3000 to make it routable, publish some
// other port (or nothing) to exercise the deny-by-default 404.
// ---------------------------------------------------------------------------

const previewReqPort = 3000

type previewTestEnv struct {
	t          *testing.T
	seedKey    []byte
	handler    *Handler
	upstream   *httptest.Server
	sandboxID  string
	domain     string
	resolver   *stubResolver
	upstreamMu sync.Mutex
	lastReq    previewCapturedRequest
}

type previewCapturedRequest struct {
	method    string
	path      string
	rawQuery  string
	hasHeader bool
	cookies   string
	received  bool
}

// newPreviewTestEnv wires a proxy whose single sandbox has the given preview
// policy and published-port set (port → token version).
func newPreviewTestEnv(t *testing.T, access string, ports map[int]int64) *previewTestEnv {
	t.Helper()

	env := &previewTestEnv{
		t:         t,
		seedKey:   []byte("test-seed-key-that-is-at-least-32-bytes-long!!"),
		sandboxID: "sbx-" + strings.Repeat("p", 8),
		domain:    "sandbox.test",
	}

	env.upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		env.upstreamMu.Lock()
		env.lastReq = previewCapturedRequest{
			method:    r.Method,
			path:      r.URL.Path,
			rawQuery:  r.URL.RawQuery,
			hasHeader: r.Header.Get(previewTokenHeader) != "",
			cookies:   r.Header.Get("Cookie"),
			received:  true,
		}
		env.upstreamMu.Unlock()
		_, _ = w.Write([]byte("app response"))
	}))
	t.Cleanup(env.upstream.Close)

	upURL, _ := url.Parse(env.upstream.URL)
	env.resolver = &stubResolver{
		info: InstanceInfo{
			VMIP:          upURL.Hostname(),
			Status:        "running",
			StartedAt:     time.Now().UnixNano(),
			PreviewAccess: access,
			PreviewPorts:  ports,
		},
	}

	env.handler = NewHandler([]string{env.domain}, env.resolver, zerolog.Nop())
	env.handler.WithAuth(env.seedKey)

	upHost := upURL.Host
	env.handler.transports = &transportCache{items: map[string]*transportEntry{}}
	env.handler.transports.items[env.sandboxID] = &transportEntry{
		lifecycleKey: env.resolver.info.lifecycleKey(),
		transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, upHost)
			},
			DisableKeepAlives: true,
		},
		lastUsed: time.Now(),
	}

	return env
}

// publishedPort is a convenience for the common "port 3000 at version v" set.
func publishedPort(v int64) map[int]int64 { return map[int]int64{previewReqPort: v} }

func (e *previewTestEnv) token(claims auth.PreviewClaims) string {
	e.t.Helper()
	if claims.SandboxID == "" {
		claims.SandboxID = e.sandboxID
	}
	if claims.Port == 0 {
		claims.Port = previewReqPort
	}
	tok, err := auth.ComputePreviewToken(e.seedKey, claims)
	if err != nil {
		e.t.Fatalf("mint preview token: %v", err)
	}
	return tok
}

func (e *previewTestEnv) request(method, target string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	req.Host = "3000-" + e.sandboxID + "." + e.domain
	return req
}

func (e *previewTestEnv) serve(req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	e.handler.ServeHTTP(w, req)
	return w
}

func (e *previewTestEnv) captured() previewCapturedRequest {
	e.upstreamMu.Lock()
	defer e.upstreamMu.Unlock()
	return e.lastReq
}

// ---------------------------------------------------------------------------
// Legacy compatibility and strict public publication
// ---------------------------------------------------------------------------

func TestPreview_LegacyPublicNoCredentialNeeded(t *testing.T) {
	for _, access := range []string{"", auth.PreviewAccessLegacyPublic} {
		env := newPreviewTestEnv(t, access, nil)
		w := env.serve(env.request(http.MethodGet, "http://unused/index.html"))
		if w.Code != http.StatusOK {
			t.Fatalf("access=%q: status = %d, want 200; body: %s", access, w.Code, w.Body.String())
		}
		if !env.captured().received {
			t.Fatalf("access=%q: upstream never received the request", access)
		}
	}
}

func TestPreview_PublicUnpublishedPort404(t *testing.T) {
	env := newPreviewTestEnv(t, auth.PreviewAccessPublic, nil)
	w := env.serve(env.request(http.MethodGet, "http://unused/"))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for an unpublished public port", w.Code)
	}
	if env.captured().received {
		t.Error("unpublished public port reached the app")
	}
}

func TestPreview_PublicPublishedPortNeedsNoCredential(t *testing.T) {
	env := newPreviewTestEnv(t, auth.PreviewAccessPublic, publishedPort(1))
	w := env.serve(env.request(http.MethodGet, "http://unused/"))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if !env.captured().received {
		t.Fatal("published public port did not reach the app")
	}
}

func TestPreview_PublicPublishedPortStripsStrayCredential(t *testing.T) {
	env := newPreviewTestEnv(t, auth.PreviewAccessPublic, publishedPort(1))
	req := env.request(http.MethodGet, "http://unused/p?keep=1&"+previewQueryParam+"=old-token")
	req.Header.Set(previewTokenHeader, "old-token")
	req.AddCookie(&http.Cookie{Name: previewCookieName, Value: "old-token"})
	req.AddCookie(&http.Cookie{Name: "app_session", Value: "keep-me"})

	w := env.serve(req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	got := env.captured()
	if got.hasHeader {
		t.Error("preview token header forwarded to the app")
	}
	if strings.Contains(got.rawQuery, previewQueryParam) {
		t.Errorf("preview token query param forwarded to the app: %q", got.rawQuery)
	}
	if !strings.Contains(got.rawQuery, "keep=1") {
		t.Errorf("unrelated query params lost: %q", got.rawQuery)
	}
	if strings.Contains(got.cookies, previewCookieName) {
		t.Errorf("preview cookie forwarded to the app: %q", got.cookies)
	}
	if !strings.Contains(got.cookies, "app_session=keep-me") {
		t.Errorf("unrelated cookies lost: %q", got.cookies)
	}
}

// ---------------------------------------------------------------------------
// Deny-by-default: unpublished ports are not routable
// ---------------------------------------------------------------------------

func TestPreview_PrivateUnpublishedPort404(t *testing.T) {
	// Port 3000 is requested but only 3001 is published → 404, and a valid
	// token for 3000 does NOT change that (nothing is published for it).
	env := newPreviewTestEnv(t, auth.PreviewAccessPrivate, map[int]int64{3001: 1})
	req := env.request(http.MethodGet, "http://unused/")
	req.Header.Set(previewTokenHeader, env.token(auth.PreviewClaims{Port: 3000, Version: 1}))

	w := env.serve(req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for an unpublished port", w.Code)
	}
	if env.captured().received {
		t.Error("request for an unpublished port reached the app")
	}
}

func TestPreview_PrivateNothingPublishedDeniesEverything(t *testing.T) {
	env := newPreviewTestEnv(t, auth.PreviewAccessPrivate, nil)
	if w := env.serve(env.request(http.MethodGet, "http://unused/")); w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 when nothing is published", w.Code)
	}
}

func TestPreview_UnpublishedPortNotEvenValidTokenLeaksStatus(t *testing.T) {
	// 404 for an unpublished port must not depend on running/paused state.
	env := newPreviewTestEnv(t, auth.PreviewAccessPrivate, map[int]int64{3001: 1})
	env.resolver.info.Status = "paused"
	w := env.serve(env.request(http.MethodGet, "http://unused/"))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
	if strings.Contains(strings.ToLower(w.Body.String()), "paused") {
		t.Errorf("404 body leaks sandbox status: %q", w.Body.String())
	}
}

func TestPreview_UnknownPolicyValueFailsClosed(t *testing.T) {
	// A policy value this proxy doesn't know must behave like private
	// (deny-by-default), never public.
	env := newPreviewTestEnv(t, "team-only", nil)
	if w := env.serve(env.request(http.MethodGet, "http://unused/")); w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for unknown policy value", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Published-port auth — deny paths
// ---------------------------------------------------------------------------

func TestPreview_PublishedNoCredential401(t *testing.T) {
	env := newPreviewTestEnv(t, auth.PreviewAccessPrivate, publishedPort(1))
	w := env.serve(env.request(http.MethodGet, "http://unused/"))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if env.captured().received {
		t.Error("unauthenticated request reached the app")
	}
}

func TestPreview_PublishedPausedDoesNotLeakStatus(t *testing.T) {
	env := newPreviewTestEnv(t, auth.PreviewAccessPrivate, publishedPort(1))
	env.resolver.info.Status = "paused"

	w := env.serve(env.request(http.MethodGet, "http://unused/"))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want 401", w.Code)
	}
	if strings.Contains(strings.ToLower(w.Body.String()), "paused") {
		t.Errorf("401 body leaks sandbox status: %q", w.Body.String())
	}

	req := env.request(http.MethodGet, "http://unused/")
	req.Header.Set(previewTokenHeader, env.token(auth.PreviewClaims{Version: 1}))
	if w := env.serve(req); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("authenticated status = %d, want 503", w.Code)
	}
}

func TestPreview_PublishedBadTokens401(t *testing.T) {
	env := newPreviewTestEnv(t, auth.PreviewAccessPrivate, publishedPort(2))
	cases := map[string]string{
		"garbage":       "not-a-token",
		"stale version": env.token(auth.PreviewClaims{Version: 1}),
		"wrong sandbox": env.token(auth.PreviewClaims{SandboxID: "sbx-other", Version: 2}),
		"wrong port":    env.token(auth.PreviewClaims{Port: 4000, Version: 2}),
		"expired":       env.token(auth.PreviewClaims{Version: 2, ExpiresAt: time.Now().Add(-time.Minute).Unix()}),
		"boxd token":    auth.ComputeAccessToken(env.seedKey, env.sandboxID),
	}
	for name, tok := range cases {
		req := env.request(http.MethodGet, "http://unused/")
		req.Header.Set(previewTokenHeader, tok)
		if w := env.serve(req); w.Code != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401", name, w.Code)
		}
	}
	if env.captured().received {
		t.Error("a rejected request reached the app")
	}
}

func TestPreview_PublishedNoSeedFailsClosed(t *testing.T) {
	env := newPreviewTestEnv(t, auth.PreviewAccessPrivate, publishedPort(1))
	tok := env.token(auth.PreviewClaims{Version: 1})
	env.handler.seedKey = nil

	req := env.request(http.MethodGet, "http://unused/")
	req.Header.Set(previewTokenHeader, tok)
	if w := env.serve(req); w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Published-port auth — allow paths
// ---------------------------------------------------------------------------

func TestPreview_PublishedHeaderToken(t *testing.T) {
	env := newPreviewTestEnv(t, auth.PreviewAccessPrivate, publishedPort(1))
	req := env.request(http.MethodGet, "http://unused/api/data?x=1")
	req.Header.Set(previewTokenHeader, env.token(auth.PreviewClaims{Version: 1}))

	w := env.serve(req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	got := env.captured()
	if !got.received {
		t.Fatal("upstream never received the request")
	}
	if got.hasHeader {
		t.Error("preview token header forwarded to the app")
	}
	if got.rawQuery != "x=1" {
		t.Errorf("query = %q, want x=1", got.rawQuery)
	}
}

func TestPreview_PublishedCookieToken(t *testing.T) {
	env := newPreviewTestEnv(t, auth.PreviewAccessPrivate, publishedPort(1))
	req := env.request(http.MethodGet, "http://unused/")
	req.AddCookie(&http.Cookie{Name: previewCookieName, Value: env.token(auth.PreviewClaims{Version: 1})})
	req.AddCookie(&http.Cookie{Name: "app_session", Value: "keep-me"})

	w := env.serve(req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	got := env.captured()
	if strings.Contains(got.cookies, previewCookieName) {
		t.Errorf("preview cookie forwarded to the app: %q", got.cookies)
	}
	if !strings.Contains(got.cookies, "app_session=keep-me") {
		t.Errorf("unrelated cookies lost: %q", got.cookies)
	}
}

func TestPreview_PublishedOptionsPreflightPassesThrough(t *testing.T) {
	env := newPreviewTestEnv(t, auth.PreviewAccessPrivate, publishedPort(1))
	w := env.serve(env.request(http.MethodOptions, "http://unused/api"))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if got := env.captured(); !got.received || got.method != http.MethodOptions {
		t.Fatalf("preflight did not reach the app: %+v", got)
	}
}

func TestPreview_UnpublishedOptionsIs404(t *testing.T) {
	// A preflight for an unpublished port is denied like any other request.
	env := newPreviewTestEnv(t, auth.PreviewAccessPrivate, map[int]int64{3001: 1})
	if w := env.serve(env.request(http.MethodOptions, "http://unused/api")); w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Query-param bootstrap → cookie
// ---------------------------------------------------------------------------

func TestPreview_QueryBootstrapRedirectsAndSetsCookie(t *testing.T) {
	env := newPreviewTestEnv(t, auth.PreviewAccessPrivate, publishedPort(1))
	tok := env.token(auth.PreviewClaims{Version: 1})
	req := env.request(http.MethodGet, "http://unused/dash?a=1&"+previewQueryParam+"="+url.QueryEscape(tok)+"&b=2")

	w := env.serve(req)
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body: %s", w.Code, w.Body.String())
	}
	if env.captured().received {
		t.Error("bootstrap request reached the app before the redirect")
	}

	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if loc.Path != "/dash" {
		t.Errorf("Location path = %q, want /dash", loc.Path)
	}
	q := loc.Query()
	if q.Get(previewQueryParam) != "" {
		t.Error("token still present in the redirect Location")
	}
	if q.Get("a") != "1" || q.Get("b") != "2" {
		t.Errorf("unrelated query params lost in redirect: %q", loc.RawQuery)
	}

	setCookie := w.Header().Get("Set-Cookie")
	for _, want := range []string{previewCookieName + "=", "Path=/", "Secure", "HttpOnly", "SameSite=None", "Partitioned"} {
		if !strings.Contains(setCookie, want) {
			t.Errorf("Set-Cookie missing %q: %q", want, setCookie)
		}
	}
	if !strings.Contains(setCookie, tok) {
		t.Error("Set-Cookie does not carry the presented token")
	}
	if w.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Error("bootstrap redirect missing Referrer-Policy: no-referrer")
	}
	if !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
		t.Error("bootstrap redirect missing Cache-Control: no-store")
	}

	follow := env.request(http.MethodGet, "http://unused"+loc.String())
	follow.AddCookie(&http.Cookie{Name: previewCookieName, Value: tok})
	if w := env.serve(follow); w.Code != http.StatusOK {
		t.Fatalf("follow-up status = %d, want 200", w.Code)
	}
}

func TestPreview_QueryInvalidToken401NoCookie(t *testing.T) {
	env := newPreviewTestEnv(t, auth.PreviewAccessPrivate, publishedPort(1))
	req := env.request(http.MethodGet, "http://unused/?"+previewQueryParam+"=bogus")
	w := env.serve(req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if w.Header().Get("Set-Cookie") != "" {
		t.Error("Set-Cookie issued for an invalid token")
	}
}

func TestPreview_QueryTokenOnPostForwardsWithoutRedirect(t *testing.T) {
	env := newPreviewTestEnv(t, auth.PreviewAccessPrivate, publishedPort(1))
	tok := env.token(auth.PreviewClaims{Version: 1})
	req := env.request(http.MethodPost, "http://unused/submit?"+previewQueryParam+"="+url.QueryEscape(tok))

	w := env.serve(req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (POST must not be redirected)", w.Code)
	}
	got := env.captured()
	if !got.received {
		t.Fatal("upstream never received the POST")
	}
	if strings.Contains(got.rawQuery, previewQueryParam) {
		t.Errorf("token query param forwarded to the app: %q", got.rawQuery)
	}
}

func TestPreview_QueryTokenOnUpgradeForwardsWithoutRedirect(t *testing.T) {
	env := newPreviewTestEnv(t, auth.PreviewAccessPrivate, publishedPort(1))
	tok := env.token(auth.PreviewClaims{Version: 1})
	req := env.request(http.MethodGet, "http://unused/hmr?"+previewQueryParam+"="+url.QueryEscape(tok))
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")

	w := env.serve(req)
	if w.Code == http.StatusFound {
		t.Fatal("Upgrade request was redirected; WebSocket clients cannot follow redirects")
	}
	got := env.captured()
	if !got.received {
		t.Fatal("upstream never received the upgrade request")
	}
	if strings.Contains(got.rawQuery, previewQueryParam) {
		t.Errorf("token query param forwarded to the app: %q", got.rawQuery)
	}
}

func TestPreview_StaleCookieFreshQueryParamStillBootstraps(t *testing.T) {
	env := newPreviewTestEnv(t, auth.PreviewAccessPrivate, publishedPort(2))
	fresh := env.token(auth.PreviewClaims{Version: 2})
	stale := env.token(auth.PreviewClaims{Version: 2, ExpiresAt: time.Now().Add(-time.Minute).Unix()})

	req := env.request(http.MethodGet, "http://unused/?"+previewQueryParam+"="+url.QueryEscape(fresh))
	req.AddCookie(&http.Cookie{Name: previewCookieName, Value: stale})
	w := env.serve(req)
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 bootstrap despite stale cookie", w.Code)
	}
}
