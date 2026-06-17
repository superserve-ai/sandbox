package secretsproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// stubResolver accepts a fixed JWT string. Tests use this to exercise the
// proxy without standing up a full Verifier + JWKS.
type stubResolver struct {
	wantJWT  string
	scopeOut *Scope
	calls    int
}

func (s *stubResolver) Authenticate(_ context.Context, _ string, jwt string) (*Scope, error) {
	s.calls++
	if jwt == s.wantJWT {
		return s.scopeOut, nil
	}
	return nil, ErrUnknownSandbox
}

// setupProxy stands up a Proxy bound to a random port plus an httptest HTTPS upstream.
// opt overrides apply on top of the default Options (CA, Resolver, transport, revoker).
func setupProxy(t *testing.T, resolver Resolver, opts ...func(*Options)) (proxyAddr string, upstream *httptest.Server, ca *CA, revoker *Revoker) {
	t.Helper()

	upstream = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream-Saw-Path", r.URL.Path)
		w.Header().Set("X-Upstream-Saw-Method", r.Method)
		w.Header().Set("X-Upstream-Auth", r.Header.Get("Authorization"))
		_, _ = io.WriteString(w, "hello from upstream\n")
	}))
	t.Cleanup(upstream.Close)

	dir := t.TempDir()
	var err error
	ca, err = NewCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), 32)
	if err != nil {
		t.Fatal(err)
	}

	// Permissive transport for the test: trust the httptest server's cert.
	upstreamCert := upstream.Certificate()
	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstreamCert)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    upstreamPool,
		},
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
	}

	revoker = NewRevoker()
	pOpts := Options{
		CA:                ca,
		Resolver:          resolver,
		UpstreamTransport: tr,
		Revoker:           revoker,
	}
	for _, fn := range opts {
		fn(&pOpts)
	}
	p := NewProxy("127.0.0.1:0", pOpts)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyAddr = l.Addr().String()

	go func() { _ = p.Serve(l) }()
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })

	for i := 0; i < 50; i++ {
		if p.IsListening() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !p.IsListening() {
		t.Fatal("proxy never reported listening")
	}
	return proxyAddr, upstream, ca, revoker
}

// dialProxy opens a TLS connection to the proxy ingress.
func dialProxy(t *testing.T, proxyAddr string, ca *CA) net.Conn {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.RootPEM()) {
		t.Fatal("failed to add CA to pool")
	}
	conf := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    pool,
		ServerName: "127.0.0.1",
	}
	conn, err := tls.Dial("tcp", proxyAddr, conf)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

// sendConnect writes a CONNECT request and reads the proxy's response line.
// The auth header carries Basic base64("sb:<jwt>") — user portion is fixed,
// JWT is the password.
func sendConnect(t *testing.T, conn net.Conn, target, jwtString string) (statusLine string, ok bool) {
	t.Helper()
	auth := base64.StdEncoding.EncodeToString([]byte("sb:" + jwtString))
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n", target, target, auth)
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	statusLine = strings.TrimRight(statusLine, "\r\n")
	// Drain headers so the conn is at the inner TLS handshake boundary.
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			break
		}
		if line == "\r\n" {
			break
		}
	}
	return statusLine, strings.HasPrefix(statusLine, "HTTP/1.1 200")
}

func TestProxyConnectAndForward(t *testing.T) {
	const testJWT = "test-jwt-string"
	resolver := &stubResolver{wantJWT: testJWT, scopeOut: &Scope{SandboxID: "sandbox-1", TeamID: "team-1"}}
	proxyAddr, upstream, ca, _ := setupProxy(t, resolver)
	upstreamURL, _ := url.Parse(upstream.URL)

	conn := dialProxy(t, proxyAddr, ca)
	defer conn.Close()

	target := upstreamURL.Host
	status, ok := sendConnect(t, conn, target, testJWT)
	if !ok {
		t.Fatalf("CONNECT failed: %q", status)
	}

	// Inner TLS handshake; trust the proxy CA that signed the leaf.
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.RootPEM())
	upstreamHost, _, _ := net.SplitHostPort(target)
	tlsClient := tls.Client(conn, &tls.Config{
		ServerName: upstreamHost,
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("inner TLS handshake: %v", err)
	}

	// Send a regular HTTP/1.1 request through the tunnel.
	req := fmt.Sprintf("GET /test-path HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer sk-proxy-aaa\r\n\r\n", target)
	if _, err := tlsClient.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(tlsClient)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: want 200, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Upstream-Saw-Path"); got != "/test-path" {
		t.Errorf("upstream path: want /test-path, got %q", got)
	}
	if got := resp.Header.Get("X-Upstream-Saw-Method"); got != "GET" {
		t.Errorf("upstream method: want GET, got %q", got)
	}
	if got := resp.Header.Get("X-Upstream-Auth"); got != "Bearer sk-proxy-aaa" {
		t.Errorf("passthrough (no inject pipeline) should forward Authorization unchanged, got %q", got)
	}
	if !strings.Contains(string(body), "hello from upstream") {
		t.Errorf("body: want upstream payload, got %q", string(body))
	}
	if resolver.calls != 1 {
		t.Errorf("Resolver.Authenticate called %d times, want 1", resolver.calls)
	}
}

func TestProxyRejectsMissingProxyAuth(t *testing.T) {
	resolver := &stubResolver{wantJWT: "x", scopeOut: &Scope{}}
	proxyAddr, upstream, ca, _ := setupProxy(t, resolver)
	upstreamURL, _ := url.Parse(upstream.URL)

	conn := dialProxy(t, proxyAddr, ca)
	defer conn.Close()

	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", upstreamURL.Host, upstreamURL.Host)
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	statusLine, _ := br.ReadString('\n')
	if !strings.Contains(statusLine, "407") {
		t.Errorf("want 407 Proxy Authentication Required, got %q", strings.TrimSpace(statusLine))
	}
	if resolver.calls != 0 {
		t.Errorf("Resolver should not be reached for missing auth header, got %d calls", resolver.calls)
	}
}

func TestProxyRejectsUnknownSandbox(t *testing.T) {
	resolver := &stubResolver{wantJWT: "good-jwt", scopeOut: &Scope{SandboxID: "sandbox-1", TeamID: "team-1"}}
	proxyAddr, upstream, ca, _ := setupProxy(t, resolver)
	upstreamURL, _ := url.Parse(upstream.URL)

	conn := dialProxy(t, proxyAddr, ca)
	defer conn.Close()

	status, ok := sendConnect(t, conn, upstreamURL.Host, "wrong-jwt")
	if ok {
		t.Fatalf("CONNECT should have failed for unknown sandbox; got %q", status)
	}
	if !strings.Contains(status, "407") {
		t.Errorf("want 407 on unknown sandbox, got %q", status)
	}
	if resolver.calls != 1 {
		t.Errorf("Resolver.Authenticate calls: want 1, got %d", resolver.calls)
	}
}

func TestProxyRejectsRevokedSandbox(t *testing.T) {
	resolver := &stubResolver{wantJWT: "good-jwt", scopeOut: &Scope{SandboxID: "sandbox-1", TeamID: "team-1"}}
	proxyAddr, upstream, ca, revoker := setupProxy(t, resolver)
	upstreamURL, _ := url.Parse(upstream.URL)
	revoker.RevokeSandbox("sandbox-1")

	conn := dialProxy(t, proxyAddr, ca)
	defer conn.Close()

	status, ok := sendConnect(t, conn, upstreamURL.Host, "good-jwt")
	if ok {
		t.Fatalf("CONNECT must fail when sandbox is revoked; got %q", status)
	}
	if !strings.Contains(status, "403") {
		t.Errorf("want 403 on revoked sandbox, got %q", status)
	}
}

func TestProxyRejectsBlockedPort(t *testing.T) {
	resolver := &stubResolver{wantJWT: "good-jwt", scopeOut: &Scope{SandboxID: "sandbox-1", TeamID: "team-1"}}
	proxyAddr, _, ca, _ := setupProxy(t, resolver, func(o *Options) {
		o.BlockedPorts = []int{4444}
	})

	conn := dialProxy(t, proxyAddr, ca)
	defer conn.Close()

	status, ok := sendConnect(t, conn, "example.com:4444", "good-jwt")
	if ok {
		t.Fatalf("CONNECT to a blocked port must fail; got %q", status)
	}
	if !strings.Contains(status, "403") {
		t.Errorf("want 403 on blocked port, got %q", status)
	}
}

func TestProxyRejectsInternalAddress(t *testing.T) {
	resolver := &stubResolver{wantJWT: "good-jwt", scopeOut: &Scope{SandboxID: "sandbox-1", TeamID: "team-1"}}
	proxyAddr, _, ca, _ := setupProxy(t, resolver, func(o *Options) {
		o.BlockInternalAddrs = true
	})

	conn := dialProxy(t, proxyAddr, ca)
	defer conn.Close()

	status, ok := sendConnect(t, conn, "169.254.169.254:443", "good-jwt")
	if ok {
		t.Fatalf("CONNECT to an internal IP must fail; got %q", status)
	}
	if !strings.Contains(status, "403") {
		t.Errorf("want 403 on internal address, got %q", status)
	}
}

func TestIsBlockedPort(t *testing.T) {
	p := NewProxy("127.0.0.1:0", Options{BlockedPorts: []int{4444, 3333}})
	cases := []struct {
		port string
		want bool
	}{
		{"4444", true},
		{"3333", true},
		{"443", false},
		{"notaport", false}, // unparseable → not blocked
		{"", false},
	}
	for _, c := range cases {
		if got := p.isBlockedPort(c.port); got != c.want {
			t.Errorf("isBlockedPort(%q) = %v, want %v", c.port, got, c.want)
		}
	}
	if NewProxy("127.0.0.1:0", Options{}).isBlockedPort("4444") {
		t.Error("no blocked ports configured: 4444 should not be blocked")
	}
}

func TestProxyRejectsNonConnectInV1(t *testing.T) {
	resolver := &stubResolver{wantJWT: "x", scopeOut: &Scope{}}
	proxyAddr, _, ca, _ := setupProxy(t, resolver)

	conn := dialProxy(t, proxyAddr, ca)
	defer conn.Close()

	// Absolute-form forward-proxy request; daemon only supports CONNECT.
	req := "GET http://api.example.com/ HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	statusLine, _ := br.ReadString('\n')
	if !strings.Contains(statusLine, "400") {
		t.Errorf("want 400 on non-CONNECT, got %q", strings.TrimSpace(statusLine))
	}
}

func TestCopyForwardableHeadersStripsHopByHop(t *testing.T) {
	src := http.Header{
		"Content-Type":        {"application/json"},
		"Connection":          {"close"},
		"Keep-Alive":          {"timeout=5"},
		"Proxy-Authorization": {"Basic xxxx"},
		"Authorization":       {"Bearer real-key"},
		"X-Trace-Id":          {"abc"},
	}
	dst := http.Header{}
	copyForwardableHeaders(src, dst)

	if dst.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type not forwarded")
	}
	if dst.Get("Authorization") != "Bearer real-key" {
		t.Errorf("Authorization should be forwarded by copyForwardableHeaders")
	}
	if dst.Get("X-Trace-Id") != "abc" {
		t.Errorf("X-Trace-Id not forwarded")
	}
	for _, h := range []string{"Connection", "Keep-Alive", "Proxy-Authorization"} {
		if dst.Get(h) != "" {
			t.Errorf("hop-by-hop header %s should have been stripped", h)
		}
	}
}

// recordingAudit captures every event the proxy emits. The zero value is ready
// to use; cond is created lazily so &recordingAudit{} stays valid.
type recordingAudit struct {
	mu     sync.Mutex
	cond   *sync.Cond
	events []AuditEvent
}

// condLocked returns the broadcast condition, creating it on first use. Caller holds mu.
func (r *recordingAudit) condLocked() *sync.Cond {
	if r.cond == nil {
		r.cond = sync.NewCond(&r.mu)
	}
	return r.cond
}

func (r *recordingAudit) Emit(ev AuditEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
	r.condLocked().Broadcast()
}
func (r *recordingAudit) Shutdown(_ context.Context) error { return nil }
func (r *recordingAudit) snapshot() []AuditEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]AuditEvent, len(r.events))
	copy(out, r.events)
	return out
}

// waitForEvents blocks until at least n events are emitted or the timeout
// elapses, then snapshots. The proxy emits the audit row after forwarding the
// response, which can land just after the client's headers-only ReadResponse
// returns — so a single snapshot races the emit. The watchdog wakes the waiter
// on timeout, leaving a missing event to fail the caller's assertion.
func (r *recordingAudit) waitForEvents(t *testing.T, n int) []AuditEvent {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	cond := r.condLocked()

	timedOut := false
	timer := time.AfterFunc(2*time.Second, func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		timedOut = true
		cond.Broadcast()
	})
	defer timer.Stop()

	for len(r.events) < n && !timedOut {
		cond.Wait()
	}
	out := make([]AuditEvent, len(r.events))
	copy(out, r.events)
	return out
}

// setupProxyWithInject stands up a Proxy whose resolver returns the supplied
// scope verbatim on any JWT match. The injected scope drives the egress +
// inject pipeline as if a verified JWT had carried those claims.
func setupProxyWithInject(t *testing.T, scope *Scope, vault VaultClient) (proxyAddr string, upstream *httptest.Server, ca *CA, audit *recordingAudit, jwt string) {
	t.Helper()

	upstream = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream-Auth", r.Header.Get("Authorization"))
		w.Header().Set("X-Upstream-ApiKey", r.Header.Get("x-api-key"))
		_, _ = io.WriteString(w, "ok\n")
	}))
	t.Cleanup(upstream.Close)

	dir := t.TempDir()
	var err error
	ca, err = NewCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), 32)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(upstream.Certificate())
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}

	jwt = "test-jwt-for-" + scope.SandboxID
	audit = &recordingAudit{}
	p := NewProxy("127.0.0.1:0", Options{
		CA:                ca,
		Resolver:          &stubResolver{wantJWT: jwt, scopeOut: scope},
		Vault:             vault,
		Audit:             audit,
		UpstreamTransport: tr,
	})

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyAddr = l.Addr().String()
	go func() { _ = p.Serve(l) }()
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })

	for i := 0; i < 50; i++ {
		if p.IsListening() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !p.IsListening() {
		t.Fatal("proxy not listening")
	}
	return proxyAddr, upstream, ca, audit, jwt
}

func TestProxyInjectsBearerEndToEnd(t *testing.T) {
	scope := &Scope{
		SandboxID: "sb-1",
		TeamID:    "team-1",
		SourceIP:  "127.0.0.1",
		Bindings: map[string]Binding{
			"proxy-anth-aaa": {
				SecretID:   "sec-anthropic",
				EnvKey:     "ANTHROPIC_API_KEY",
				AuthType:   "bearer",
				AuthConfig: map[string]any{},
				Hosts:      []string{"127.0.0.1"}, // httptest binds 127.0.0.1
			},
		},
	}
	vault := &stubVault{values: map[string]string{"sec-anthropic": "sk-ant-REAL"}}

	proxyAddr, upstream, ca, audit, jwt := setupProxyWithInject(t, scope, vault)
	upstreamURL, _ := url.Parse(upstream.URL)

	conn := dialProxy(t, proxyAddr, ca)
	defer conn.Close()

	status, ok := sendConnect(t, conn, upstreamURL.Host, jwt)
	if !ok {
		t.Fatalf("CONNECT failed: %q", status)
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.RootPEM())
	upstreamHost, _, _ := net.SplitHostPort(upstreamURL.Host)
	tlsClient := tls.Client(conn, &tls.Config{
		ServerName: upstreamHost,
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("inner TLS handshake: %v", err)
	}

	req := fmt.Sprintf(
		"GET /v1/messages HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer proxy-anth-aaa\r\n\r\n",
		upstreamURL.Host,
	)
	if _, err := tlsClient.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsClient), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: want 200, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Upstream-Auth"); got != "Bearer sk-ant-REAL" {
		t.Errorf("upstream received %q, want %q", got, "Bearer sk-ant-REAL")
	}

	events := audit.waitForEvents(t, 1)
	if len(events) != 1 {
		t.Fatalf("audit: want 1 event, got %d (%+v)", len(events), events)
	}
	got := events[0]
	if got.Status != http.StatusOK {
		t.Errorf("audit.Status: want 200, got %d", got.Status)
	}
	if got.UpstreamStatus == nil || *got.UpstreamStatus != http.StatusOK {
		t.Errorf("audit.UpstreamStatus: want *200, got %v", got.UpstreamStatus)
	}
	if got.SecretID != "sec-anthropic" {
		t.Errorf("audit.SecretID: want sec-anthropic, got %q", got.SecretID)
	}
	if got.SandboxID != "sb-1" || got.TeamID != "team-1" {
		t.Errorf("audit identity drift: %+v", got)
	}
	if got.Method != "GET" || got.Host == "" || got.Path != "/v1/messages" {
		t.Errorf("audit request-shape drift: %+v", got)
	}
	if got.ErrorCode != "" {
		t.Errorf("audit.ErrorCode on success should be empty, got %q", got.ErrorCode)
	}
}

func TestProxyDeniesHostNotInCredentialAllowlist(t *testing.T) {
	scope := &Scope{
		SandboxID: "sb-1",
		TeamID:    "team-1",
		SourceIP:  "127.0.0.1",
		Bindings: map[string]Binding{
			"proxy-openai-aaa": {
				SecretID:   "sec-openai",
				AuthType:   "bearer",
				AuthConfig: map[string]any{},
				Hosts:      []string{"api.openai.com"},
			},
		},
	}
	vault := &stubVault{values: map[string]string{"sec-openai": "sk-REAL"}}

	proxyAddr, upstream, ca, audit, jwt := setupProxyWithInject(t, scope, vault)
	upstreamURL, _ := url.Parse(upstream.URL)

	conn := dialProxy(t, proxyAddr, ca)
	defer conn.Close()
	status, ok := sendConnect(t, conn, upstreamURL.Host, jwt)
	if !ok {
		t.Fatalf("CONNECT failed: %q", status)
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.RootPEM())
	upstreamHost, _, _ := net.SplitHostPort(upstreamURL.Host)
	tlsClient := tls.Client(conn, &tls.Config{
		ServerName: upstreamHost, RootCAs: pool, MinVersion: tls.VersionTLS12,
	})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("inner TLS handshake: %v", err)
	}

	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer proxy-openai-aaa\r\n\r\n", upstreamURL.Host)
	_, _ = tlsClient.Write([]byte(req))
	resp, err := http.ReadResponse(bufio.NewReader(tlsClient), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status: want 403, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Superserve-Proxy-Error"); got != "true" {
		t.Errorf("X-Superserve-Proxy-Error header missing, got %q", got)
	}
	if reason := resp.Header.Get("X-Superserve-Proxy-Reason"); reason != "credential_host_mismatch" {
		t.Errorf("reason: want credential_host_mismatch, got %q", reason)
	}

	events := audit.waitForEvents(t, 1)
	if len(events) != 1 {
		t.Fatalf("audit: want 1 deny event, got %d (%+v)", len(events), events)
	}
	ev := events[0]
	if ev.Status != http.StatusForbidden {
		t.Errorf("audit.Status: want 403, got %d", ev.Status)
	}
	if ev.UpstreamStatus != nil {
		t.Errorf("audit.UpstreamStatus: want nil on deny, got %v", *ev.UpstreamStatus)
	}
	if ev.ErrorCode != "credential_host_mismatch" {
		t.Errorf("audit.ErrorCode: want credential_host_mismatch, got %q", ev.ErrorCode)
	}
	if ev.SecretID != "sec-openai" {
		t.Errorf("audit.SecretID: want sec-openai on credential-host-mismatch, got %q", ev.SecretID)
	}
}

func TestOneShotListener(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	l := newOneShotListener(serverConn)
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if c != serverConn {
		t.Errorf("first Accept should yield the wrapped conn")
	}
	// Second Accept blocks until Close.
	done := make(chan error, 1)
	go func() {
		_, err := l.Accept()
		done <- err
	}()
	select {
	case <-done:
		t.Fatal("second Accept returned before Close")
	case <-time.After(50 * time.Millisecond):
	}
	_ = l.Close()
	select {
	case err := <-done:
		if !errors.Is(err, errOneShotListenerClosed) {
			t.Errorf("want errOneShotListenerClosed, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Accept did not return after Close")
	}
	// Double-close should be safe.
	_ = l.Close()
}

// TestProxyTLS_SANFallbacks: when SNI is empty, the leaf cert SAN must
// match SandboxFacingHost.
func TestProxyTLS_SANFallbacks(t *testing.T) {
	dir := t.TempDir()
	ca, err := NewCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), 16)
	if err != nil {
		t.Fatal(err)
	}

	p := NewProxy("127.0.0.1:0", Options{
		CA:                ca,
		Resolver:          &stubResolver{},
		SandboxFacingHost: "192.0.2.1",
	})

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = p.Serve(l) }()
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })

	for i := 0; i < 50; i++ {
		if p.IsListening() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.RootPEM())

	conn, err := tls.Dial("tcp", l.Addr().String(), &tls.Config{
		RootCAs:            pool,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	leaf := conn.ConnectionState().PeerCertificates[0]
	wantIP := net.ParseIP("192.0.2.1")
	found := false
	for _, ip := range leaf.IPAddresses {
		if ip.Equal(wantIP) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("leaf SAN missing %s; got DNS=%v IP=%v", wantIP, leaf.DNSNames, leaf.IPAddresses)
	}
}

func TestProxyRejectsOversizedBodyWith413(t *testing.T) {
	// A body larger than MaxRequestBodyBytes must surface as 413 Payload
	// Too Large with a body_too_large reason so the agent can handle it.
	const testJWT = "test-jwt-body"
	const limit = 1024
	resolver := &stubResolver{wantJWT: testJWT, scopeOut: &Scope{SandboxID: "sb-body", TeamID: "team-1"}}
	proxyAddr, upstream, ca, _ := setupProxy(t, resolver,
		func(o *Options) { o.MaxRequestBodyBytes = limit },
	)
	upstreamURL, _ := url.Parse(upstream.URL)

	conn := dialProxy(t, proxyAddr, ca)
	defer conn.Close()

	target := upstreamURL.Host
	status, ok := sendConnect(t, conn, target, testJWT)
	if !ok {
		t.Fatalf("CONNECT failed: %q", status)
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.RootPEM())
	upstreamHost, _, _ := net.SplitHostPort(target)
	tlsClient := tls.Client(conn, &tls.Config{
		ServerName: upstreamHost, RootCAs: pool, MinVersion: tls.VersionTLS12,
	})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("inner TLS handshake: %v", err)
	}

	// Send a body comfortably larger than the limit.
	body := strings.Repeat("X", limit*4)
	req := fmt.Sprintf(
		"POST /large HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n%s",
		target, len(body), body,
	)
	if _, err := tlsClient.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(tlsClient)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status: want 413, got %d", resp.StatusCode)
	}
	if reason := resp.Header.Get("X-Superserve-Proxy-Reason"); reason != "body_too_large" {
		t.Errorf("proxy reason: want body_too_large, got %q", reason)
	}
	if flag := resp.Header.Get("X-Superserve-Proxy-Error"); flag != "true" {
		t.Errorf("proxy error flag missing, got %q", flag)
	}
}
