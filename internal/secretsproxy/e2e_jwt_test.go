package secretsproxy

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"
)

// jwksHTTP serves a single Ed25519 public key under /internal/jwks. Stands in
// for the control plane in tests that need a real JWKS-backed verifier.
func jwksHTTP(t *testing.T, kid string, pub ed25519.PublicKey) *httptest.Server {
	t.Helper()
	body, _ := json.Marshal(JWKSResponse{Keys: []JWKSKey{{
		Kid: kid,
		Kty: "OKP",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(pub),
	}}})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// JWKSResponse / JWKSKey mirror what the control plane's /internal/jwks emits.
// Mirrored locally so the test doesn't import the api package.
type JWKSResponse struct {
	Keys []JWKSKey `json:"keys"`
}
type JWKSKey struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
}

// e2eDaemon brings up a full proxy stack (CA, JWKS-backed Verifier, JWTResolver,
// vault, audit) — exactly what the production daemon does, minus the unix
// control socket. Tests assert that requests carrying a JWT signed by jwksKey
// succeed against the running upstream.
type e2eDaemon struct {
	proxyAddr string
	ca        *CA
	audit     *recordingAudit
}

func startE2EDaemon(t *testing.T, jwksURL string, vault VaultClient, upstreamCert *x509.Certificate) *e2eDaemon {
	t.Helper()

	dir := t.TempDir()
	ca, err := NewCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), 32)
	if err != nil {
		t.Fatal(err)
	}

	fetcher := NewHTTPJWKSFetcher(jwksURL, "test-tok")
	verifier, err := NewVerifier(context.Background(), fetcher)
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	resolver := NewJWTResolver(verifier)

	pool := x509.NewCertPool()
	pool.AddCert(upstreamCert)
	upstreamTr := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool},
	}

	audit := &recordingAudit{}
	p := NewProxy("127.0.0.1:0", Options{
		CA:                ca,
		Resolver:          resolver,
		Vault:             vault,
		Audit:             audit,
		UpstreamTransport: upstreamTr,
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
	if !p.IsListening() {
		t.Fatal("proxy never came up")
	}

	return &e2eDaemon{proxyAddr: l.Addr().String(), ca: ca, audit: audit}
}

// makeRequestThroughProxy opens a CONNECT tunnel with the supplied JWT, does
// the inner TLS handshake against the proxy's MITM leaf, sends a GET, and
// returns the parsed response. Caller closes resp.Body.
func makeRequestThroughProxy(t *testing.T, d *e2eDaemon, upstreamHostPort, jwtString string, headers map[string]string) *http.Response {
	t.Helper()

	conn := dialProxy(t, d.proxyAddr, d.ca)
	t.Cleanup(func() { _ = conn.Close() })

	status, ok := sendConnect(t, conn, upstreamHostPort, jwtString)
	if !ok {
		t.Fatalf("CONNECT failed: %q", status)
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(d.ca.RootPEM())
	host, _, _ := net.SplitHostPort(upstreamHostPort)
	tlsClient := tls.Client(conn, &tls.Config{
		ServerName: host,
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("inner TLS handshake: %v", err)
	}

	reqLine := fmt.Sprintf("GET /resource HTTP/1.1\r\nHost: %s\r\n", upstreamHostPort)
	for k, v := range headers {
		reqLine += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	reqLine += "\r\n"
	if _, err := tlsClient.Write([]byte(reqLine)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsClient), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp
}

// TestE2E_JWTPathInjectsCredentialEndToEnd builds the full daemon stack against
// a fake JWKS-serving control plane, mints a JWT signed by the control plane's
// key, sends a request through the proxy, and verifies the upstream sees the
// real credential (proving the inject pipeline runs end-to-end through the
// JWT verification + resolver path).
func TestE2E_JWTPathInjectsCredentialEndToEnd(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Fake control plane: serves JWKS.
	jwksSrv := jwksHTTP(t, "v1", pub)

	// Fake upstream: echoes back the Authorization header it observed.
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream-Auth", r.Header.Get("Authorization"))
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(upstream.Close)
	upstreamURL, _ := url.Parse(upstream.URL)

	vault := &stubVault{teamID: "team-e2e", values: map[string]string{"sec-anthropic": "sk-ant-REAL"}}

	d := startE2EDaemon(t, jwksSrv.URL, vault, upstream.Certificate())

	// Mint a JWT that authorizes 127.0.0.1 (loopback) with one binding.
	tok := signForTest(t, priv, "v1", JWTClaims{
		TeamID:   "team-e2e",
		SourceIP: "127.0.0.1",
		Bindings: []JWTBindingClaim{{
			ProxyToken: "proxy-anth-e2e",
			SecretID:   "sec-anthropic",
			EnvKey:     "ANTHROPIC_API_KEY",
			Hosts:      []string{"127.0.0.1"},
			AuthType:   "bearer",
			AuthConfig: map[string]any{},
		}},
	}, time.Now())

	resp := makeRequestThroughProxy(t, d, upstreamURL.Host, tok, map[string]string{
		"Authorization": "Bearer proxy-anth-e2e",
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: want 200, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Upstream-Auth"); got != "Bearer sk-ant-REAL" {
		t.Errorf("upstream Authorization: want %q, got %q", "Bearer sk-ant-REAL", got)
	}
	if events := d.audit.waitForEvents(t, 1); len(events) != 1 {
		t.Errorf("want exactly 1 audit event, got %d", len(events))
	}
}

// TestE2E_DaemonRestartDoesNotInvalidateJWT proves the headline property: a
// JWT minted before the daemon restarted still works against a freshly-started
// daemon (with empty in-memory state). This is the property that pause/resume
// and operational daemon restarts rely on.
func TestE2E_DaemonRestartDoesNotInvalidateJWT(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	jwksSrv := jwksHTTP(t, "v1", pub)

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream-Auth", r.Header.Get("Authorization"))
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(upstream.Close)
	upstreamURL, _ := url.Parse(upstream.URL)

	vault := &stubVault{teamID: "team-restart", values: map[string]string{"sec-1": "real-secret-value"}}

	// First daemon: agent's JWT is minted while this daemon is up.
	d1 := startE2EDaemon(t, jwksSrv.URL, vault, upstream.Certificate())
	tok := signForTest(t, priv, "v1", JWTClaims{
		TeamID:   "team-restart",
		SourceIP: "127.0.0.1",
		Bindings: []JWTBindingClaim{{
			ProxyToken: "proxy-x",
			SecretID:   "sec-1",
			EnvKey:     "SOME_KEY",
			Hosts:      []string{"127.0.0.1"},
			AuthType:   "bearer",
			AuthConfig: map[string]any{},
		}},
	}, time.Now())

	resp1 := makeRequestThroughProxy(t, d1, upstreamURL.Host, tok, map[string]string{
		"Authorization": "Bearer proxy-x",
	})
	defer resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first daemon: want 200, got %d", resp1.StatusCode)
	}
	if got := resp1.Header.Get("X-Upstream-Auth"); got != "Bearer real-secret-value" {
		t.Fatalf("first daemon: upstream Authorization mismatch: %q", got)
	}

	// "Restart" the daemon: stand up a brand-new daemon (new Verifier with
	// freshly-fetched JWKS, new in-memory anything). Reuse the same JWT —
	// it must still authenticate and inject correctly.
	d2 := startE2EDaemon(t, jwksSrv.URL, vault, upstream.Certificate())

	resp2 := makeRequestThroughProxy(t, d2, upstreamURL.Host, tok, map[string]string{
		"Authorization": "Bearer proxy-x",
	})
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("post-restart daemon: want 200, got %d", resp2.StatusCode)
	}
	if got := resp2.Header.Get("X-Upstream-Auth"); got != "Bearer real-secret-value" {
		t.Errorf("post-restart daemon: upstream Authorization mismatch: %q", got)
	}
}

// TestE2E_SourceIPMismatchIsRejected pins the two-factor scoping: a JWT
// claiming source_ip=X is rejected when the request lands from a different IP.
// The proxy hears CONNECTs over loopback (127.0.0.1), so a JWT claiming
// 10.99.99.99 must fail.
func TestE2E_SourceIPMismatchIsRejected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	jwksSrv := jwksHTTP(t, "v1", pub)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(upstream.Close)
	upstreamURL, _ := url.Parse(upstream.URL)

	d := startE2EDaemon(t, jwksSrv.URL, &stubVault{}, upstream.Certificate())

	tok := signForTest(t, priv, "v1", JWTClaims{
		TeamID:   "team-x",
		SourceIP: "10.99.99.99", // does NOT match 127.0.0.1
	}, time.Now())

	conn := dialProxy(t, d.proxyAddr, d.ca)
	defer conn.Close()

	status, ok := sendConnect(t, conn, upstreamURL.Host, tok)
	if ok {
		t.Fatalf("CONNECT should have failed for source-IP mismatch; got %q", status)
	}
	if status == "" {
		t.Error("empty status line on rejection")
	}
}
