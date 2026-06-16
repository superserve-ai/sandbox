package secretsproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestLogsDoNotLeakCredentialValues exercises the full proxy stack with real
// credentials and a captured slog output. It then scans every log line for
// the cleartext credential, JWT, and proxy token — none should appear.
//
// This is a regression check: any future change that accidentally adds the
// credential value to a log line (e.g., via err.Error() that wraps an HTTP
// request dump) will be caught here.
func TestLogsDoNotLeakCredentialValues(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	jwksSrv := jwksHTTP(t, "v1", pub)

	const (
		realCredentialValue = "sk-ant-VERY-SECRET-CREDENTIAL-VALUE"
		proxyTokenInEnv     = "proxy-tok-DO-NOT-LEAK"
	)

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(upstream.Close)
	upstreamURL, _ := url.Parse(upstream.URL)

	// Capture all slog output produced by the proxy.
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	dir := t.TempDir()
	ca, err := NewCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), 32)
	if err != nil {
		t.Fatal(err)
	}

	fetcher := NewHTTPJWKSFetcher(jwksSrv.URL, "test-tok")
	verifier, err := NewVerifier(context.Background(), fetcher)
	if err != nil {
		t.Fatal(err)
	}
	resolver := NewJWTResolver(verifier)

	pool := x509.NewCertPool()
	pool.AddCert(upstream.Certificate())
	upstreamTr := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool},
	}
	vault := &stubVault{values: map[string]string{"sec-1": realCredentialValue}}

	p := NewProxy("127.0.0.1:0", Options{
		CA:                ca,
		Resolver:          resolver,
		Vault:             vault,
		Audit:             &recordingAudit{},
		Logger:            logger,
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

	tok := signForTest(t, priv, "v1", JWTClaims{
		TeamID:   "team-1",
		SourceIP: "127.0.0.1",
		Bindings: []JWTBindingClaim{{
			ProxyToken: proxyTokenInEnv,
			SecretID:   "sec-1",
			EnvKey:     "ANTHROPIC_API_KEY",
			Hosts:      []string{"127.0.0.1"},
			AuthType:   "bearer",
			AuthConfig: map[string]any{},
		}},
	}, time.Now())

	// Drive a happy-path request through the proxy.
	conn := dialProxy(t, l.Addr().String(), ca)
	defer conn.Close()
	status, ok := sendConnect(t, conn, upstreamURL.Host, tok)
	if !ok {
		t.Fatalf("CONNECT failed: %q", status)
	}
	pool2 := x509.NewCertPool()
	pool2.AppendCertsFromPEM(ca.RootPEM())
	tlsClient := tls.Client(conn, &tls.Config{
		ServerName: "127.0.0.1",
		RootCAs:    pool2,
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatal(err)
	}
	req := "GET /x HTTP/1.1\r\nHost: " + upstreamURL.Host + "\r\nAuthorization: Bearer " + proxyTokenInEnv + "\r\n\r\n"
	if _, err := tlsClient.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsClient), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	// Also exercise the reject path; that's where errors with sensitive
	// substrings could most plausibly leak.
	badConn := dialProxy(t, l.Addr().String(), ca)
	defer badConn.Close()
	_, _ = sendConnect(t, badConn, upstreamURL.Host, "this-is-not-a-valid-jwt")

	logs := logBuf.String()
	forbidden := []string{realCredentialValue, tok, proxyTokenInEnv}
	for _, secret := range forbidden {
		if strings.Contains(logs, secret) {
			t.Errorf("log output contains forbidden substring: %q\nfull logs:\n%s", secret, logs)
		}
	}
}

