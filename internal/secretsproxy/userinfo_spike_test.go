package secretsproxy

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestLongUserinfoRoundTripsThroughHTTPTransport verifies that a ~10 KB
// opaque token in HTTPS_PROXY userinfo survives Go's http.Transport round-trip
// into a CONNECT request the daemon can parse. The JWT at our 32-binding cap
// is ~10 KB; this pins the transport-layer assumption that bound.
func TestLongUserinfoRoundTripsThroughHTTPTransport(t *testing.T) {
	// Pick a size that exceeds the worst-case JWT for our binding cap.
	rawTokenBytes := make([]byte, 8*1024)
	if _, err := rand.Read(rawTokenBytes); err != nil {
		t.Fatal(err)
	}
	longToken := base64.RawURLEncoding.EncodeToString(rawTokenBytes) // ~10.9 KB

	// Minimal proxy: accept the CONNECT, parse Proxy-Authorization, echo
	// the decoded userinfo back on a single-line response, then close.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	type seen struct {
		user, pass string
		err        error
	}
	seenCh := make(chan seen, 1)

	go func() {
		conn, err := l.Accept()
		if err != nil {
			seenCh <- seen{err: err}
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))

		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			seenCh <- seen{err: err}
			return
		}
		if req.Method != http.MethodConnect {
			seenCh <- seen{err: nil, user: "method=" + req.Method}
			return
		}

		header := req.Header.Get("Proxy-Authorization")
		const prefix = "Basic "
		if !strings.HasPrefix(header, prefix) {
			seenCh <- seen{err: nil, user: "missing-basic"}
			return
		}
		decoded, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(header[len(prefix):]))
		if derr != nil {
			seenCh <- seen{err: derr}
			return
		}
		creds := string(decoded)
		idx := strings.IndexByte(creds, ':')
		if idx < 0 {
			seenCh <- seen{err: nil, user: "no-colon"}
			return
		}
		seenCh <- seen{user: creds[:idx], pass: creds[idx+1:]}

		// Reject the tunnel (we only care about the CONNECT itself).
		_, _ = conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
	}()

	proxyURL := &url.URL{
		Scheme: "http",
		User:   url.UserPassword("sb", longToken),
		Host:   l.Addr().String(),
	}

	tr := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}

	// Any HTTPS URL will do; we'll get a CONNECT to that host:port. The
	// upstream is never actually reached because our fake proxy closes.
	_, err = client.Get("https://example.invalid/")
	if err == nil {
		t.Fatal("expected upstream connect to fail (fake proxy doesn't tunnel)")
	}

	select {
	case got := <-seenCh:
		if got.err != nil {
			t.Fatalf("proxy read error: %v", got.err)
		}
		if got.user != "sb" {
			t.Errorf("user portion: got %q, want %q", got.user, "sb")
		}
		if got.pass != longToken {
			t.Errorf("password portion length: got %d, want %d (first 32: got %q want %q)",
				len(got.pass), len(longToken), safePrefix(got.pass, 32), safePrefix(longToken, 32))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("proxy goroutine never returned")
	}
}

func safePrefix(s string, n int) string {
	if len(s) < n {
		return s
	}
	return s[:n]
}
