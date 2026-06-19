package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/blocklist"
)

func TestBuildUpstreamTransport(t *testing.T) {
	// DialContext is always set so the internal-IP guard applies, whether or
	// not a policy resolver or blocklist is configured.
	if got := buildUpstreamTransport(nil, nil); got.DialContext == nil {
		t.Error("DialContext should be set for the internal-IP guard without a resolver")
	}
	if got := buildUpstreamTransport(buildPolicyResolver("127.0.0.1:19053"), nil); got.DialContext == nil {
		t.Error("DialContext should be set with a resolver")
	}
}

func TestDialGuardInternalRange(t *testing.T) {
	guard := dialGuard(nil)
	cases := []struct {
		addr      string
		wantBlock bool
	}{
		{"10.0.0.1:443", true},
		{"169.254.169.254:443", true},
		{"192.168.0.5:8080", true},
		{"8.8.8.8:443", false},
		{"1.1.1.1:80", false},
	}
	for _, c := range cases {
		err := guard("tcp", c.addr, nil)
		if (err != nil) != c.wantBlock {
			t.Errorf("dialGuard(%q) err=%v, wantBlock=%v", c.addr, err, c.wantBlock)
		}
	}
}

func TestDialGuardBlocklistCIDR(t *testing.T) {
	bl := blocklist.New(&blocklist.Config{CustomCIDRs: []string{"203.0.113.0/24"}}, zerolog.Nop())
	guard := dialGuard(bl)
	if err := guard("tcp", "203.0.113.5:443", nil); err == nil {
		t.Error("a dial into a blocklisted CIDR should be refused")
	}
	if err := guard("tcp", "8.8.8.8:443", nil); err != nil {
		t.Errorf("a non-blocklisted IP should pass: %v", err)
	}
}

func TestLoadEgressBlocklist(t *testing.T) {
	// Unset path: enforcement disabled, no matcher, no ports, no error.
	if bl, ports, err := loadEgressBlocklist(""); bl != nil || ports != nil || err != nil {
		t.Errorf("empty path: bl=%v ports=%v err=%v", bl, ports, err)
	}

	// A configured-but-unreadable path must fail closed (error), not silently
	// disable enforcement.
	if _, _, err := loadEgressBlocklist(filepath.Join(t.TempDir(), "does-not-exist.yaml")); err == nil {
		t.Error("a configured but missing blocklist path must abort startup, not return nil")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "blocklist.yaml")
	doc := "blocked_egress_ports:\n  - 3333\n  - 4444\ncustom_domains:\n  - evil.example\n"
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	bl, ports, err := loadEgressBlocklist(path)
	if err != nil {
		t.Fatalf("valid config: %v", err)
	}
	if bl == nil {
		t.Fatal("expected a live blocklist matcher")
	}
	if len(ports) != 2 || ports[0] != 3333 || ports[1] != 4444 {
		t.Errorf("ports=%v, want [3333 4444]", ports)
	}
	if blocked, _ := bl.Blocked("evil.example", nil); !blocked {
		t.Error("a pinned custom_domains entry must be blocked on the proxied path")
	}
	if blocked, _ := bl.Blocked("pool.evil.example", nil); !blocked {
		t.Error("a subdomain of a pinned domain must be blocked")
	}
}

// The CIDR sink wired in main relies on CloseIdleConnections forcing the next
// request to re-dial (and re-hit the guard); pin that it drops pooled conns.
func TestCloseIdleConnsForcesRedial(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var dials int32
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			atomic.AddInt32(&dials, 1)
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
		MaxIdleConns:    10,
		IdleConnTimeout: 90 * time.Second,
	}
	client := &http.Client{Transport: tr}

	do := func() {
		resp, err := client.Get(srv.URL)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}

	do() // opens and pools a connection
	do() // reuses the pooled connection: no new dial
	if got := atomic.LoadInt32(&dials); got != 1 {
		t.Fatalf("expected the second request to reuse the pooled conn (1 dial), got %d", got)
	}

	tr.CloseIdleConnections() // what the blocklist CIDR sink triggers

	do() // the pooled conn is gone, so this must re-dial (and hit the guard)
	if got := atomic.LoadInt32(&dials); got != 2 {
		t.Fatalf("expected a re-dial after CloseIdleConnections, got %d dials", got)
	}
}
