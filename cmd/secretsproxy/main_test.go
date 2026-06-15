package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Unset path: enforcement disabled, no matcher, no ports.
	if bl, ports := loadEgressBlocklist(ctx, ""); bl != nil || ports != nil {
		t.Errorf("empty path: bl=%v ports=%v", bl, ports)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "blocklist.yaml")
	doc := "blocked_egress_ports:\n  - 3333\n  - 4444\ncustom_domains:\n  - evil.example\n"
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	bl, ports := loadEgressBlocklist(ctx, path)
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
