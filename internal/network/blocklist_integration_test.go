package network

import (
	"net"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/blocklist"
)

func TestProxyBlocklistPrecedesSandboxAllow(t *testing.T) {
	dir := t.TempDir()
	cfg := &blocklist.Config{
		CustomDomains: []string{"pool.example.com"},
		StatePath:     filepath.Join(dir, "state"),
	}
	p := NewEgressProxy(0, 0, 0, 0, zerolog.Nop())
	p.SetBlocklist(blocklist.New(cfg, zerolog.Nop()))

	// The sandbox explicitly allows the domain — the global blocklist must
	// still win. handleConn checks the blocklist before isAllowed; this
	// verifies the lookup the proxy performs.
	if blocked, dim := p.blocklist.Blocked("pool.example.com", net.ParseIP("8.8.8.8")); !blocked || dim != "domain" {
		t.Errorf("Blocked() = (%v, %q), want (true, domain)", blocked, dim)
	}
}
