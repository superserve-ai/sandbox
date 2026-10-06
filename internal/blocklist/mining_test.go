package blocklist

import (
	"context"
	"github.com/rs/zerolog"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestMiningMatchKeepsClassificationAndRevisionIndependent(t *testing.T) {
	dir := t.TempDir()
	ordinary := New(&Config{CustomDomains: []string{"ordinary.example"}, StatePath: filepath.Join(dir, "generic")}, zerolog.Nop())
	mining := New(&Config{CustomDomains: []string{"mining.example"}, CustomCIDRs: []string{"203.0.113.0/24"}, StatePath: filepath.Join(dir, "private")}, zerolog.Nop())
	if ok, _ := ordinary.Blocked("ordinary.example", nil); !ok {
		t.Fatal("generic block missing")
	}
	if _, ok := mining.MiningMatch("ordinary.example", nil); ok {
		t.Fatal("generic deny promoted into mining evidence")
	}
	domain, ok := mining.MiningMatch("sub.mining.example.", nil)
	if !ok || domain.Kind != "domain" || domain.Indicator != "mining.example" {
		t.Fatal("domain evidence missing")
	}
	ip, ok := mining.MiningMatch("", net.ParseIP("203.0.113.9"))
	if !ok || ip.Kind != "ip" || ip.PolicyRevision != domain.PolicyRevision || len(ip.PolicyRevision) != 64 {
		t.Fatal("CIDR evidence/revision missing")
	}
}

func TestMiningConfigurationSeparatesPersistedGenericState(t *testing.T) {
	dir := t.TempDir()
	generic := filepath.Join(dir, "generic.yaml")
	private := filepath.Join(dir, "private.yaml")
	for _, path := range []string{generic, private} {
		if err := os.WriteFile(path, []byte("custom_domains: []\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ordinary, err := LoadConfig(generic)
	if err != nil {
		t.Fatal(err)
	}
	config, err := LoadMiningConfig(private)
	if err != nil {
		t.Fatal(err)
	}
	if config.StatePath == ordinary.StatePath {
		t.Fatal("default mining state collided with generic denylist")
	}
	if err := os.WriteFile(ordinary.StatePath, []byte("ordinary.example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	policy := New(config, zerolog.Nop())
	if _, hit := policy.MiningMatch("ordinary.example", nil); hit {
		t.Fatal("generic persisted indicator escalated into mining")
	}
	policy.reloadConfig(context.Background(), private)
	if policy.cfg.StatePath != config.StatePath {
		t.Fatal("reload lost mining state separation")
	}
}
