package blocklist

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
)

func TestMiningMatchKeepsClassificationAndRevisionIndependent(t *testing.T) {
	dir := t.TempDir()
	ordinary := New(&Config{CustomDomains: []string{"ordinary.example"}, StatePath: filepath.Join(dir, "generic")}, zerolog.Nop())
	mining := New(&Config{mining: true, CustomDomains: []string{"mining.example"}, CustomCIDRs: []string{"203.0.113.0/24"}, StatePath: filepath.Join(dir, "private")}, zerolog.Nop())
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
	if ordinary.cur.Load().revision != "" {
		t.Fatal("ordinary startup computed an unused mining revision")
	}
	ordinary.Refresh(context.Background())
	if ordinary.cur.Load().revision != "" {
		t.Fatal("ordinary refresh computed an unused mining revision")
	}
	mining.cfg.CustomDomains = append(mining.cfg.CustomDomains, "added.example")
	mining.Refresh(context.Background())
	updated, ok := mining.MiningMatch("added.example", nil)
	if !ok || len(updated.PolicyRevision) != 64 || updated.PolicyRevision == domain.PolicyRevision {
		t.Fatal("mining refresh did not publish updated evidence revision")
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

func TestReloadPreservesStateSeparation(t *testing.T) {
	for _, mining := range []bool{false, true} {
		t.Run(fmt.Sprintf("mining=%t", mining), func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "policy.yaml")
			state := filepath.Join(dir, "policy.state")
			otherState := filepath.Join(dir, "other.state")
			feed := filepath.Join(dir, "feed")
			if err := os.WriteFile(feed, []byte("feed.example\n"), 0600); err != nil {
				t.Fatal(err)
			}
			writeConfig := func(state, domain, cidr string) {
				t.Helper()
				body := fmt.Sprintf("state_path: %q\ndomain_feeds: [%q]\ncustom_domains: [%q]\ncustom_cidrs: [%q]\n", state, feed, domain, cidr)
				if err := os.WriteFile(path, []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			readState := func(path string) []byte {
				t.Helper()
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				return raw
			}
			other := New(&Config{mining: !mining, DomainFeeds: []string{feed}, StatePath: otherState}, zerolog.Nop())
			other.Refresh(t.Context())
			otherBefore := readState(otherState)
			writeConfig(state, "old.example", "192.0.2.0/24")
			cfg, err := loadConfig(path, mining)
			if err != nil {
				t.Fatal(err)
			}
			b := New(cfg, zerolog.Nop())
			b.Refresh(t.Context())
			before := b.cur.Load()
			stateBefore := readState(state)

			// The config changes after queuing. Validation must occur when
			// the refresh loop reads and applies the queued filename.
			b.Reload(path)
			writeConfig(otherState, "new.example", "203.0.113.0/24")
			b.reloadConfig(t.Context(), <-b.reloadCh)
			if b.cfg != cfg || b.cur.Load() != before {
				t.Fatal("rejected state-path change changed live config or snapshot")
			}
			if !bytes.Equal(readState(state), stateBefore) || !bytes.Equal(readState(otherState), otherBefore) {
				t.Fatal("rejected reload overwrote persisted state")
			}

			writeConfig(state, "new.example", "203.0.113.0/24")
			b.reloadConfig(t.Context(), path)
			for _, item := range []struct {
				domain, ip string
				blocked    bool
			}{
				{domain: "old.example", blocked: false},
				{domain: "new.example", blocked: true},
				{ip: "192.0.2.1", blocked: false},
				{ip: "203.0.113.1", blocked: true},
			} {
				if got, _ := b.Blocked(item.domain, net.ParseIP(item.ip)); got != item.blocked {
					t.Fatalf("normal reload: %v blocked=%t", item, got)
				}
			}
			if !bytes.Equal(readState(otherState), otherBefore) {
				t.Fatal("normal reload overwrote other policy state")
			}
		})
	}
}

func TestPersistedStateMatchesPolicyClassification(t *testing.T) {
	for _, mining := range []bool{false, true} {
		for _, persistedMining := range []bool{false, true} {
			t.Run(fmt.Sprintf("mining=%t/persistedMining=%t", mining, persistedMining), func(t *testing.T) {
				state := filepath.Join(t.TempDir(), "state")
				raw := "persisted.example\n"
				if persistedMining {
					raw = miningStateHeader + raw
				}
				if err := os.WriteFile(state, []byte(raw), 0600); err != nil {
					t.Fatal(err)
				}
				b := New(&Config{mining: mining, StatePath: state, CustomDomains: []string{"pinned.example"}}, zerolog.Nop())
				if got, _ := b.Blocked("persisted.example", nil); got != (mining == persistedMining) {
					t.Fatal("persisted state crossed policy classification")
				}
				if got, _ := b.Blocked("pinned.example", nil); !got {
					t.Fatal("pinned coverage lost")
				}
			})
		}
	}
}
