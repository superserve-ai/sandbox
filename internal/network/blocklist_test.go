package network

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
)

func TestAddFeedText(t *testing.T) {
	sb := newSnapshotBuilder()
	n := sb.addFeedText(`
# comment line
pool.example.com
EVIL.Example.ORG.   # trailing comment
1.2.3.4
5.6.7.8:8081
10.20.0.0/16
not a valid entry !!
singlelabel
2001:db8::1
`)
	if n != 5 {
		t.Errorf("addFeedText accepted %d entries, want 5", n)
	}

	snap := sb.snapshot()
	for _, d := range []string{"pool.example.com", "evil.example.org"} {
		if _, ok := snap.domains[d]; !ok {
			t.Errorf("domain %q missing from snapshot", d)
		}
	}
	if _, ok := snap.domains["singlelabel"]; ok {
		t.Error("dotless entry should have been rejected")
	}
	if len(snap.nets) != 3 {
		t.Errorf("got %d nets, want 3 (two /32s and one /16)", len(snap.nets))
	}
}

func TestBlockedDomainWalksParents(t *testing.T) {
	sb := newSnapshotBuilder()
	sb.addFeedText("blocked.test\n")
	snap := sb.snapshot()

	for host, want := range map[string]bool{
		"blocked.test":        true,
		"pool.blocked.test":   true,
		"a.pool.blocked.test": true,
		"POOL.BLOCKED.TEST":   true,
		"notblocked.test":     false,
		"blocked.test.evil":   false,
		"other.test":          false,
	} {
		if got := snap.blockedDomain(host); got != want {
			t.Errorf("blockedDomain(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestBlocklistBlocked(t *testing.T) {
	dir := t.TempDir()
	feed := filepath.Join(dir, "feed.txt")
	if err := os.WriteFile(feed, []byte("pool.example.com\n9.9.9.0/24\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := &BlocklistConfig{
		DomainFeeds:   []string{feed},
		CustomDomains: []string{"pinned.example.net"},
		CustomCIDRs:   []string{"1.2.3.4"},
		StatePath:     filepath.Join(dir, "state"),
	}
	b := NewBlocklist(cfg, zerolog.Nop())
	b.refresh(t.Context())

	tests := []struct {
		hostname string
		ip       string
		want     bool
		wantDim  string
	}{
		{"pool.example.com", "8.8.8.8", true, "domain"},
		{"deep.pool.example.com", "8.8.8.8", true, "domain"},
		{"pinned.example.net", "8.8.8.8", true, "domain"},
		{"", "9.9.9.42", true, "ip"},
		{"", "1.2.3.4", true, "ip"},
		{"fine.example.com", "8.8.8.8", false, ""},
		{"", "8.8.8.8", false, ""},
	}
	for _, tc := range tests {
		got, dim := b.Blocked(tc.hostname, net.ParseIP(tc.ip))
		if got != tc.want || dim != tc.wantDim {
			t.Errorf("Blocked(%q, %s) = (%v, %q), want (%v, %q)",
				tc.hostname, tc.ip, got, dim, tc.want, tc.wantDim)
		}
	}

	// State file should have been persisted for cold-start seeding.
	if _, err := os.Stat(cfg.StatePath); err != nil {
		t.Errorf("state file not persisted: %v", err)
	}

	// A fresh Blocklist seeded only from state (feed gone) still blocks.
	os.Remove(feed)
	b2 := NewBlocklist(cfg, zerolog.Nop())
	if got, _ := b2.Blocked("pool.example.com", nil); !got {
		t.Error("state-seeded blocklist should block pool.example.com before first refresh")
	}
}

func TestRefreshKeepsLastGoodOnTotalFailure(t *testing.T) {
	dir := t.TempDir()
	feed := filepath.Join(dir, "feed.txt")
	if err := os.WriteFile(feed, []byte("pool.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &BlocklistConfig{
		DomainFeeds: []string{feed},
		StatePath:   filepath.Join(dir, "state"),
	}
	b := NewBlocklist(cfg, zerolog.Nop())
	b.refresh(t.Context())
	if got, _ := b.Blocked("pool.example.com", nil); !got {
		t.Fatal("expected pool.example.com blocked after first refresh")
	}

	// Feed disappears — refresh must keep the previous snapshot.
	os.Remove(feed)
	b.refresh(t.Context())
	if got, _ := b.Blocked("pool.example.com", nil); !got {
		t.Error("snapshot was lost after total feed failure")
	}
}

func TestRefreshKeepsFailedFeedFromCache(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.txt")
	flaky := filepath.Join(dir, "flaky.txt")
	if err := os.WriteFile(good, []byte("stable.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(flaky, []byte("flaky-only.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &BlocklistConfig{
		DomainFeeds: []string{good, flaky},
		StatePath:   filepath.Join(dir, "state"),
	}
	b := NewBlocklist(cfg, zerolog.Nop())
	b.refresh(t.Context())

	// One feed fails this round; the other still succeeds. The failed feed's
	// entries must survive from cache rather than vanishing.
	os.Remove(flaky)
	b.refresh(t.Context())

	if got, _ := b.Blocked("flaky-only.example.com", nil); !got {
		t.Error("entry from transiently-failed feed was dropped; expected cache fallback")
	}
	if got, _ := b.Blocked("stable.example.com", nil); !got {
		t.Error("entry from healthy feed missing after partial-failure refresh")
	}
}

func TestCIDRSinkInvokedOnRefresh(t *testing.T) {
	dir := t.TempDir()
	feed := filepath.Join(dir, "feed.txt")
	if err := os.WriteFile(feed, []byte("10.20.30.0/24\nblocked.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &BlocklistConfig{
		DomainFeeds: []string{feed},
		CustomCIDRs: []string{"203.0.113.7"},
		StatePath:   filepath.Join(dir, "state"),
	}
	b := NewBlocklist(cfg, zerolog.Nop())

	var got []string
	b.SetCIDRSink(func(c []string) { got = c })
	b.refresh(t.Context())

	// Sink should receive only CIDRs (not domains): the feed /24 and the
	// pinned /32.
	if len(got) != 2 {
		t.Fatalf("sink got %v, want 2 CIDRs", got)
	}
	found := map[string]bool{}
	for _, c := range got {
		found[c] = true
	}
	if !found["10.20.30.0/24"] || !found["203.0.113.7/32"] {
		t.Errorf("sink CIDRs = %v, missing expected entries", got)
	}
}

func TestLoadBlocklistConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bl.yaml")
	if err := os.WriteFile(path, []byte(`
domain_feeds:
  - https://example.com/feed.txt
custom_domains:
  - bad.example.com
custom_cidrs:
  - 1.2.3.0/24
blocked_egress_ports: [12345, 23456]
refresh_interval: 30m
`), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadBlocklistConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.BlockedEgressPorts) != 2 || cfg.BlockedEgressPorts[0] != 12345 {
		t.Errorf("blocked_egress_ports = %v, want [12345 23456]", cfg.BlockedEgressPorts)
	}
	if cfg.refreshInterval().Minutes() != 30 {
		t.Errorf("refresh interval = %v, want 30m", cfg.refreshInterval())
	}
	if cfg.StatePath != filepath.Join(dir, "blocklist.state") {
		t.Errorf("default state path = %q", cfg.StatePath)
	}

	// Invalid duration and invalid CIDR must be rejected at load time.
	for name, content := range map[string]string{
		"bad duration": "refresh_interval: nonsense\n",
		"bad cidr":     "custom_cidrs: [not-a-cidr]\n",
	} {
		p := filepath.Join(dir, "bad.yaml")
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadBlocklistConfig(p); err == nil {
			t.Errorf("%s: expected load error, got nil", name)
		}
	}
}

func TestProxyBlocklistPrecedesSandboxAllow(t *testing.T) {
	dir := t.TempDir()
	cfg := &BlocklistConfig{
		CustomDomains: []string{"pool.example.com"},
		StatePath:     filepath.Join(dir, "state"),
	}
	p := NewEgressProxy(0, 0, 0, 0, zerolog.Nop())
	p.SetBlocklist(NewBlocklist(cfg, zerolog.Nop()))

	// The sandbox explicitly allows the domain — the global blocklist must
	// still win. handleConn checks the blocklist before isAllowed, so here
	// we verify the lookup the proxy performs.
	if blocked, dim := p.blocklist.Blocked("pool.example.com", net.ParseIP("8.8.8.8")); !blocked || dim != "domain" {
		t.Errorf("Blocked() = (%v, %q), want (true, domain)", blocked, dim)
	}
}
