package network

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

func TestAddFeedText(t *testing.T) {
	sb := newSnapshotBuilder()
	n, err := sb.addFeedText(`
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
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

func TestRefreshPreservesSeededStateOnPartialFirstFailure(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state")
	// State from a prior good run holds entries from BOTH feeds (the on-disk
	// state is a merged blob, not attributable to a specific feed).
	if err := os.WriteFile(statePath, []byte("from-good.example.com\nfrom-flaky.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(dir, "good.txt")
	if err := os.WriteFile(good, []byte("from-good.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	flaky := filepath.Join(dir, "flaky.txt") // missing → fails, and no cache yet
	cfg := &BlocklistConfig{
		DomainFeeds: []string{good, flaky},
		StatePath:   statePath,
	}
	b := NewBlocklist(cfg, zerolog.Nop()) // seeds cur from state; feedCache empty

	b.refresh(t.Context()) // good succeeds, flaky fails on the very first refresh

	// The flaky feed's entry existed only in seeded state (no per-feed cache),
	// so it must be retained via the previous-snapshot union, not dropped.
	if got, _ := b.Blocked("from-flaky.example.com", nil); !got {
		t.Error("state-seeded entry from a feed that failed on first refresh was dropped")
	}
	if got, _ := b.Blocked("from-good.example.com", nil); !got {
		t.Error("entry from the healthy feed missing")
	}

	// A round that fails must not overwrite the on-disk state with a shrunken
	// snapshot, so a subsequent cold start still seeds the full set.
	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "from-flaky.example.com") {
		t.Error("degraded refresh overwrote state file, losing the failed feed's entries")
	}
}

func TestCIDRSinkFiresWhenAllFeedsDownWithSeededState(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state")
	// Pre-seed a state file with a CIDR, simulating a prior good fetch.
	if err := os.WriteFile(statePath, []byte("198.51.100.0/24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &BlocklistConfig{
		DomainFeeds: []string{filepath.Join(dir, "missing-feed.txt")}, // never resolves
		StatePath:   statePath,
	}
	b := NewBlocklist(cfg, zerolog.Nop()) // seeds snapshot from state

	var got []string
	sinkCalled := false
	b.SetCIDRSink(func(c []string) { sinkCalled = true; got = c })

	b.refresh(t.Context()) // feed fails, no cache → early return path

	if !sinkCalled {
		t.Fatal("sink not invoked on total feed outage; host drop set would stay empty")
	}
	if len(got) != 1 || got[0] != "198.51.100.0/24" {
		t.Errorf("sink CIDRs = %v, want [198.51.100.0/24] from seeded state", got)
	}
}

func TestAddFeedTextRejectsOverlongLine(t *testing.T) {
	sb := newSnapshotBuilder()
	// A single line larger than the scanner's 1 MiB buffer stops Scan early.
	overlong := strings.Repeat("a", 2<<20)
	_, err := sb.addFeedText("good.example.com\n" + overlong + "\n")
	if err == nil {
		t.Fatal("expected a scanner error for an over-long line, got nil")
	}
}

func TestFeedParseErrorKeepsLastGood(t *testing.T) {
	dir := t.TempDir()
	feed := filepath.Join(dir, "feed.txt")
	if err := os.WriteFile(feed, []byte("keep.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &BlocklistConfig{
		DomainFeeds: []string{feed},
		StatePath:   filepath.Join(dir, "state"),
	}
	b := NewBlocklist(cfg, zerolog.Nop())
	b.refresh(t.Context())
	if got, _ := b.Blocked("keep.example.com", nil); !got {
		t.Fatal("expected keep.example.com blocked after first refresh")
	}

	// Feed mutates to contain an over-long line: the parse must fail and the
	// last-good snapshot must be retained, not replaced by a truncated set.
	if err := os.WriteFile(feed, []byte(strings.Repeat("a", 2<<20)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	b.refresh(t.Context())
	if got, _ := b.Blocked("keep.example.com", nil); !got {
		t.Error("last-good entry lost after a feed parse error")
	}
}

func TestOversizedFeedFailsAndKeepsLastGood(t *testing.T) {
	dir := t.TempDir()

	// Server whose body length depends on a switch, so we can serve a small
	// good body first, then an oversized one.
	oversized := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if oversized {
			w.Write([]byte("a.example.com\nb.example.com\nc.example.com\n")) // > cap below
		} else {
			w.Write([]byte("a.example.com\n"))
		}
	}))
	defer srv.Close()

	cfg := &BlocklistConfig{
		DomainFeeds: []string{srv.URL},
		StatePath:   filepath.Join(dir, "state"),
	}
	b := NewBlocklist(cfg, zerolog.Nop())
	b.maxBytes = 20 // tiny cap for the test

	b.refresh(t.Context()) // small body, succeeds
	if got, _ := b.Blocked("a.example.com", nil); !got {
		t.Fatal("expected a.example.com blocked after first refresh")
	}

	// Now the feed exceeds the cap: the fetch must fail, not silently
	// truncate, so the last-good snapshot is retained.
	oversized = true
	b.refresh(t.Context())
	if got, _ := b.Blocked("a.example.com", nil); !got {
		t.Error("last-good entry lost after oversized feed; truncation was treated as success")
	}

	// State file must not have been overwritten with truncated content.
	if raw, err := os.ReadFile(cfg.StatePath); err == nil && len(raw) > 20 {
		t.Errorf("state file holds %d bytes; oversized feed should not have persisted", len(raw))
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

	// Invalid duration, invalid CIDR, and un-droppable web ports must all be
	// rejected at load time.
	for name, content := range map[string]string{
		"bad duration": "refresh_interval: nonsense\n",
		"bad cidr":     "custom_cidrs: [not-a-cidr]\n",
		"web port 80":  "blocked_egress_ports: [80]\n",
		"web port 443": "blocked_egress_ports: [443, 3333]\n",
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
