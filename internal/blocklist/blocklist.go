package blocklist

// blocklist.go implements a global egress denylist for the egress proxy and
// host firewall. Which feeds are fetched, which domains/CIDRs are pinned,
// and which ports are dropped all come from an operator-supplied config
// file; nothing is built in.
//
// Enforcement points:
//   - EgressProxy checks Blocked() on every HTTP/TLS connection (SNI/Host
//     plus original destination IP) before per-sandbox rules.
//   - installHostFirewall drops BlockedEgressPorts in the FORWARD chain for
//     traffic that is not redirected through the proxy.
//
// The list is a denylist, so the failure mode is "no extra blocking", never
// "block everything": a fetch error keeps the last good snapshot, and the
// last good snapshot is persisted to StatePath so a vmd restart does not
// come up empty while the first fetch is in flight.

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	yaml "go.yaml.in/yaml/v3"
)

const (
	// defaultBlocklistRefresh is used when refresh_interval is unset.
	defaultBlocklistRefresh = 6 * time.Hour

	// maxFeedBytes caps a single feed download so a hijacked or
	// misconfigured feed URL cannot exhaust memory.
	maxFeedBytes = 16 << 20 // 16 MiB

	feedFetchTimeout = 60 * time.Second
)

// Config is the schema of the operator-supplied config file
// (VMD_EGRESS_BLOCKLIST_CONFIG). All fields are optional.
type Config struct {
	// DomainFeeds are URLs (http/https) or local file paths to plain-text
	// feeds: one entry per line, '#' starts a comment. Entries may be
	// domains, IPs, IP:port pairs, or CIDRs.
	DomainFeeds []string `yaml:"domain_feeds"`

	// CustomDomains and CustomCIDRs are pinned entries that are always
	// blocked regardless of feed contents.
	CustomDomains []string `yaml:"custom_domains"`
	CustomCIDRs   []string `yaml:"custom_cidrs"`

	// BlockedEgressPorts are dropped in the host FORWARD chain for all
	// sandbox traffic (both TCP and UDP).
	BlockedEgressPorts []uint16 `yaml:"blocked_egress_ports"`

	// RefreshInterval is a Go duration string ("6h", "30m"). Default 6h.
	RefreshInterval string `yaml:"refresh_interval"`

	// StatePath is where the last good merged list is persisted. Default:
	// "<config dir>/blocklist.state".
	StatePath string `yaml:"state_path"`
}

// LoadConfig reads and validates the YAML config at path.
func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read blocklist config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse blocklist config %s: %w", path, err)
	}
	if cfg.RefreshInterval != "" {
		d, err := time.ParseDuration(cfg.RefreshInterval)
		if err != nil {
			return nil, fmt.Errorf("invalid refresh_interval %q: %w", cfg.RefreshInterval, err)
		}
		// time.NewTicker panics on a non-positive duration; reject it here.
		if d <= 0 {
			return nil, fmt.Errorf("refresh_interval must be positive, got %q", cfg.RefreshInterval)
		}
	}
	for _, c := range cfg.CustomCIDRs {
		if _, err := parseCIDROrIP(c); err != nil {
			return nil, fmt.Errorf("invalid custom_cidrs entry %q: %w", c, err)
		}
	}
	for _, p := range cfg.BlockedEgressPorts {
		// 80/443 are REDIRECTed to the egress proxy in PREROUTING, which runs
		// before the FORWARD drop, so a port drop here would be a silent
		// no-op. Web traffic is governed by the domain blocklist and the
		// proxy path instead. Reject rather than silently ignore.
		if p == 80 || p == 443 {
			return nil, fmt.Errorf("blocked_egress_ports must not contain %d: web ports are enforced via the egress proxy and domain rules, not port drops", p)
		}
	}
	if cfg.StatePath == "" {
		cfg.StatePath = filepath.Join(filepath.Dir(path), "blocklist.state")
	}
	return &cfg, nil
}

func (c *Config) refreshInterval() time.Duration {
	if c.RefreshInterval == "" {
		return defaultBlocklistRefresh
	}
	d, err := time.ParseDuration(c.RefreshInterval)
	if err != nil || d <= 0 {
		return defaultBlocklistRefresh
	}
	return d
}

// blocklistSnapshot is an immutable merged view of all sources. Swapped
// atomically on refresh so lookups never take a lock.
type blocklistSnapshot struct {
	domains map[string]struct{}
	nets    []netip.Prefix
}

// Blocklist holds the current snapshot and refreshes it from the configured
// feeds. Lookup methods are safe for concurrent use.
type Blocklist struct {
	cfg  *Config
	log  zerolog.Logger
	cur  atomic.Pointer[blocklistSnapshot]
	http *http.Client

	// maxBytes caps a single HTTP feed download. Defaults to maxFeedBytes;
	// overridable in tests.
	maxBytes int64

	// feedCache holds the last successfully fetched text per feed URL so a
	// transient failure of one feed does not drop that feed's entries from
	// the merged snapshot. Only touched from the single refresh goroutine.
	feedCache map[string]string

	// sink, if set, receives the snapshot's CIDRs after every refresh so
	// downstream enforcers (e.g. the host firewall) can mirror them.
	sink func([]string)
}

// New builds a Blocklist seeded from the pinned config entries and
// the persisted state file (if present). Feeds are first fetched in Start.
func New(cfg *Config, log zerolog.Logger) *Blocklist {
	b := &Blocklist{
		cfg:       cfg,
		log:       log.With().Str("component", "egress-blocklist").Logger(),
		http:      &http.Client{Timeout: feedFetchTimeout},
		feedCache: make(map[string]string),
		maxBytes:  maxFeedBytes,
	}

	seed := newSnapshotBuilder()
	seed.addConfigEntries(cfg)
	if raw, err := os.ReadFile(cfg.StatePath); err == nil {
		n, perr := seed.addFeedText(string(raw))
		if perr != nil {
			b.log.Warn().Err(perr).Str("path", cfg.StatePath).Msg("persisted state parse incomplete")
		}
		b.log.Info().Int("entries", n).Str("path", cfg.StatePath).Msg("seeded blocklist from persisted state")
	}
	b.cur.Store(seed.snapshot())
	return b
}

// SetCIDRSink registers a callback invoked with the snapshot's CIDR list
// after each refresh (and on the initial refresh in Start). Used to mirror
// IP/CIDR entries into the host firewall so they are enforced on every port,
// not only the proxied HTTP/TLS ports. Must be set before Start.
func (b *Blocklist) SetCIDRSink(fn func([]string)) {
	b.sink = fn
}

// CIDRs returns the current snapshot's blocked prefixes as strings.
func (b *Blocklist) CIDRs() []string {
	snap := b.cur.Load()
	if snap == nil {
		return nil
	}
	out := make([]string, 0, len(snap.nets))
	for _, p := range snap.nets {
		out = append(out, p.String())
	}
	return out
}

// Refresh fetches all feeds once, synchronously, so a caller can enforce
// feed-sourced entries before it starts serving.
func (b *Blocklist) Refresh(ctx context.Context) { b.refresh(ctx) }

// Start fetches all feeds immediately, then refreshes on the configured
// interval. Blocks until ctx is cancelled.
func (b *Blocklist) Start(ctx context.Context) error {
	b.refresh(ctx)
	ticker := time.NewTicker(b.cfg.refreshInterval())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			b.refresh(ctx)
		}
	}
}

// Blocked reports whether a connection identified by hostname (may be empty)
// and destination IP hits the blocklist. The second return value names the
// matching dimension ("domain" or "ip") for logging.
func (b *Blocklist) Blocked(hostname string, dstIP net.IP) (bool, string) {
	snap := b.cur.Load()
	if snap == nil {
		return false, ""
	}
	if hostname != "" && snap.blockedDomain(hostname) {
		return true, "domain"
	}
	if dstIP != nil {
		// AddrFromSlice + Unmap matches both IPv4 and IPv6 (including v4-mapped).
		if addr, ok := netip.AddrFromSlice(dstIP); ok {
			addr = addr.Unmap()
			for _, p := range snap.nets {
				if p.Contains(addr) {
					return true, "ip"
				}
			}
		}
	}
	return false, ""
}

// blockedDomain walks parent labels so a blocked "example.com" also blocks
// "pool.example.com".
func (s *blocklistSnapshot) blockedDomain(hostname string) bool {
	h := strings.ToLower(strings.TrimSuffix(hostname, "."))
	for h != "" {
		if _, ok := s.domains[h]; ok {
			return true
		}
		_, parent, ok := strings.Cut(h, ".")
		if !ok {
			break
		}
		h = parent
	}
	return false
}

// refresh fetches every feed and atomically swaps in the merged snapshot.
//
// A feed that fails to fetch falls back to its last successfully fetched
// text (feedCache) so one transient failure cannot drop that feed's entries
// while others succeed. A feed that has never succeeded contributes nothing.
// If no feed yields any text (fresh or cached) the previous snapshot is kept
// so transient outages never shrink coverage.
func (b *Blocklist) refresh(ctx context.Context) {
	builder := newSnapshotBuilder()
	builder.addConfigEntries(b.cfg)

	fetched, cached, failed := 0, 0, 0
	degraded := false
	var stateText strings.Builder
	for _, src := range b.cfg.DomainFeeds {
		text, err := b.fetchFeed(ctx, src)
		fromCache := false
		if err != nil {
			degraded = true
			prev, ok := b.feedCache[src]
			if !ok {
				failed++
				b.log.Warn().Err(err).Str("feed", src).Msg("blocklist feed fetch failed (no cached copy)")
				continue
			}
			text = prev
			fromCache = true
			b.log.Warn().Err(err).Str("feed", src).Msg("blocklist feed fetch failed; using cached copy")
		}

		// Parse in isolation so a malformed feed (e.g. a line longer than the
		// scanner buffer, which stops Scan mid-stream) is treated as a failed
		// feed rather than silently contributing a truncated set.
		fb := newSnapshotBuilder()
		if _, perr := fb.addFeedText(text); perr != nil {
			degraded = true
			failed++
			b.log.Warn().Err(perr).Str("feed", src).Msg("blocklist feed parse failed; skipping feed")
			continue
		}

		if fromCache {
			cached++
		} else {
			fetched++
			b.feedCache[src] = text
		}
		builder.addSnapshot(fb.snapshot())
		stateText.WriteString(text)
		stateText.WriteString("\n")
	}

	// Fail-safe: a failed or missing feed must never shrink coverage. Union
	// the previous snapshot so entries sourced only from an unavailable feed
	// survive — including entries seeded from the state file at startup, for
	// which there is no per-feed cache to fall back on. A later fully
	// successful refresh rebuilds without this union, so legitimate removals
	// still take effect once every feed is reachable again.
	if degraded {
		if prev := b.cur.Load(); prev != nil {
			builder.addSnapshot(prev)
		}
	}

	snap := builder.snapshot()
	b.cur.Store(snap)
	b.log.Info().
		Int("domains", len(snap.domains)).
		Int("cidrs", len(snap.nets)).
		Int("feeds_ok", fetched).
		Int("feeds_cached", cached).
		Int("feeds_failed", failed).
		Msg("blocklist refreshed")

	// Mirror CIDRs to the host firewall on every refresh, degraded ones
	// included, so the host drop set always matches the active snapshot.
	if b.sink != nil {
		b.sink(b.CIDRs())
	}

	// Persist only a fully successful fetch so the on-disk state always
	// represents a complete snapshot for cold-start seeding — never the
	// shrunken text of a degraded round.
	if !degraded && fetched > 0 {
		if err := writeFileAtomic(b.cfg.StatePath, []byte(stateText.String())); err != nil {
			b.log.Warn().Err(err).Str("path", b.cfg.StatePath).Msg("failed to persist blocklist state")
		}
	}
}

func (b *Blocklist) fetchFeed(ctx context.Context, src string) (string, error) {
	if !strings.HasPrefix(src, "http://") && !strings.HasPrefix(src, "https://") {
		raw, err := os.ReadFile(src)
		if err != nil {
			return "", err
		}
		return string(raw), nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return "", err
	}
	resp, err := b.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	// Read one byte past the cap so truncation is detectable. A silently
	// truncated feed would otherwise count as a successful fetch, overwrite
	// the cache, and persist a partial state — dropping every entry past the
	// cutoff. Fail instead, so refresh() falls back to the last-good copy.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, b.maxBytes+1))
	if err != nil {
		return "", err
	}
	if int64(len(raw)) > b.maxBytes {
		return "", fmt.Errorf("feed exceeds %d byte cap", b.maxBytes)
	}
	return string(raw), nil
}

// ---------------------------------------------------------------------------
// Snapshot building / feed parsing
// ---------------------------------------------------------------------------

type snapshotBuilder struct {
	domains map[string]struct{}
	nets    map[netip.Prefix]struct{}
}

func newSnapshotBuilder() *snapshotBuilder {
	return &snapshotBuilder{
		domains: make(map[string]struct{}),
		nets:    make(map[netip.Prefix]struct{}),
	}
}

// addSnapshot merges an existing snapshot's entries into the builder. Used to
// retain previous coverage across a degraded refresh.
func (sb *snapshotBuilder) addSnapshot(s *blocklistSnapshot) {
	for d := range s.domains {
		sb.domains[d] = struct{}{}
	}
	for _, p := range s.nets {
		sb.nets[p] = struct{}{}
	}
}

func (sb *snapshotBuilder) addConfigEntries(cfg *Config) {
	for _, d := range cfg.CustomDomains {
		if d = normalizeDomain(d); d != "" {
			sb.domains[d] = struct{}{}
		}
	}
	for _, c := range cfg.CustomCIDRs {
		if p, err := parseCIDROrIP(c); err == nil {
			sb.nets[p] = struct{}{}
		}
	}
}

// addFeedText parses feed lines into the builder and returns the number of
// entries accepted. Unparseable lines are skipped — feeds aggregated from
// threat intel commonly mix formats and annotations. A non-nil error means
// the scan stopped early (e.g. a line exceeding the buffer), so the parse is
// incomplete and the caller must not treat the result as authoritative.
func (sb *snapshotBuilder) addFeedText(text string) (int, error) {
	added := 0
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// CIDR (1.2.3.0/24)
		if strings.Contains(line, "/") {
			if p, err := netip.ParsePrefix(line); err == nil && p.Addr().Is4() {
				sb.nets[p.Masked()] = struct{}{}
				added++
			}
			continue
		}

		// IP:port (1.2.3.4:8080) — port is irrelevant for a destination
		// denylist; block the IP outright.
		if host, _, err := net.SplitHostPort(line); err == nil {
			line = host
		}

		// Bare IP (1.2.3.4)
		if addr, err := netip.ParseAddr(line); err == nil {
			if addr.Is4() {
				sb.nets[netip.PrefixFrom(addr, 32)] = struct{}{}
				added++
			}
			continue
		}

		// Domain
		if d := normalizeDomain(line); d != "" {
			sb.domains[d] = struct{}{}
			added++
		}
	}
	return added, scanner.Err()
}

func (sb *snapshotBuilder) snapshot() *blocklistSnapshot {
	nets := make([]netip.Prefix, 0, len(sb.nets))
	for p := range sb.nets {
		nets = append(nets, p)
	}
	return &blocklistSnapshot{domains: sb.domains, nets: nets}
}

// normalizeDomain lowercases and validates a domain-ish entry. Returns ""
// for entries that cannot be a DNS name (so junk feed lines are dropped
// instead of polluting the set).
func normalizeDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(d, ".")))
	d = strings.TrimPrefix(d, "*.")
	if d == "" || !strings.Contains(d, ".") || len(d) > 253 {
		return ""
	}
	for _, r := range d {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '.', r == '_':
		default:
			return ""
		}
	}
	return d
}

// parseCIDROrIP accepts both "1.2.3.0/24" and bare "1.2.3.4" config entries.
func parseCIDROrIP(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return p.Masked(), nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
