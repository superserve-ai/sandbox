// Command secretsproxy runs the in-host MITM enforcement daemon.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/blocklist"
	dbq "github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/egresspolicy"
	"github.com/superserve-ai/sandbox/internal/secretsproxy"
)

func main() {
	if err := run(); err != nil {
		log.Fatal().Err(err).Msg("secretsproxy exited with error")
	}
}

func run() error {
	zerolog.TimeFieldFormat = time.RFC3339
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).
		With().Str("svc", "secretsproxy").Logger()

	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	rootCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	ca, err := secretsproxy.NewCA(cfg.CACertPath, cfg.CAKeyPath, cfg.CertCacheSize)
	if err != nil {
		return fmt.Errorf("init CA: %w", err)
	}
	log.Info().
		Str("ca_cert", cfg.CACertPath).
		Str("ca_key", cfg.CAKeyPath).
		Msg("CA initialized")

	jwksFetcher := secretsproxy.NewHTTPJWKSFetcher(cfg.ControlPlaneURL, cfg.DaemonAuthToken)
	verifier, err := secretsproxy.NewVerifier(rootCtx, jwksFetcher)
	if err != nil {
		return fmt.Errorf("init JWKS: %w", err)
	}
	resolver := secretsproxy.NewJWTResolver(verifier)
	log.Info().Str("control_plane", cfg.ControlPlaneURL).Msg("JWKS loaded from control plane")

	httpVault := secretsproxy.NewHTTPVaultClient(cfg.ControlPlaneURL, cfg.DaemonAuthToken)
	cachedVault := secretsproxy.NewCachedVault(httpVault, secretsproxy.VaultCacheOptions{
		TTL:      cfg.VaultCacheTTL,
		IdleTTL:  cfg.VaultCacheIdleTTL,
		Capacity: cfg.VaultCacheCapacity,
	})

	httpRules := secretsproxy.NewHTTPRulesClient(cfg.ControlPlaneURL, cfg.DaemonAuthToken)
	cachedRules := secretsproxy.NewCachedRules(httpRules, secretsproxy.RulesCacheOptions{})

	revoker := secretsproxy.NewRevoker()
	revoked, err := secretsproxy.FetchRevokedSandboxes(rootCtx, cfg.ControlPlaneURL, cfg.DaemonAuthToken)
	if err != nil {
		return fmt.Errorf("bootstrap revocations: %w", err)
	}
	revoker.Bootstrap(revoked)
	log.Info().Int("revoked_sandboxes", len(revoked)).Msg("revocations loaded from control plane")
	go reconcileRevocations(rootCtx, revoker, cfg.ControlPlaneURL, cfg.DaemonAuthToken)

	auditSink, dbCleanup, err := buildAuditSink(rootCtx, cfg)
	if err != nil {
		return fmt.Errorf("init audit sink: %w", err)
	}
	defer func() {
		if dbCleanup != nil {
			dbCleanup()
		}
	}()

	// Enforce the operator blocklist on the proxied path too, so a secrets
	// sandbox gets the same containment as direct traffic through the firewall.
	egressBlocklist, blockedPorts := loadEgressBlocklist(rootCtx, cfg.BlocklistConfigPath)
	var blEnforcer secretsproxy.EgressBlocklist
	if egressBlocklist != nil {
		blEnforcer = egressBlocklist
	}

	dnsResolver := buildPolicyResolver(cfg.UpstreamResolverAddr)
	proxy := secretsproxy.NewProxy(cfg.ProxyAddr, secretsproxy.Options{
		CA:                  ca,
		Resolver:            resolver,
		Vault:               cachedVault,
		Rules:               cachedRules,
		Audit:               auditSink,
		Revoker:             revoker,
		SandboxFacingHost:   cfg.SandboxFacingHost,
		MaxRequestBodyBytes: cfg.MaxRequestBodyBytes,
		UpstreamTransport:   buildUpstreamTransport(dnsResolver, egressBlocklist),
		BlockedPorts:        blockedPorts,
		BlockInternalAddrs:  true,
		DNSResolver:         dnsResolver,
		Blocklist:           blEnforcer,
	})
	if cfg.UpstreamResolverAddr != "" {
		log.Info().Str("resolver", cfg.UpstreamResolverAddr).Msg("upstream name resolution routed through policy resolver")
	}
	proxyErrCh := make(chan error, 1)
	go func() { proxyErrCh <- proxy.ListenAndServe() }()
	log.Info().Str("addr", cfg.ProxyAddr).Msg("proxy listener started")

	control := secretsproxy.NewControlServer(cfg.ControlSocketPath, cachedVault, cachedRules, revoker)
	controlErrCh := make(chan error, 1)
	go func() { controlErrCh <- control.ListenAndServe() }()
	log.Info().Str("socket", cfg.ControlSocketPath).Msg("control RPC listener started")

	select {
	case <-rootCtx.Done():
		log.Info().Msg("shutdown signal received")
	case err := <-proxyErrCh:
		if !isClosedServer(err) {
			log.Error().Err(err).Msg("proxy listener exited unexpectedly")
		}
	case err := <-controlErrCh:
		if !isClosedServer(err) {
			log.Error().Err(err).Msg("control listener exited unexpectedly")
		}
	}

	// Graceful shutdown — bound so a wedged peer can't hold us forever.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = proxy.Shutdown(shutdownCtx)
	_ = control.Shutdown(shutdownCtx)
	_ = auditSink.Shutdown(shutdownCtx)

	if dropped := droppedCount(auditSink); dropped > 0 {
		log.Warn().Int64("dropped", dropped).Msg("audit events dropped at shutdown")
	}
	return nil
}

func isClosedServer(err error) bool {
	if err == nil {
		return true
	}
	return err == http.ErrServerClosed
}

// droppedCount returns the SQLAuditSink dropped counter, or 0 for other sinks.
func droppedCount(sink secretsproxy.AuditSink) int64 {
	if s, ok := sink.(*secretsproxy.SQLAuditSink); ok {
		return s.Dropped()
	}
	return 0
}

// loadEgressBlocklist loads the operator blocklist and starts its refresh loop,
// returning the live matcher and the blocked egress ports. An unset or
// unparseable path returns (nil, nil) with enforcement disabled and logged,
// rather than silently passing traffic the operator expects to be blocked.
func loadEgressBlocklist(ctx context.Context, path string) (*blocklist.Blocklist, []int) {
	if path == "" {
		log.Warn().Msg("SECRETSPROXY_BLOCKLIST_CONFIG unset; proxied-path egress blocklist enforcement disabled")
		return nil, nil
	}
	cfg, err := blocklist.LoadConfig(path)
	if err != nil {
		log.Error().Err(err).Str("path", path).Msg("egress blocklist failed to load; proxied-path blocklist enforcement DISABLED")
		return nil, nil
	}
	bl := blocklist.New(cfg, log.Logger)
	go func() { _ = bl.Start(ctx) }()
	log.Info().
		Int("feeds", len(cfg.DomainFeeds)).
		Int("pinned_domains", len(cfg.CustomDomains)).
		Int("pinned_cidrs", len(cfg.CustomCIDRs)).
		Int("blocked_ports", len(cfg.BlockedEgressPorts)).
		Msg("egress blocklist enforced on proxied path")
	return bl, portsToInt(cfg.BlockedEgressPorts)
}

// revocationReconcileInterval bounds how long a dropped revocation push can go
// unnoticed: the push is the instant path, this periodic fetch is the backstop.
const revocationReconcileInterval = 60 * time.Second

// reconcileRevocations periodically merges the control plane's revoked set into
// the local one, so a revocation whose push was lost is still applied within the
// interval. A fetch error keeps the current set (last-known-good) — a transient
// outage never un-revokes a sandbox.
func reconcileRevocations(ctx context.Context, revoker *secretsproxy.Revoker, baseURL, token string) {
	ticker := time.NewTicker(revocationReconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			revoked, err := secretsproxy.FetchRevokedSandboxes(ctx, baseURL, token)
			if err != nil {
				log.Warn().Err(err).Msg("revocation reconcile failed; keeping last-known-good set")
				continue
			}
			revoker.Reconcile(revoked)
		}
	}
}

func portsToInt(ports []uint16) []int {
	if len(ports) == 0 {
		return nil
	}
	out := make([]int, len(ports))
	for i, p := range ports {
		out[i] = int(p)
	}
	return out
}

// buildPolicyResolver returns a resolver that sends queries to resolverAddr so
// resolution follows the same egress policy as guest traffic. A nil result
// (resolverAddr unset) means the default resolver.
func buildPolicyResolver(resolverAddr string) *net.Resolver {
	if resolverAddr == "" {
		return nil
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, network, resolverAddr)
		},
	}
}

// buildUpstreamTransport builds the upstream transport, resolving through res
// and applying the internal-IP and blocklist-CIDR guards on every dial.
func buildUpstreamTransport(res *net.Resolver, bl *blocklist.Blocklist) *http.Transport {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   dialGuard(bl),
		Resolver:  res,
	}
	return &http.Transport{
		DialContext:           pinnedDialContext(dialer),
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ForceAttemptHTTP2:     false,
	}
}

// pinnedDialContext dials the IP pinned on the request context (the address the
// CIDR policy was evaluated against) instead of re-resolving the host, so policy
// and connection always use the same IP. The dialer's Control guard still runs
// on the final address. Falls back to normal resolution when nothing is pinned.
func pinnedDialContext(d *net.Dialer) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if ip := secretsproxy.PinnedDialIP(ctx); ip != nil {
			if _, port, err := net.SplitHostPort(addr); err == nil {
				addr = net.JoinHostPort(ip.String(), port)
			}
		}
		return d.DialContext(ctx, network, addr)
	}
}

// dialGuard rejects dials to internal ranges and to operator-blocklisted CIDRs.
// Running on the resolved address, it catches IP-literal targets and hostnames
// that resolve into a denied range (the domain blocklist is enforced earlier, at
// CONNECT, where the hostname is known). A nil bl skips the blocklist check.
func dialGuard(bl *blocklist.Blocklist) func(string, string, syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return nil
		}
		if egresspolicy.IsIPDenied(ip) {
			return fmt.Errorf("blocked: internal address %s", ip)
		}
		if bl != nil {
			if blocked, _ := bl.Blocked("", ip); blocked {
				return fmt.Errorf("blocked: egress blocklist %s", ip)
			}
		}
		return nil
	}
}

type config struct {
	ProxyAddr         string
	ControlSocketPath string
	CACertPath        string
	CAKeyPath         string
	CertCacheSize     int

	ControlPlaneURL    string
	DaemonAuthToken    string
	VaultCacheTTL      time.Duration
	VaultCacheIdleTTL  time.Duration
	VaultCacheCapacity int

	DatabaseURL string

	AuditBufferSize int
	AuditBatchSize  int
	AuditFlushEvery time.Duration

	SandboxFacingHost   string
	MaxRequestBodyBytes int64

	// UpstreamResolverAddr, when set, routes upstream name resolution through
	// this DNS server (host:port) so dials follow the same egress policy as
	// guest traffic.
	UpstreamResolverAddr string

	// BlocklistConfigPath points at the operator egress-blocklist YAML. Its
	// blocked_egress_ports are refused at CONNECT, matching the host firewall.
	BlocklistConfigPath string
}

func loadConfig() (*config, error) {
	c := &config{
		ProxyAddr:            envOr("SECRETSPROXY_LISTEN", "0.0.0.0:9443"),
		ControlSocketPath:    envOr("SECRETSPROXY_SOCKET", "/run/secretsproxy/control.sock"),
		CACertPath:           envOr("SECRETSPROXY_CA_CERT", "/var/lib/secretsproxy/ca.crt"),
		CAKeyPath:            envOr("SECRETSPROXY_CA_KEY", "/var/lib/secretsproxy/ca.key"),
		CertCacheSize:        1024,
		ControlPlaneURL:      strings.TrimRight(envOr("CONTROL_PLANE_URL", ""), "/"),
		DaemonAuthToken:      os.Getenv("DAEMON_AUTH_TOKEN"),
		VaultCacheTTL:        parseDur(os.Getenv("VAULT_CACHE_TTL"), 60*time.Second),
		VaultCacheIdleTTL:    parseDur(os.Getenv("VAULT_CACHE_IDLE_TTL"), 10*time.Minute),
		VaultCacheCapacity:   int(parseInt64Bytes(os.Getenv("VAULT_CACHE_CAPACITY"), 1024)),
		DatabaseURL:          os.Getenv("DATABASE_URL"),
		AuditBufferSize:      4096,
		AuditBatchSize:       64,
		AuditFlushEvery:      250 * time.Millisecond,
		MaxRequestBodyBytes:  parseInt64Bytes(os.Getenv("SECRETSPROXY_MAX_BODY_BYTES"), 256*1024*1024),
		UpstreamResolverAddr: strings.TrimSpace(os.Getenv("SECRETSPROXY_DNS_RESOLVER")),
		BlocklistConfigPath:  strings.TrimSpace(os.Getenv("SECRETSPROXY_BLOCKLIST_CONFIG")),
	}
	flag.StringVar(&c.ProxyAddr, "listen", c.ProxyAddr, "proxy listener address (host:port)")
	flag.StringVar(&c.ControlSocketPath, "socket", c.ControlSocketPath, "control RPC unix socket path")
	flag.Parse()

	if c.ControlPlaneURL == "" {
		return nil, fmt.Errorf("CONTROL_PLANE_URL is required")
	}
	if c.DaemonAuthToken == "" {
		return nil, fmt.Errorf("DAEMON_AUTH_TOKEN is required")
	}
	if addr := os.Getenv("SECRETSPROXY_SANDBOX_ADDR"); addr != "" {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("SECRETSPROXY_SANDBOX_ADDR %q: %w", addr, err)
		}
		c.SandboxFacingHost = host
	}
	if c.UpstreamResolverAddr != "" {
		if _, _, err := net.SplitHostPort(c.UpstreamResolverAddr); err != nil {
			return nil, fmt.Errorf("SECRETSPROXY_DNS_RESOLVER %q: %w", c.UpstreamResolverAddr, err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(c.CACertPath), 0o700); err != nil {
		return nil, fmt.Errorf("mkdir CA dir: %w", err)
	}
	return c, nil
}

func envOr(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}

func parseDur(raw string, fallback time.Duration) time.Duration {
	if raw == "" {
		return fallback
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return fallback
	}
	return d
}

func parseInt64Bytes(raw string, fallback int64) int64 {
	if raw == "" {
		return fallback
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

// buildAuditSink returns the SQL sink; missing DATABASE_URL fails closed unless SECRETSPROXY_AUDIT_DISABLED=true.
func buildAuditSink(ctx context.Context, cfg *config) (secretsproxy.AuditSink, func(), error) {
	if cfg.DatabaseURL == "" {
		if os.Getenv("SECRETSPROXY_AUDIT_DISABLED") == "true" {
			log.Warn().Msg("SECRETSPROXY_AUDIT_DISABLED=true; audit events will be discarded")
			return secretsproxy.NewNopAuditSink(), nil, nil
		}
		return nil, nil, fmt.Errorf("DATABASE_URL is required; set SECRETSPROXY_AUDIT_DISABLED=true to run without audit")
	}
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, nil, fmt.Errorf("connect to audit DB: %w", err)
	}
	queries := dbq.New(pool)
	sink := secretsproxy.NewSQLAuditSink(queries, secretsproxy.SQLAuditSinkOptions{
		BufferSize:    cfg.AuditBufferSize,
		BatchSize:     cfg.AuditBatchSize,
		FlushInterval: cfg.AuditFlushEvery,
	})
	cleanup := func() { pool.Close() }
	log.Info().Msg("audit sink: SQL")
	return sink, cleanup, nil
}
