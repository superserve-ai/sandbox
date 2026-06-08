// Command secretsproxy runs the in-host MITM enforcement daemon.
package main

import (
	"context"
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

	dbq "github.com/superserve-ai/sandbox/internal/db"
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
	cachedVault := secretsproxy.NewCachedVault(httpVault, cfg.VaultCacheTTL)

	revoker := secretsproxy.NewRevoker()
	revoked, err := secretsproxy.FetchRevokedSandboxes(rootCtx, cfg.ControlPlaneURL, cfg.DaemonAuthToken)
	if err != nil {
		return fmt.Errorf("bootstrap revocations: %w", err)
	}
	revoker.Bootstrap(revoked)
	log.Info().Int("revoked_sandboxes", len(revoked)).Msg("revocations loaded from control plane")

	auditSink, dbCleanup, err := buildAuditSink(rootCtx, cfg)
	if err != nil {
		return fmt.Errorf("init audit sink: %w", err)
	}
	defer func() {
		if dbCleanup != nil {
			dbCleanup()
		}
	}()

	proxy := secretsproxy.NewProxy(cfg.ProxyAddr, secretsproxy.Options{
		CA:                  ca,
		Resolver:            resolver,
		Vault:               cachedVault,
		Audit:               auditSink,
		Revoker:             revoker,
		SandboxFacingHost:   cfg.SandboxFacingHost,
		MaxRequestBodyBytes: cfg.MaxRequestBodyBytes,
	})
	proxyErrCh := make(chan error, 1)
	go func() { proxyErrCh <- proxy.ListenAndServe() }()
	log.Info().Str("addr", cfg.ProxyAddr).Msg("proxy listener started")

	control := secretsproxy.NewControlServer(cfg.ControlSocketPath, cachedVault, revoker)
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

type config struct {
	ProxyAddr         string
	ControlSocketPath string
	CACertPath        string
	CAKeyPath         string
	CertCacheSize     int

	ControlPlaneURL string
	DaemonAuthToken string
	VaultCacheTTL   time.Duration

	DatabaseURL string

	AuditBufferSize int
	AuditBatchSize  int
	AuditFlushEvery time.Duration

	SandboxFacingHost   string
	MaxRequestBodyBytes int64
}

func loadConfig() (*config, error) {
	c := &config{
		ProxyAddr:         envOr("SECRETSPROXY_LISTEN", "0.0.0.0:9443"),
		ControlSocketPath: envOr("SECRETSPROXY_SOCKET", "/run/secretsproxy/control.sock"),
		CACertPath:        envOr("SECRETSPROXY_CA_CERT", "/var/lib/secretsproxy/ca.crt"),
		CAKeyPath:         envOr("SECRETSPROXY_CA_KEY", "/var/lib/secretsproxy/ca.key"),
		CertCacheSize:     1024,
		ControlPlaneURL:   strings.TrimRight(envOr("CONTROL_PLANE_URL", ""), "/"),
		DaemonAuthToken:   os.Getenv("DAEMON_AUTH_TOKEN"),
		VaultCacheTTL:     parseDur(os.Getenv("VAULT_CACHE_TTL"), 60*time.Second),
		DatabaseURL:       os.Getenv("DATABASE_URL"),
		AuditBufferSize:     4096,
		AuditBatchSize:      64,
		AuditFlushEvery:     250 * time.Millisecond,
		MaxRequestBodyBytes: parseInt64Bytes(os.Getenv("SECRETSPROXY_MAX_BODY_BYTES"), 256*1024*1024),
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
