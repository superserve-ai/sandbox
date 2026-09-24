package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/coreos/go-systemd/v22/activation"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/analytics"
	"github.com/superserve-ai/sandbox/internal/auth"
	"github.com/superserve-ai/sandbox/internal/proxy"
	"github.com/superserve-ai/sandbox/internal/sentrylog"
	"github.com/superserve-ai/sandbox/internal/telemetry"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "proxy exited with error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	multi := zerolog.MultiLevelWriter(os.Stdout, &sentrylog.Writer{})
	log := zerolog.New(multi).With().
		Timestamp().
		Str("service", "proxy").
		Logger()

	if dsn := os.Getenv("SENTRY_DSN"); dsn != "" {
		if err := sentry.Init(sentry.ClientOptions{Dsn: dsn, EnableLogs: true}); err != nil {
			log.Warn().Err(err).Msg("sentry.Init failed")
		} else {
			defer sentry.Flush(2 * time.Second)
		}
	}

	addr := envOrDefault("PROXY_ADDR", ":5007")
	redirectAddr := envOrDefault("PROXY_REDIRECT_ADDR", ":5008")
	drainGrace, err := time.ParseDuration(envOrDefault("PROXY_DRAIN_GRACE", "30s"))
	if err != nil || drainGrace <= 0 || drainGrace > 10*time.Minute {
		log.Fatal().Msg("PROXY_DRAIN_GRACE must be positive and at most 10m")
	}
	vmdAddr := envOrDefault("VMD_ADDR", "http://127.0.0.1:9090")
	domains := proxyDomains()
	if legacy := os.Getenv("PROXY_DOMAIN"); legacy != "" && !slices.Contains(domains, legacy) {
		log.Warn().Str("proxy_domain", legacy).Strs("effective_domains", domains).
			Msg("PROXY_DOMAIN is set but not in the effective domain list — PROXY_DOMAINS overrides it and this host will stop serving it")
	}

	log.Info().
		Str("addr", addr).
		Str("vmd_addr", vmdAddr).
		Strs("domains", domains).
		Msg("starting edge proxy")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	workCtx, finishWork := context.WithCancel(context.Background())
	defer finishWork()
	drainDeadline := make(chan context.Context, 1)
	go func() {
		<-ctx.Done()
		deadline, cancel := context.WithTimeout(context.Background(), drainGrace)
		defer cancel()
		drainDeadline <- deadline
		<-deadline.Done()
	}()
	var peerErr <-chan error
	peerRecorder := telemetry.NewNoopRecorder()

	resolver := proxy.NewVMDResolver(vmdAddr)
	proxyHandler := proxy.NewHandler(domains, resolver, log)
	routingEnabled := os.Getenv("PEER_ROUTING_ENABLED")
	if routingEnabled != "" && routingEnabled != "0" && routingEnabled != "1" {
		log.Fatal().Msg("PEER_ROUTING_ENABLED must be empty, 0, or 1")
	}
	dbPool, err := newOwnershipPool(ctx, routingEnabled == "1", os.Getenv("PROXY_DATABASE_URL"))
	if err != nil {
		log.Fatal().Err(err).Msg("init ownership database")
	}
	localHostID := os.Getenv("HOST_ID")
	var ownership proxy.OwnershipResolver
	if dbPool != nil {
		defer dbPool.Close()
		ownership = proxy.NewCachedOwnershipResolver(workCtx, proxy.NewDBOwnershipResolver(dbPool, localHostID))
	}
	var routingRecorder telemetry.RoutingOutcomeRecorder
	var peerTelemetry proxy.RecorderPeerTelemetry
	if envOrDefault("OTEL_METRICS_ENABLED", "false") == "true" {
		interval, ierr := time.ParseDuration(envOrDefault("OTEL_EXPORT_INTERVAL", "15s"))
		if ierr != nil {
			log.Warn().Err(ierr).Msg("invalid OTEL_EXPORT_INTERVAL; using 15s")
			interval = 15 * time.Second
		}
		rec, rerr := telemetry.NewOTelRecorder(ctx, telemetry.OTelConfig{
			HostID:         os.Getenv("HOST_ID"),
			ServiceName:    envOrDefault("OTEL_SERVICE_NAME", "sandbox-proxy"),
			ServiceVersion: os.Getenv("OTEL_SERVICE_VERSION"),
			Environment:    envOrDefault("OTEL_ENVIRONMENT", "dev"),
			Endpoint:       envOrDefault("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318"),
			ExportInterval: interval,
		})
		if rerr != nil {
			log.Error().Err(rerr).Msg("otel metrics init failed; proxy metrics disabled")
		} else {
			peerRecorder = rec
			proxyHandler.WithTelemetry(rec)
			routingRecorder = rec
			peerTelemetry = proxy.RecorderPeerTelemetry{Recorder: rec, HostID: os.Getenv("HOST_ID"), Region: os.Getenv("HOST_REGION")}
			defer func() {
				// Bounded: a stalled collector must not hang proxy restarts
				// on the final flush.
				flushCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				_ = rec.Shutdown(flushCtx)
			}()
			log.Info().Msg("otel metrics enabled")
		}
	}
	proxyHandler.StartSweeper(workCtx)

	// Product-usage analytics for exec/files — no-op when POSTHOG_KEY is unset.
	analyticsClient, err := analytics.New(os.Getenv("POSTHOG_KEY"), os.Getenv("POSTHOG_HOST"), log)
	if err != nil {
		log.Fatal().Err(err).Msg("init analytics")
	}
	defer analyticsClient.Close()
	proxyHandler.WithAnalytics(analyticsClient)

	// Data-plane auth — the HMAC seed is shared with the control plane.
	// Both sides derive per-sandbox access tokens as HMAC-SHA256(seed, sandboxID).
	seedHex := os.Getenv("SANDBOX_ACCESS_TOKEN_SEED")
	originsEnv := os.Getenv("PROXY_ALLOWED_ORIGINS")
	required := os.Getenv("REQUIRE_DATA_PLANE") == "1"

	if seedHex == "" {
		if required {
			log.Fatal().Msg("REQUIRE_DATA_PLANE=1 but SANDBOX_ACCESS_TOKEN_SEED missing")
		}
		log.Warn().Msg("data-plane endpoints disabled (SANDBOX_ACCESS_TOKEN_SEED not configured)")
	} else {
		seed, err := hex.DecodeString(seedHex)
		if err != nil {
			log.Fatal().Err(err).Msg("SANDBOX_ACCESS_TOKEN_SEED is not valid hex")
		}
		if err := auth.ValidateSeed(seed); err != nil {
			log.Fatal().Err(err).Msg("SANDBOX_ACCESS_TOKEN_SEED invalid")
		}

		proxyHandler.WithAuth(seed)
		resolver.WithPreviewTokens()
		resolver.WithPreviewBrowserAuth()
		proxyHandler.WithFiles()
		log.Info().Msg("files endpoint enabled")
		proxyHandler.WithExec()
		log.Info().Msg("exec endpoint enabled")

		if originsEnv != "" {
			origins := splitCSV(originsEnv)
			if required && len(origins) == 1 && origins[0] == "*" {
				log.Fatal().Msg("REQUIRE_DATA_PLANE=1 but PROXY_ALLOWED_ORIGINS is wildcard (*) — refusing to start with open origins in production")
			}
			proxyHandler.WithTerminal(origins)
			log.Info().Strs("allowed_origins", origins).Msg("terminal endpoint enabled")
		} else {
			log.Warn().Msg("terminal endpoint disabled (PROXY_ALLOWED_ORIGINS not configured)")
		}
	}

	// Legacy hosts can keep serving local traffic during the staged peer rollout.
	// Credentials become mandatory as soon as this host either accepts peer ingress
	// or participates in outbound ownership routing.
	peerAddr := os.Getenv("PEER_PROXY_LISTEN_ADDR")
	var peerTLS proxy.PeerTLSConfig
	var peers proxy.PeerTransport
	if peerTransportRequired(routingEnabled, peerAddr) {
		peerTLS, peers, err = newOutboundPeerTransport(log, peerTelemetry)
		if err != nil {
			log.Fatal().Err(err).Msg("invalid peer client credentials")
		}
		defer peers.Close()
	}
	router := proxy.NewRoutingHandler(domains, localHostID, ownership, peers, proxyHandler, log, routingRecorder)
	log.Info().Bool("enabled", routingEnabled == "1").Msg("peer ownership routing configured")
	mux, localMux := newDataPlaneMuxes(proxyHandler, router, routingEnabled == "1")
	if dbPool != nil {
		mux = newProxyMuxWithReadiness(proxyHandler, router, func(ctx context.Context) bool {
			ctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
			defer cancel()
			return dbPool.Ping(ctx) == nil
		})
	}
	var localSrv *http.Server
	var localConnections *proxy.DrainConnections
	var localErr <-chan error
	if peerIngressEnabled(peerAddr) {
		if err := validatePeerListener(peerAddr, addr, redirectAddr); err != nil {
			log.Fatal().Err(err).Msg("invalid PEER_PROXY_LISTEN_ADDR")
		}
		cfg, err := peerTLS.Load()
		if err != nil {
			log.Fatal().Err(err).Msg("peer TLS setup failed")
		}
		streamLimit, err := strconv.ParseInt(envOrDefault("PEER_PROXY_MAX_STREAMS", "128"), 10, 32)
		if err != nil || streamLimit <= 0 {
			log.Fatal().Msg("PEER_PROXY_MAX_STREAMS must be a positive 32-bit integer")
		}
		target := envOrDefault("PEER_PROXY_TARGET_ADDR", "127.0.0.1:5010")
		if err := validateListenerPorts(target, peerAddr, redirectAddr); err != nil {
			log.Fatal().Err(err).Msg("peer target shares an ingress port")
		}
		localListener, err := bindLocalPeerTarget(target, addr, redirectAddr)
		if err != nil {
			log.Fatal().Err(err).Msg("local peer target bind failed")
		}
		// Peer traffic terminates at the local handler, never the public router.
		localSrv = proxy.NewServer(target, localMux)
		localConnections = proxy.NewDrainConnections()
		localSrv.ConnState = localConnections.ConnState
		localErrCh := make(chan error, 1)
		localErr = localErrCh
		go func() {
			err := localSrv.Serve(localConnections.Listener(localListener))
			if err == http.ErrServerClosed {
				err = nil
			}
			localErrCh <- err
			if err != nil {
				stop()
			}
		}()
		// Bind synchronously so an enabled peer ingress cannot fail silently
		// while the public listener continues serving without private routing.
		peerListener, err := net.Listen("tcp", peerAddr)
		if err != nil {
			log.Fatal().Err(err).Msg("peer ingress bind failed")
		}
		errCh := make(chan error, 1)
		peerErr = errCh
		go func() {
			err := proxy.ServePeerListenerWithDrain(ctx, peerListener, cfg, target, log, peerRecorder, streamLimit, drainGrace)
			// Always publish the result so shutdown supervision cannot race a
			// failed Serve call and silently discard its error.
			errCh <- err
			if err != nil && ctx.Err() == nil {
				// Cancel the shared lifecycle immediately; main will supervise
				// the error after the public listener has shut down.
				stop()
			}
		}()
	}

	// HTTP→HTTPS redirect listener with graceful shutdown.
	redirectMux := newRedirectMux(proxyHandler, mux)
	redirectSrv := &http.Server{
		Addr:    redirectAddr,
		Handler: redirectMux,
	}
	// Buffer the failure so the serve goroutine can report it before canceling
	// the shared lifecycle and waiting for the public drain to finish.
	redirectErrCh := make(chan error, 1)
	// Socket-activated listeners survive a restart (deploy/proxy.socket).
	publicLis, redirectLis := inheritedListeners(activation.Listeners, addr, redirectAddr, log)
	if redirectLis == nil {
		// Bind before starting the public server so a redirect collision fails
		// startup and cannot be mistaken for a clean lifecycle cancellation.
		redirectLis, err = net.Listen("tcp", redirectAddr)
		if err != nil {
			return fmt.Errorf("bind redirect listener: %w", err)
		}
	}
	go func() {
		defer close(redirectErrCh)
		log.Info().Str("addr", redirectAddr).Msg("starting HTTP→HTTPS redirect listener")
		err := redirectSrv.Serve(redirectLis)
		if err != nil && err != http.ErrServerClosed {
			log.Error().Err(err).Msg("redirect listener error")
			propagateRedirectError(err, redirectErrCh, stop)
		}
	}()

	if err := proxy.ServeWithDrain(ctx, publicLis, addr, mux, drainGrace, log); err != nil {
		log.Fatal().Err(err).Msg("proxy error")
	}
	if peerErr != nil {
		if err := <-peerErr; err != nil {
			log.Fatal().Err(err).Msg("peer ingress stopped")
		}
	}

	// Shut down the redirect listener cleanly.
	shutCtx := <-drainDeadline
	_ = redirectSrv.Shutdown(shutCtx)
	if err := <-redirectErrCh; err != nil {
		return fmt.Errorf("redirect listener stopped: %w", err)
	}
	if localSrv != nil {
		_ = localConnections.Shutdown(shutCtx, localSrv, log)
		if err := <-localErr; err != nil {
			log.Fatal().Err(err).Msg("local peer target stopped")
		}
	}

	log.Info().Msg("proxy stopped")
	return nil
}

func propagateRedirectError(err error, report chan<- error, stop context.CancelFunc) {
	if err == nil || err == http.ErrServerClosed {
		return
	}
	report <- err
	stop()
}

func newRedirectMux(proxyHandler *proxy.Handler, readiness http.Handler) *http.ServeMux {
	redirectMux := http.NewServeMux()
	redirectMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" && !proxyHandler.ServesHost(r.Host) {
			if r.Host == "proxy-readiness.invalid" {
				readiness.ServeHTTP(w, r)
				return
			}
			readiness.ServeHTTP(readinessHeaders{w}, r)
			w.Header().Del("Content-Type")
		}
		host := r.Host
		if i := strings.IndexByte(host, ':'); i >= 0 {
			host = host[:i]
		}
		http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusMovedPermanently)
	})
	return redirectMux
}

// Keep the normal redirect while attributing its resolver readiness to this process.
type readinessHeaders struct{ http.ResponseWriter }

func (w readinessHeaders) WriteHeader(int)                {}
func (w readinessHeaders) Write(body []byte) (int, error) { return len(body), nil }

// bindLocalPeerTarget keeps peer traffic off the public routing and redirect ports.
func bindLocalPeerTarget(target, publicAddr, redirectAddr string) (net.Listener, error) {
	parsed, err := netip.ParseAddrPort(target)
	if err != nil || !parsed.Addr().IsLoopback() || parsed.Port() == 0 {
		return nil, fmt.Errorf("peer target must be a loopback IP with a nonzero port: %q", target)
	}
	if err := validateListenerPorts(target, publicAddr, redirectAddr); err != nil {
		return nil, err
	}
	return net.Listen("tcp", target)
}

func validatePeerListener(peerAddr, publicAddr, redirectAddr string) error {
	endpoint, err := netip.ParseAddrPort(peerAddr)
	if err != nil || !proxy.PrivateBind(peerAddr) || (endpoint.Port() != proxy.PeerPort && endpoint.Port() != 5102 && endpoint.Port() != 5112) {
		return fmt.Errorf("peer listener must use a private IP and a reserved peer port: %q", peerAddr)
	}
	return validateListenerPorts(peerAddr, publicAddr, redirectAddr)
}

func validateListenerPorts(peerAddr, publicAddr, redirectAddr string) error {
	_, peerPort, err := net.SplitHostPort(peerAddr)
	if err != nil {
		return err
	}
	peerNumber, err := net.LookupPort("tcp", peerPort)
	if err != nil {
		return err
	}
	for _, addr := range []string{publicAddr, redirectAddr} {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			continue
		}
		number, err := net.LookupPort("tcp", port)
		if err == nil && number == peerNumber {
			return fmt.Errorf("peer listener %q must use a distinct port from %q", peerAddr, addr)
		}
	}
	return nil
}

// peerIngressEnabled keeps the optional listener gated solely by its explicit address.
func peerIngressEnabled(addr string) bool { return addr != "" }

func peerTransportRequired(routingEnabled, peerAddr string) bool {
	return routingEnabled == "1" || peerIngressEnabled(peerAddr)
}

type proxyHealthResponse struct {
	Generation    string   `json:"generation"`
	Capabilities  []string `json:"capabilities"`
	FilesEnabled  bool     `json:"files_enabled"`
	ResolverReady bool     `json:"resolver_ready"`
}

func newOwnershipPool(ctx context.Context, enabled bool, databaseURL string) (*pgxpool.Pool, error) {
	if !enabled {
		return nil, nil
	}
	if databaseURL == "" {
		return nil, fmt.Errorf("PROXY_DATABASE_URL is required for cross-host routing")
	}
	config, err := ownershipPoolConfig(databaseURL)
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, err
	}
	// Validate persistence before accepting routed traffic.
	bootstrapCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(bootstrapCtx); err != nil {
		pool.Close()
		return nil, err
	}
	var restricted bool
	err = pool.QueryRow(bootstrapCtx, `SELECT current_user = 'sandbox_proxy_router'
		AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls
		AND NOT EXISTS (SELECT 1 FROM pg_auth_members WHERE member = pg_roles.oid)
		AND NOT has_table_privilege(current_user, 'public.sandbox', 'INSERT,UPDATE,DELETE,TRUNCATE')
		AND NOT has_any_column_privilege(current_user, 'public.sandbox', 'INSERT,UPDATE')
		AND NOT has_table_privilege(current_user, 'public.host', 'INSERT,UPDATE,DELETE,TRUNCATE')
		AND NOT has_any_column_privilege(current_user, 'public.host', 'INSERT,UPDATE')
		FROM pg_roles WHERE rolname = current_user`).Scan(&restricted)
	if err != nil || !restricted {
		pool.Close()
		return nil, fmt.Errorf("ownership database requires the restricted sandbox_proxy_router role")
	}
	return pool, nil
}

func ownershipPoolConfig(databaseURL string) (*pgxpool.Config, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, err
	}
	// Fixed per-process budget: independent of host CPU count and URL options.
	config.MaxConns = 4
	config.MinConns = 0
	config.MinIdleConns = 0
	config.ConnConfig.RuntimeParams["default_transaction_read_only"] = "on"
	config.ConnConfig.RuntimeParams["statement_timeout"] = "500"
	config.ConnConfig.RuntimeParams["search_path"] = "public,pg_catalog"
	return config, nil
}

func newProxyMux(proxyHandler *proxy.Handler) *http.ServeMux {
	return newProxyMuxWithHandler(proxyHandler, proxyHandler)
}

func newDataPlaneMuxes(local *proxy.Handler, router http.Handler, routingEnabled bool) (publicMux, localMux *http.ServeMux) {
	if !routingEnabled {
		return newProxyMux(local), newProxyMux(local)
	}
	return newProxyMuxWithHandler(local, router), newProxyMux(local)
}

func newProxyMuxWithHandler(proxyHandler *proxy.Handler, dataPlane http.Handler) *http.ServeMux {
	return newProxyMuxWithReadiness(proxyHandler, dataPlane, nil)
}

func newProxyMuxWithReadiness(proxyHandler *proxy.Handler, dataPlane http.Handler, dependencies func(context.Context) bool) *http.ServeMux {
	generation := os.Getenv("PROXY_GENERATION")
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if proxyHandler.ServesHost(r.Host) {
			dataPlane.ServeHTTP(w, r)
			return
		}
		resolverReady := proxyHandler.ResolverReady(r.Context())
		if dependencies != nil {
			resolverReady = dependencies(r.Context()) && resolverReady
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Proxy-Generation", generation)
		w.Header().Set("X-Proxy-Resolver-Ready", strconv.FormatBool(resolverReady))
		w.Header().Set("Content-Type", "application/json")
		if r.Host == "proxy-readiness.invalid" && !resolverReady {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_ = json.NewEncoder(w).Encode(proxyHealthResponse{
			Generation:    generation,
			Capabilities:  proxyHandler.PreviewCapabilities(),
			FilesEnabled:  proxyHandler.FilesEnabled(),
			ResolverReady: resolverReady,
		})
	})
	mux.Handle("/", dataPlane)
	return mux
}

// proxyDomains resolves the set of sandbox domains the proxy accepts.
// PROXY_DOMAINS (comma-separated) takes precedence so one deploy can serve
// both the legacy hostname and the region-prefixed hostname during a DNS
// transition; otherwise the single-value PROXY_DOMAIN keeps existing
// deploys unchanged.
func proxyDomains() []string {
	if domains := splitCSV(os.Getenv("PROXY_DOMAINS")); len(domains) > 0 {
		return domains
	}
	return []string{envOrDefault("PROXY_DOMAIN", "sandbox.superserve.ai")}
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func splitCSV(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if t := strings.TrimSpace(s); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func newOutboundPeerTransport(log zerolog.Logger, recorder proxy.PeerPoolTelemetry) (proxy.PeerTLSConfig, proxy.PeerTransport, error) {
	cfg := proxy.PeerTLSConfig{CertFile: os.Getenv("PEER_PROXY_CERT_FILE"), KeyFile: os.Getenv("PEER_PROXY_KEY_FILE"), CAFile: os.Getenv("PEER_PROXY_CA_FILE"), ExpectedSPIFFE: os.Getenv("PEER_PROXY_SPIFFE_URI"), Log: log}
	if _, err := cfg.LoadClient(); err != nil {
		return cfg, nil, err
	}
	return cfg, proxy.NewPeerTransport(proxy.PeerPoolConfig{Dial: proxy.GRPCPeerDialer(cfg.LoadClient), Telemetry: recorder, MaxConnections: 4, StreamsPerConnection: 32}), nil
}
