package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	var peerErr <-chan error
	peerRecorder := telemetry.NewNoopRecorder()

	resolver := proxy.NewVMDResolver(vmdAddr)
	proxyHandler := proxy.NewHandler(domains, resolver, log)
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal().Msg("DATABASE_URL is required for cross-host routing")
	}
	dbPool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		log.Fatal().Err(err).Msg("init ownership database")
	}
	defer dbPool.Close()
	// Cross-host routing must not start in a silently local-only or
	// unavailable state. Validate the shared persistence connection before
	// bringing up either listener; later lookups still use their request
	// contexts for cancellation and bounded work.
	bootstrapCtx, bootstrapCancel := context.WithTimeout(ctx, 5*time.Second)
	err = dbPool.Ping(bootstrapCtx)
	bootstrapCancel()
	if err != nil {
		log.Fatal().Err(err).Msg("ownership database unavailable")
	}
	ownership := proxy.NewDBOwnershipResolver(dbPool)
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
	proxyHandler.StartSweeper(ctx)

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

	// Health check for the GCP LB and VMD's end-to-end capability probe.
	// It only responds on non-sandbox hosts so the boxd-label lockdown isn't
	// bypassed.
	peerTLS, peers, err := newOutboundPeerTransport(log, peerTelemetry)
	if err != nil {
		log.Fatal().Err(err).Msg("invalid peer client credentials")
	}
	defer peers.Close()
	router := proxy.NewRoutingHandler(domains, os.Getenv("HOST_ID"), ownership, peers, proxyHandler, log, routingRecorder)
	mux, localMux := newDataPlaneMuxes(proxyHandler, router)
	var localSrv *http.Server
	var localErr <-chan error
	if peerAddr := os.Getenv("PEER_PROXY_LISTEN_ADDR"); peerIngressEnabled(peerAddr) {
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
		localErrCh := make(chan error, 1)
		localErr = localErrCh
		go func() {
			err := localSrv.Serve(localListener)
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
			err := proxy.ServePeerListenerWithRecorder(ctx, peerListener, cfg, target, log, peerRecorder, streamLimit)
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
	redirectMux := http.NewServeMux()
	redirectMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if i := strings.IndexByte(host, ':'); i >= 0 {
			host = host[:i]
		}
		http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusMovedPermanently)
	})
	redirectSrv := &http.Server{
		Addr:    redirectAddr,
		Handler: redirectMux,
	}
	go func() {
		log.Info().Str("addr", redirectAddr).Msg("starting HTTP→HTTPS redirect listener")
		if err := redirectSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error().Err(err).Msg("redirect listener error")
		}
	}()

	if err := proxy.ListenAndServe(ctx, addr, mux, log); err != nil {
		log.Fatal().Err(err).Msg("proxy error")
	}
	if peerErr != nil {
		if err := <-peerErr; err != nil {
			log.Fatal().Err(err).Msg("peer ingress stopped")
		}
	}

	// Shut down the redirect listener cleanly.
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()
	_ = redirectSrv.Shutdown(shutCtx)
	if localSrv != nil {
		_ = localSrv.Shutdown(shutCtx)
		if err := <-localErr; err != nil {
			log.Fatal().Err(err).Msg("local peer target stopped")
		}
	}

	log.Info().Msg("proxy stopped")
}

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
	if err := proxy.ValidatePeerEndpoint(peerAddr); err != nil {
		return err
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

// peerIngressEnabled keeps the optional listener gated solely by its explicit
// address. Outbound client credentials remain mandatory when ingress is disabled.
func peerIngressEnabled(addr string) bool { return addr != "" }

type proxyHealthResponse struct {
	Capabilities  []string `json:"capabilities"`
	FilesEnabled  bool     `json:"files_enabled"`
	ResolverReady bool     `json:"resolver_ready"`
}

func newProxyMux(proxyHandler *proxy.Handler) *http.ServeMux {
	return newProxyMuxWithHandler(proxyHandler, proxyHandler)
}

func newDataPlaneMuxes(local *proxy.Handler, router *proxy.RoutingHandler) (publicMux, localMux *http.ServeMux) {
	return newProxyMuxWithHandler(local, router), newProxyMux(local)
}

func newProxyMuxWithHandler(proxyHandler *proxy.Handler, dataPlane http.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if proxyHandler.ServesHost(r.Host) {
			dataPlane.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(proxyHealthResponse{
			Capabilities:  proxyHandler.PreviewCapabilities(),
			FilesEnabled:  proxyHandler.FilesEnabled(),
			ResolverReady: proxyHandler.ResolverReady(r.Context()),
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
	return cfg, proxy.NewPeerTransport(proxy.PeerPoolConfig{Dial: proxy.GRPCPeerDialer(cfg.LoadClient), Telemetry: recorder}), nil
}
