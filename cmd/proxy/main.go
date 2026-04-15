package main

import (
	"context"
	"encoding/hex"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/superserve-ai/sandbox/internal/auth"
	"github.com/superserve-ai/sandbox/internal/proxy"
	"github.com/superserve-ai/sandbox/internal/telemetry"
)

// version is set by ldflags at build time; falls back to "dev".
var version = "dev"

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log := zerolog.New(os.Stdout).With().
		Timestamp().
		Str("service", "proxy").
		Logger().
		Hook(telemetry.ZerologTraceHook{})

	addr := envOrDefault("PROXY_ADDR", ":5007")
	redirectAddr := envOrDefault("PROXY_REDIRECT_ADDR", ":5008")
	vmdAddr := envOrDefault("VMD_ADDR", "http://127.0.0.1:9090")
	domain := envOrDefault("PROXY_DOMAIN", "sandbox.superserve.ai")

	log.Info().
		Str("addr", addr).
		Str("vmd_addr", vmdAddr).
		Str("domain", domain).
		Msg("starting edge proxy")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	tel, err := telemetry.New(ctx, "proxy", version, os.Getenv("NODE_ID"))
	if err != nil {
		log.Fatal().Err(err).Msg("init telemetry")
	}
	defer func() {
		if err := tel.Shutdown(context.Background()); err != nil {
			log.Warn().Err(err).Msg("telemetry shutdown")
		}
	}()
	if err := tel.StartRuntimeInstrumentation(); err != nil {
		log.Warn().Err(err).Msg("runtime instrumentation")
	}

	resolver := proxy.NewVMDResolver(vmdAddr)
	proxyHandler := proxy.NewHandler(domain, resolver, log)
	proxyHandler.StartSweeper(ctx)

	// Data-plane auth — the HMAC seed is shared with the control plane.
	// Both sides derive per-sandbox access tokens as HMAC-SHA256(seed, sandboxID).
	seedHex := os.Getenv("SANDBOX_ACCESS_TOKEN_SEED")
	originsEnv := os.Getenv("TERMINAL_ALLOWED_ORIGINS")
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
		proxyHandler.WithFiles()
		log.Info().Msg("files endpoint enabled")

		if originsEnv != "" {
			origins := splitCSV(originsEnv)
			proxyHandler.WithTerminal(origins)
			log.Info().Strs("allowed_origins", origins).Msg("terminal endpoint enabled")
		} else {
			log.Warn().Msg("terminal endpoint disabled (TERMINAL_ALLOWED_ORIGINS not configured)")
		}
	}

	// Health check for the GCP LB. Only responds on non-sandbox hosts
	// so the boxd-label lockdown isn't bypassed.
	domainSuffix := "." + domain
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if i := strings.IndexByte(host, ':'); i >= 0 {
			host = host[:i]
		}
		if strings.HasSuffix(host, domainSuffix) {
			proxyHandler.ServeHTTP(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.Handle("/", proxyHandler)

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

	// otelhttp wraps the entire mux so every forwarded request becomes a
	// span. The /health filter avoids drowning the trace backend in
	// noise from the LB liveness probe.
	tracedMux := otelhttp.NewHandler(mux, "proxy",
		otelhttp.WithFilter(func(r *http.Request) bool {
			return r.URL.Path != "/health"
		}),
	)
	if err := proxy.ListenAndServe(ctx, addr, tracedMux, log); err != nil {
		log.Fatal().Err(err).Msg("proxy error")
	}

	// Shut down the redirect listener cleanly.
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()
	_ = redirectSrv.Shutdown(shutCtx)

	log.Info().Msg("proxy stopped")
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
