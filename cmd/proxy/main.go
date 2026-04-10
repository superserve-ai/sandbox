package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/proxy"
)

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log := zerolog.New(os.Stdout).With().
		Timestamp().
		Str("service", "proxy").
		Logger()

	addr := envOrDefault("PROXY_ADDR", ":5007")
	vmdAddr := envOrDefault("VMD_ADDR", "http://127.0.0.1:9090")
	domain := envOrDefault("PROXY_DOMAIN", "sandbox.superserve.ai")

	log.Info().
		Str("addr", addr).
		Str("vmd_addr", vmdAddr).
		Str("domain", domain).
		Msg("starting edge proxy")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	resolver := proxy.NewVMDResolver(vmdAddr)
	proxyHandler := proxy.NewHandler(domain, resolver, log)
	proxyHandler.StartSweeper(ctx)

	// Wrap with a health check endpoint for the GCP LB health probe.
	// The LB hits /health directly on the instance IP (not a sandbox URL),
	// so the proxy handler would reject it — intercept it first.
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.Handle("/", proxyHandler)

	if err := proxy.ListenAndServe(ctx, addr, mux, log); err != nil {
		log.Fatal().Err(err).Msg("proxy error")
	}
	log.Info().Msg("proxy stopped")
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
