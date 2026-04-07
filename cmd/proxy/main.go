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
	vmdAddr := envOrDefault("VMD_ADDR", "http://localhost:9090")

	log.Info().
		Str("addr", addr).
		Str("vmd_addr", vmdAddr).
		Msg("starting edge proxy")

	resolver := proxy.NewResolver(vmdAddr)
	proxyHandler := proxy.NewHandler(resolver, log)

	// Wrap with a health check endpoint for the GCP LB health probe.
	// The LB hits /health directly on the instance IP (not a sandbox URL),
	// so the proxy handler would reject it — intercept it first.
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.Handle("/", proxyHandler)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Info().Str("signal", sig.String()).Msg("shutting down")
		cancel()
	}()

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

