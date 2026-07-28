package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/analytics"
	"github.com/superserve-ai/sandbox/internal/auth"
	"github.com/superserve-ai/sandbox/internal/preview"
	"github.com/superserve-ai/sandbox/internal/proxy"
	"github.com/superserve-ai/sandbox/internal/sentrylog"
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

	resolver := proxy.NewVMDResolver(vmdAddr)
	proxyHandler := proxy.NewHandler(domains, resolver, log)
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
	mux := newProxyMux(proxyHandler)

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

	// Shut down the redirect listener cleanly.
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()
	_ = redirectSrv.Shutdown(shutCtx)

	log.Info().Msg("proxy stopped")
}

type proxyHealthResponse struct {
	Capabilities []string `json:"capabilities"`
}

func newProxyMux(proxyHandler *proxy.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if proxyHandler.ServesHost(r.Host) {
			proxyHandler.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(proxyHealthResponse{
			Capabilities: []string{preview.HostCapabilityPorts},
		})
	})
	mux.Handle("/", proxyHandler)
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
