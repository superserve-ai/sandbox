package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"strings"
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

	resolver := proxy.NewVMDResolver(vmdAddr)
	proxyHandler := proxy.NewHandler(domain, resolver, log)
	proxyHandler.StartSweeper(ctx)

	// Data-plane auth — the Ed25519 verifier and the single shared nonce
	// cache are used by every token-gated endpoint on the edge (terminal
	// bridge, /files reverse proxy, and any future scoped capability).
	// Both features share the same Verifier and NonceCache; installing
	// them through WithTerminal and WithFiles below is idempotent as
	// long as the same instances are reused.
	//
	// REQUIRE_TERMINAL=1 makes missing configuration a hard-fail at boot
	// rather than a warn-and-continue. Prod should always set this so a
	// misconfigured deploy breaks the health check instead of silently
	// shipping a proxy with the data-plane endpoints disabled — users
	// would only notice when they hit an opaque 404 on upload or
	// "open terminal".
	verifier, verr := proxy.LoadTerminalVerifierFromEnv()
	originsEnv := os.Getenv("TERMINAL_ALLOWED_ORIGINS")
	required := os.Getenv("REQUIRE_TERMINAL") == "1"

	switch {
	case verr != nil:
		if required {
			log.Fatal().
				Err(verr).
				Msg("REQUIRE_TERMINAL=1 but TERMINAL_TOKEN_PUBLIC_KEY missing/invalid")
		}
		log.Warn().
			Err(verr).
			Msg("data-plane endpoints disabled (TERMINAL_TOKEN_PUBLIC_KEY not configured)")
	case originsEnv == "":
		if required {
			log.Fatal().
				Msg("REQUIRE_TERMINAL=1 but TERMINAL_ALLOWED_ORIGINS missing")
		}
		log.Warn().
			Msg("data-plane endpoints disabled (TERMINAL_ALLOWED_ORIGINS not configured)")
	default:
		origins := splitCSV(originsEnv)
		nonces := proxy.DefaultNonceCache()
		proxyHandler.
			WithTerminal(verifier, nonces, origins).
			WithFiles(verifier, nonces)
		log.Info().
			Strs("allowed_origins", origins).
			Msg("data-plane endpoints enabled (terminal, files)")
	}

	// Wrap with a health check endpoint for the GCP LB health probe.
	// The LB hits /health directly on the instance IP (not a sandbox
	// URL), so the proxy handler would reject it — intercept it first.
	//
	// Important: we only answer 200 when the request is NOT addressed
	// at a sandbox host. If a caller sends /health with a sandbox
	// Host header (e.g. `boxd-<id>.sandbox.superserve.ai/health`), we
	// fall through to the proxy handler so the boxd-label lockdown
	// can 404 it normally. Otherwise the global /health handler would
	// punch a hole in the documented "every non-allowlisted path
	// under boxd- returns 404" promise.
	domainSuffix := "." + domain
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if i := strings.IndexByte(host, ':'); i >= 0 {
			host = host[:i]
		}
		if strings.HasSuffix(host, domainSuffix) {
			// Sandbox-addressed /health — defer to the proxy
			// handler so the boxd-label lockdown applies.
			proxyHandler.ServeHTTP(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.Handle("/", proxyHandler)

	// HTTP→HTTPS redirect listener. The SSL Proxy LB on port 443 terminates
	// TLS and forwards plain HTTP to the main listener. A separate L4
	// forwarding rule on port 80 lands here, on a dedicated port, with a
	// single 301 handler. Doing it on a separate port (rather than
	// path-routing within the main listener) means main-listener traffic
	// is unambiguously "TLS-terminated and trusted" while redirect-listener
	// traffic is unambiguously "plain HTTP from a public client" — no
	// confusion about which path the request came from.
	redirectMux := http.NewServeMux()
	redirectMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Strip any TCP port from Host (rare on port 80 but be safe).
		host := r.Host
		if i := strings.IndexByte(host, ':'); i >= 0 {
			host = host[:i]
		}
		http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusMovedPermanently)
	})
	go func() {
		log.Info().Str("addr", redirectAddr).Msg("starting HTTP→HTTPS redirect listener")
		srv := &http.Server{
			Addr:    redirectAddr,
			Handler: redirectMux,
		}
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error().Err(err).Msg("redirect listener error")
		}
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

// splitCSV trims and returns non-empty entries from a comma-separated
// string. Used for TERMINAL_ALLOWED_ORIGINS where whitespace around
// commas should not cause silent misconfiguration.
func splitCSV(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if t := strings.TrimSpace(s); t != "" {
			out = append(out, t)
		}
	}
	return out
}
