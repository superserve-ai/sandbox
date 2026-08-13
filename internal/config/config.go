package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/auth"
)

// Config holds all configuration for the Superserve Sandbox control plane.
type Config struct {
	Port        string // API_PORT, default "8080"
	VMDAddress  string // VMD_GRPC_ADDRESS, default "localhost:50051"
	DatabaseURL string // DATABASE_URL, required

	StripeSecretKey        string   // STRIPE_SECRET_KEY
	StripeWebhookSecret    string   // STRIPE_WEBHOOK_SECRET
	StripeAPIBaseURL       string   // STRIPE_API_BASE_URL, default "https://api.stripe.com"
	StripeAPIVersion       string   // STRIPE_API_VERSION, required for Stripe requests
	StripeCheckoutPriceIDs []string // STRIPE_CHECKOUT_PRICE_IDS, required for checkout sessions
	BillingResources       []BillingResourceConfig
	AppAllowedOrigins      []string // APP_ALLOWED_ORIGINS, comma-separated browser origins allowed in billing redirects

	// SandboxAccessTokenSeed is the HMAC seed shared with the edge
	// proxy. Both sides derive per-sandbox access tokens as
	// HMAC-SHA256(seed, sandboxID). Loaded from SANDBOX_ACCESS_TOKEN_SEED
	// (hex-encoded, >= 32 bytes).
	SandboxAccessTokenSeed []byte

	// EdgeProxyDomain is the public hostname suffix served by the edge
	// proxy, used to construct URLs in sandbox responses.
	EdgeProxyDomain string

	// DefaultHostID is the fallback host identifier used when no scheduler
	// is configured. Set via DEFAULT_HOST_ID; defaults to "default".
	DefaultHostID string

	// SystemTeamID owns curated templates that are visible to every team
	// (python-3.11, node-22, etc.). Set via SYSTEM_TEAM_ID; empty means
	// "no system team configured" and users see only their own templates.
	// Must be a valid UUID matching an existing team row.
	SystemTeamID string

	// SentryDSN is the Sentry data source name for error reporting.
	// Loaded from SENTRY_DSN; empty disables Sentry.
	SentryDSN string

	// KMSKeyResource is the Cloud KMS key resource name used to wrap per-row DEKs.
	// Empty disables the /secrets endpoints.
	KMSKeyResource string

	// SecretsSigningKey is the base64-encoded Ed25519 private seed used to
	// sign per-sandbox JWTs. Empty disables JWT minting.
	SecretsSigningKey string

	// SecretsSigningKeyID is the kid stamped on minted JWTs and served by
	// the JWKS endpoint. Defaults to "v1".
	SecretsSigningKeyID string

	// OTelMetricsEnabled gates app-level operational metrics export. Defaults
	// false so local/test behavior remains unchanged unless explicitly enabled.
	OTelMetricsEnabled bool
	OTelServiceName    string
	OTelServiceVersion string
	OTelEnvironment    string
	OTelEndpoint       string
	OTelInsecure       bool
	OTelExportInterval time.Duration
}

// Load reads configuration from environment variables.
func Load() (*Config, error) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}

	seed, err := loadSeed(
		os.Getenv("SANDBOX_ACCESS_TOKEN_SEED"),
		os.Getenv("ALLOW_EPHEMERAL_SEED") == "1",
	)
	if err != nil {
		return nil, fmt.Errorf("SANDBOX_ACCESS_TOKEN_SEED: %w", err)
	}

	exportInterval, err := durationEnv("OTEL_EXPORT_INTERVAL", 15*time.Second)
	if err != nil {
		return nil, err
	}
	checkoutPriceIDs := checkoutPriceIDs()

	cfg := &Config{
		Port:                   envOrDefault("API_PORT", "8080"),
		VMDAddress:             envOrDefault("VMD_GRPC_ADDRESS", "localhost:50051"),
		DatabaseURL:            dbURL,
		StripeSecretKey:        os.Getenv("STRIPE_SECRET_KEY"),
		StripeWebhookSecret:    os.Getenv("STRIPE_WEBHOOK_SECRET"),
		StripeAPIBaseURL:       envOrDefault("STRIPE_API_BASE_URL", "https://api.stripe.com"),
		StripeAPIVersion:       strings.TrimSpace(os.Getenv("STRIPE_API_VERSION")),
		StripeCheckoutPriceIDs: checkoutPriceIDs,
		BillingResources:       billingResources(checkoutPriceIDs),
		AppAllowedOrigins:      splitCSV(os.Getenv("APP_ALLOWED_ORIGINS")),
		SandboxAccessTokenSeed: seed,
		EdgeProxyDomain:        envOrDefault("EDGE_PROXY_DOMAIN", "sandbox.superserve.ai"),
		DefaultHostID:          envOrDefault("DEFAULT_HOST_ID", "default"),
		SystemTeamID:           os.Getenv("SYSTEM_TEAM_ID"),
		SentryDSN:              os.Getenv("SENTRY_DSN"),
		KMSKeyResource:         os.Getenv("KMS_KEY_RESOURCE"),
		SecretsSigningKey:      os.Getenv("SECRETS_SIGNING_KEY"),
		SecretsSigningKeyID:    envOrDefault("SECRETS_SIGNING_KEY_ID", "v1"),
		OTelMetricsEnabled:     boolEnv("OTEL_METRICS_ENABLED", false),
		OTelServiceName:        envOrDefault("OTEL_SERVICE_NAME", "sandbox-controlplane"),
		OTelServiceVersion:     os.Getenv("OTEL_SERVICE_VERSION"),
		OTelEnvironment:        envOrDefault("OTEL_ENVIRONMENT", "dev"),
		OTelEndpoint:           envOrDefault("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318"),
		OTelInsecure:           boolEnv("OTEL_EXPORTER_OTLP_INSECURE", false),
		OTelExportInterval:     exportInterval,
	}
	return cfg, nil
}

func checkoutPriceIDs() []string {
	ids := splitCSV(os.Getenv("STRIPE_CHECKOUT_PRICE_IDS"))
	if len(ids) == 0 {
		ids = splitCSV(os.Getenv("STRIPE_CHECKOUT_PRICE_ID"))
	}
	return ids
}

// BillingResourceConfig describes one metered resource in the billing model.
// The default configuration is loaded from the existing Stripe checkout price
// environment variables, but a JSON resource list can override it when needed.
type BillingResourceConfig struct {
	ResourceKey     string `json:"resource_key"`
	DisplayName     string `json:"display_name"`
	SortOrder       int    `json:"sort_order"`
	UsageUnit       string `json:"usage_unit"`
	DisplayUnit     string `json:"display_unit"`
	StripeEventName string `json:"stripe_event_name"`
	StripePriceID   string `json:"stripe_price_id"`
	Tracked         bool   `json:"tracked"`
	Billable        bool   `json:"billable"`
	CheckoutEnabled bool   `json:"checkout_enabled"`
}

func billingResources(checkoutPriceIDs []string) []BillingResourceConfig {
	if raw := strings.TrimSpace(os.Getenv("BILLING_RESOURCE_CONFIG")); raw != "" {
		var resources []BillingResourceConfig
		if err := json.Unmarshal([]byte(raw), &resources); err == nil && len(resources) > 0 {
			normalizeBillingResources(resources)
			return resources
		}
	}

	resources := []BillingResourceConfig{
		{
			ResourceKey:     "vcpu",
			UsageUnit:       "second",
			StripeEventName: "cpu_vcpu_hours",
			Tracked:         true,
			Billable:        true,
			CheckoutEnabled: true,
		},
		{
			ResourceKey:     "memory_gib",
			UsageUnit:       "second",
			StripeEventName: "memory_gib_hours",
			Tracked:         true,
			Billable:        true,
			CheckoutEnabled: true,
		},
		{
			ResourceKey:     "storage_gib",
			UsageUnit:       "second",
			StripeEventName: "storage_gib_hours",
			Tracked:         true,
			Billable:        false,
			CheckoutEnabled: true,
		},
	}
	for i := range resources {
		if i < len(checkoutPriceIDs) {
			resources[i].StripePriceID = checkoutPriceIDs[i]
		}
	}
	normalizeBillingResources(resources)
	return resources
}

func normalizeBillingResources(resources []BillingResourceConfig) {
	for i := range resources {
		if resources[i].UsageUnit == "" {
			resources[i].UsageUnit = "second"
		}
		if resources[i].DisplayUnit == "" {
			resources[i].DisplayUnit = defaultBillingResourceDisplayUnit(resources[i].ResourceKey)
		}
		if resources[i].DisplayName == "" {
			resources[i].DisplayName = defaultBillingResourceDisplayName(resources[i].ResourceKey)
		}
		if resources[i].SortOrder == 0 {
			resources[i].SortOrder = (i + 1) * 10
		}
	}
}

func defaultBillingResourceDisplayName(resourceKey string) string {
	switch resourceKey {
	case "vcpu":
		return "CPU"
	case "memory_gib":
		return "Memory"
	case "storage_gib":
		return "Storage"
	default:
		return resourceKey
	}
}

func defaultBillingResourceDisplayUnit(resourceKey string) string {
	switch resourceKey {
	case "vcpu":
		return "vCPU-hours"
	case "memory_gib":
		return "GiB-hours"
	case "storage_gib":
		return "GiB-hours"
	default:
		return resourceKey
	}
}

func splitCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if v := strings.TrimSpace(part); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func loadSeed(envValue string, allowEphemeral bool) ([]byte, error) {
	if envValue == "" {
		if !allowEphemeral {
			return nil, fmt.Errorf("required in production; set ALLOW_EPHEMERAL_SEED=1 for local dev")
		}
		seed := make([]byte, 32)
		if _, err := rand.Read(seed); err != nil {
			return nil, fmt.Errorf("generate ephemeral seed: %w", err)
		}
		log.Warn().Msg("SANDBOX_ACCESS_TOKEN_SEED unset — generated ephemeral seed (DO NOT USE IN PRODUCTION)")
		return seed, nil
	}

	seed, err := hex.DecodeString(envValue)
	if err != nil {
		return nil, fmt.Errorf("not valid hex: %w", err)
	}
	if err := auth.ValidateSeed(seed); err != nil {
		return nil, err
	}
	return seed, nil
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func boolEnv(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(v)
	if err != nil {
		log.Warn().Err(err).Str("key", key).Str("value", v).Bool("fallback", fallback).Msg("invalid boolean env var")
		return fallback
	}
	return parsed
}

func durationEnv(key string, fallback time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return parsed, nil
}
