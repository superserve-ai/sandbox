package config

import (
	"testing"
	"time"
)

func TestLoadOTelEnvVars(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://example.invalid/sandbox")
	t.Setenv("SANDBOX_ACCESS_TOKEN_SEED", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	t.Setenv("OTEL_METRICS_ENABLED", "true")
	t.Setenv("OTEL_SERVICE_NAME", "sandbox-controlplane")
	t.Setenv("OTEL_ENVIRONMENT", "production")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://10.0.0.3:4318")
	t.Setenv("OTEL_EXPORT_INTERVAL", "15s")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if !cfg.OTelMetricsEnabled {
		t.Fatal("OTelMetricsEnabled = false, want true")
	}
	if got, want := cfg.OTelServiceName, "sandbox-controlplane"; got != want {
		t.Fatalf("OTelServiceName = %q, want %q", got, want)
	}
	if got, want := cfg.OTelEnvironment, "production"; got != want {
		t.Fatalf("OTelEnvironment = %q, want %q", got, want)
	}
	if got, want := cfg.OTelEndpoint, "http://10.0.0.3:4318"; got != want {
		t.Fatalf("OTelEndpoint = %q, want %q", got, want)
	}
	if got, want := cfg.OTelExportInterval, 15*time.Second; got != want {
		t.Fatalf("OTelExportInterval = %s, want %s", got, want)
	}
}
