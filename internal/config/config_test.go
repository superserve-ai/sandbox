package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoadOTelEnvVars(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://example.invalid/sandbox")
	t.Setenv("SANDBOX_ACCESS_TOKEN_SEED", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	t.Setenv("TEMPLATE_BUILD_REGION", "example-region")
	t.Setenv("BACKUP_BUCKET", "example-bucket")
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

func TestLoadRequiresTemplateBuildStorageConfig(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://example.invalid/sandbox")
	t.Setenv("SANDBOX_ACCESS_TOKEN_SEED", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	for _, tc := range []struct {
		name   string
		region string
		bucket string
		want   string
	}{
		{name: "missing region", bucket: "example-bucket", want: "TEMPLATE_BUILD_REGION"},
		{name: "blank region", region: "  ", bucket: "example-bucket", want: "TEMPLATE_BUILD_REGION"},
		{name: "missing bucket", region: "example-region", want: "BACKUP_BUCKET"},
		{name: "blank bucket", region: "example-region", bucket: "  ", want: "BACKUP_BUCKET"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TEMPLATE_BUILD_REGION", tc.region)
			t.Setenv("BACKUP_BUCKET", tc.bucket)
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Load() error = %v, want %s", err, tc.want)
			}
		})
	}
}

func TestLoadEmailTransport(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://example.invalid/sandbox")
	t.Setenv("SANDBOX_ACCESS_TOKEN_SEED", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	t.Setenv("TEMPLATE_BUILD_REGION", "example-region")
	t.Setenv("BACKUP_BUCKET", "example-bucket")
	for _, tc := range []struct {
		name, transport, host, port string
		want                        string
		wantErr                     bool
	}{
		{name: "default is resend"},
		{name: "explicit resend ignores smtp settings", transport: "resend", host: "127.0.0.1", port: "1025"},
		{name: "smtp", transport: "smtp", host: "127.0.0.1", port: "1025", want: "127.0.0.1:1025"},
		{name: "smtp ipv6", transport: "smtp", host: "::1", port: "25", want: "[::1]:25"},
		{name: "smtp without host", transport: "smtp", port: "1025", wantErr: true},
		{name: "smtp without port", transport: "smtp", host: "127.0.0.1", wantErr: true},
		{name: "smtp with invalid port", transport: "smtp", host: "127.0.0.1", port: "70000", wantErr: true},
		{name: "unknown transport", transport: "sendmail", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("EMAIL_TRANSPORT", tc.transport)
			t.Setenv("SMTP_HOST", tc.host)
			t.Setenv("SMTP_PORT", tc.port)
			cfg, err := Load()
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "EMAIL_TRANSPORT") {
					t.Fatalf("Load() error = %v, want EMAIL_TRANSPORT error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if cfg.SMTPAddr != tc.want {
				t.Fatalf("SMTPAddr = %q, want %q", cfg.SMTPAddr, tc.want)
			}
		})
	}
}

func TestPlanPriceIDs(t *testing.T) {
	ids, err := planPriceIDs(" starter_monthly = price_a ,starter_annual=price_b")
	if err != nil || len(ids) != 2 || ids["starter_monthly"] != "price_a" || ids["starter_annual"] != "price_b" {
		t.Fatalf("ids=%v err=%v", ids, err)
	}
	for _, raw := range []string{"starter_monthly", "starter_monthly=", "=price_a", "starter_monthly=price_a,starter_monthly=price_b"} {
		if _, err := planPriceIDs(raw); err == nil {
			t.Errorf("%q: expected error", raw)
		}
	}
	c := Config{StripeProAnnualPriceID: "price_pro", StripePlanPriceIDs: map[string]string{"starter_monthly": "price_a"}}
	if c.PlanPriceID("pro_annual") != "price_pro" || c.PlanPriceID("starter_monthly") != "price_a" || c.PlanPriceID("starter_annual") != "" {
		t.Fatal("unexpected plan price lookup")
	}
	c.StripePlanPriceIDs["pro_annual"] = "price_pro_repriced"
	if c.PlanPriceID("pro_annual") != "price_pro_repriced" || c.StripeProAnnualPriceID != "price_pro" {
		t.Fatal("a catalog Pro price must override checkout only")
	}
}
