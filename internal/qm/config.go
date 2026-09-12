// Package qm is the hosted-QM control service: the /v1/qm API the console
// proxies to, and the wiring that turns tenant requests into provisioner
// runs. It is a separate binary from the control plane (cmd/qm-api) and
// reaches Postgres only as the qm_api role.
package qm

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// Provisioner trigger modes, from QM_PROVISIONER_MODE.
const (
	ProvisionerModeCloudRun  = "cloudrun"
	ProvisionerModeInProcess = "inprocess"
)

// Secret Manager backends, from QM_SECRETS_BACKEND.
const (
	SecretsBackendGCP    = "gcp"
	SecretsBackendMemory = "memory"
)

// Config is the service's environment.
type Config struct {
	// DatabaseURL connects as the qm_api role.
	DatabaseURL string
	Port        string
	GCPProject  string
	// BaseDomain is the parent of tenant hostnames, e.g. qm.example.com.
	BaseDomain string
	// ProvisionerJob is the Cloud Run Job (short name) that runs plans.
	ProvisionerJob    string
	ProvisionerRegion string
	// ProvisionerMode is cloudrun (default) or inprocess.
	ProvisionerMode string
	// ProvisionerStub makes cloud-touching steps succeed without GCP.
	ProvisionerStub bool
	// SecretsBackend is gcp (default) or memory; memory is only for local
	// runs where nothing must persist.
	SecretsBackend string
	TenantImage    string
	SentryDSN      string
	// RunStaleAfter is how long an in-flight tenant may go without a new
	// event before the API treats its run as lost and lets it be retried
	// or deleted.
	RunStaleAfter time.Duration
}

const defaultRunStaleAfter = 30 * time.Minute

// LoadConfig reads the environment. Required: DATABASE_URL, QM_BASE_DOMAIN,
// and GCP_PROJECT unless every GCP-backed component is switched to its
// local implementation.
func LoadConfig() (Config, error) {
	cfg := Config{
		DatabaseURL:       os.Getenv("DATABASE_URL"),
		Port:              envOr("PORT", "8080"),
		GCPProject:        os.Getenv("GCP_PROJECT"),
		BaseDomain:        strings.TrimSuffix(strings.ToLower(os.Getenv("QM_BASE_DOMAIN")), "."),
		ProvisionerJob:    envOr("QM_PROVISIONER_JOB", "qm-provisioner"),
		ProvisionerRegion: envOr("QM_PROVISIONER_REGION", "us-central1"),
		ProvisionerMode:   envOr("QM_PROVISIONER_MODE", ProvisionerModeCloudRun),
		ProvisionerStub:   isTruthy(os.Getenv("QM_PROVISIONER_STUB")),
		SecretsBackend:    envOr("QM_SECRETS_BACKEND", SecretsBackendGCP),
		TenantImage:       os.Getenv("QM_TENANT_IMAGE"),
		SentryDSN:         os.Getenv("SENTRY_DSN"),
		RunStaleAfter:     defaultRunStaleAfter,
	}
	if raw := os.Getenv("QM_RUN_STALE_AFTER"); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil || d <= 0 {
			return cfg, fmt.Errorf("QM_RUN_STALE_AFTER must be a positive duration")
		}
		cfg.RunStaleAfter = d
	}
	if cfg.DatabaseURL == "" {
		return cfg, fmt.Errorf("DATABASE_URL is required")
	}
	if cfg.BaseDomain == "" {
		return cfg, fmt.Errorf("QM_BASE_DOMAIN is required")
	}
	switch cfg.ProvisionerMode {
	case ProvisionerModeCloudRun, ProvisionerModeInProcess:
	default:
		return cfg, fmt.Errorf("QM_PROVISIONER_MODE must be %s or %s", ProvisionerModeCloudRun, ProvisionerModeInProcess)
	}
	switch cfg.SecretsBackend {
	case SecretsBackendGCP, SecretsBackendMemory:
	default:
		return cfg, fmt.Errorf("QM_SECRETS_BACKEND must be %s or %s", SecretsBackendGCP, SecretsBackendMemory)
	}
	// The Cloud Run Job is another process: secrets written to this one's
	// memory would never reach it, so that pairing is refused outright.
	if cfg.ProvisionerMode == ProvisionerModeCloudRun && cfg.SecretsBackend == SecretsBackendMemory {
		return cfg, fmt.Errorf("QM_SECRETS_BACKEND=memory requires QM_PROVISIONER_MODE=inprocess")
	}
	needsGCP := cfg.ProvisionerMode == ProvisionerModeCloudRun || cfg.SecretsBackend == SecretsBackendGCP
	if needsGCP && cfg.GCPProject == "" {
		return cfg, fmt.Errorf("GCP_PROJECT is required unless QM_PROVISIONER_MODE=inprocess and QM_SECRETS_BACKEND=memory")
	}
	return cfg, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func isTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
