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

	// Shared infrastructure the provisioner attaches each tenant to. These
	// mirror the QM Terraform module's contract one-for-one (it exports the
	// same QM_* names), so a value that differs here from what was applied
	// there points a tenant at something that does not exist. Empty is
	// tolerated only under QM_PROVISIONER_STUB, where no step calls GCP;
	// otherwise the plan's readiness check refuses the binary at startup.
	SQLInstance       string
	SQLConnectionName string
	SQLPrivateIP      string
	LBURLMap          string
	VPCNetwork        string
	VPCSubnetwork     string
	BucketLocation    string
	// BucketLifecycleJSON is the lifecycle policy applied to every tenant
	// bucket, in the Cloud Storage JSON API's shape. Empty applies none.
	BucketLifecycleJSON string

	// Tenant runtime configuration, rendered into each tenant's service.
	//
	// ResendSecret is the Secret Manager name of the *platform's* one
	// Resend API key: hosted QM has a single Resend account and a single
	// verified sending domain, so the key is shared and each tenant's
	// service account is granted read access to it. It is deliberately not
	// a generated per-tenant secret. Without it a tenant's embedded auth
	// broker fails closed on /idp/authorize and nobody can sign in, so the
	// provisioner treats it as required, not optional.
	ResendSecret string
	// EmailFrom is the sender magic links are sent from, at the verified
	// domain, optionally as "Name <sender@example.com>".
	EmailFrom string
	// SandboxAPIURL and SandboxTemplate configure the tenant's sandbox
	// backend: the Superserve API its QM creates sandboxes against, and the
	// template it launches them from.
	SandboxAPIURL   string
	SandboxTemplate string
	// SandboxKeyRegion tags the API keys the provisioner issues with this
	// cell's region (ss_live_<region>_<random>), as the control plane's own
	// keys are; an untagged key gets the generic 401 when it reaches the
	// wrong cell instead of the redirect hint.
	SandboxKeyRegion string
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
		ProvisionerRegion: os.Getenv("QM_PROVISIONER_REGION"),
		ProvisionerMode:   envOr("QM_PROVISIONER_MODE", ProvisionerModeCloudRun),
		ProvisionerStub:   isTruthy(os.Getenv("QM_PROVISIONER_STUB")),
		SecretsBackend:    envOr("QM_SECRETS_BACKEND", SecretsBackendGCP),
		TenantImage:       os.Getenv("QM_TENANT_IMAGE"),
		SentryDSN:         os.Getenv("SENTRY_DSN"),
		RunStaleAfter:     defaultRunStaleAfter,

		SQLInstance:         os.Getenv("QM_SQL_INSTANCE"),
		SQLConnectionName:   os.Getenv("QM_SQL_CONNECTION_NAME"),
		SQLPrivateIP:        os.Getenv("QM_SQL_PRIVATE_IP"),
		LBURLMap:            os.Getenv("QM_LB_URL_MAP"),
		VPCNetwork:          os.Getenv("QM_VPC_NETWORK"),
		VPCSubnetwork:       os.Getenv("QM_VPC_SUBNETWORK"),
		BucketLocation:      os.Getenv("QM_TENANT_BUCKET_LOCATION"),
		BucketLifecycleJSON: os.Getenv("QM_TENANT_BUCKET_LIFECYCLE_JSON"),

		ResendSecret:     os.Getenv("QM_RESEND_SECRET"),
		EmailFrom:        os.Getenv("QM_EMAIL_FROM"),
		SandboxAPIURL:    strings.TrimSuffix(os.Getenv("QM_SANDBOX_API_URL"), "/"),
		SandboxTemplate:  os.Getenv("QM_SANDBOX_TEMPLATE"),
		SandboxKeyRegion: envOr("QM_SANDBOX_KEY_REGION", os.Getenv("SANDBOX_ID_REGION")),
	}
	// Buckets default to the provisioner's own region rather than failing:
	// the Terraform module's tenant_bucket_location does the same.
	if cfg.BucketLocation == "" {
		cfg.BucketLocation = cfg.ProvisionerRegion
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
	// No default: the job is resolved by project, region and name, and a
	// region guessed here that differs from where the job was deployed
	// fails every trigger. The deploy sets it from the region it targets.
	if cfg.ProvisionerMode == ProvisionerModeCloudRun && cfg.ProvisionerRegion == "" {
		return cfg, fmt.Errorf("QM_PROVISIONER_REGION is required when QM_PROVISIONER_MODE=%s", ProvisionerModeCloudRun)
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
