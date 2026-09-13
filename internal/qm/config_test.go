package qm

import (
	"strings"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://qm_api:x@localhost/db")
	t.Setenv("QM_BASE_DOMAIN", "QM.Example.com.")
	t.Setenv("GCP_PROJECT", "")
	t.Setenv("QM_PROVISIONER_MODE", "")
	t.Setenv("QM_SECRETS_BACKEND", "")
	t.Setenv("QM_PROVISIONER_STUB", "")

	if _, err := LoadConfig(); err == nil || !strings.Contains(err.Error(), "GCP_PROJECT") {
		t.Errorf("cloud run mode without a project: err = %v", err)
	}

	t.Setenv("QM_PROVISIONER_MODE", "inprocess")
	t.Setenv("QM_SECRETS_BACKEND", "memory")
	t.Setenv("QM_PROVISIONER_STUB", "1")
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BaseDomain != "qm.example.com" || cfg.Port != "8080" || !cfg.ProvisionerStub {
		t.Errorf("cfg = %+v", cfg)
	}

	t.Setenv("QM_PROVISIONER_MODE", "cloudrun")
	t.Setenv("GCP_PROJECT", "example-project")
	if _, err := LoadConfig(); err == nil || !strings.Contains(err.Error(), "inprocess") {
		t.Errorf("memory secrets with the cloud run job: err = %v", err)
	}
	// The job is addressed by region, so triggering one is refused until
	// the deploy says which region it was placed in.
	t.Setenv("QM_SECRETS_BACKEND", "gcp")
	if _, err := LoadConfig(); err == nil || !strings.Contains(err.Error(), "QM_PROVISIONER_REGION") {
		t.Errorf("cloud run job without a region: err = %v", err)
	}
	t.Setenv("QM_PROVISIONER_REGION", "us-east4")
	if cfg, err := LoadConfig(); err != nil || cfg.ProvisionerRegion != "us-east4" {
		t.Errorf("cfg = %+v err = %v", cfg, err)
	}
	t.Setenv("QM_SECRETS_BACKEND", "memory")
	t.Setenv("QM_PROVISIONER_REGION", "")
	t.Setenv("QM_PROVISIONER_MODE", "sometimes")
	if _, err := LoadConfig(); err == nil {
		t.Error("bad provisioner mode accepted")
	}
	t.Setenv("QM_PROVISIONER_MODE", "inprocess")
	t.Setenv("QM_BASE_DOMAIN", "")
	if _, err := LoadConfig(); err == nil {
		t.Error("missing base domain accepted")
	}
}

// The shared-infrastructure values come straight from the Terraform
// module's QM_* contract; LoadConfig only reads them (the plan's readiness
// check is what refuses an incomplete set), so the test is that each name
// lands in the field the steps read.
func TestLoadConfigSharedInfrastructure(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://qm_api:x@localhost/db")
	t.Setenv("QM_BASE_DOMAIN", "qm.example.com")
	t.Setenv("QM_PROVISIONER_MODE", "inprocess")
	t.Setenv("QM_SECRETS_BACKEND", "memory")
	t.Setenv("QM_PROVISIONER_REGION", "us-central1")
	t.Setenv("QM_SQL_INSTANCE", "qm-tenants-staging")
	t.Setenv("QM_SQL_CONNECTION_NAME", "example-project:us-central1:qm-tenants-staging")
	t.Setenv("QM_SQL_PRIVATE_IP", "10.0.0.3")
	t.Setenv("QM_LB_URL_MAP", "qm-https-staging")
	t.Setenv("QM_VPC_NETWORK", "example-network")
	t.Setenv("QM_VPC_SUBNETWORK", "example-subnet")
	t.Setenv("QM_TENANT_BUCKET_LIFECYCLE_JSON", ` {"rule":[]} `)
	t.Setenv("QM_RESEND_SECRET", "qm-resend-api-key")
	t.Setenv("QM_EMAIL_FROM", "QM <no-reply@mail.qm.example.com>")
	t.Setenv("QM_SANDBOX_API_URL", "https://api.example.com/")
	t.Setenv("QM_SANDBOX_TEMPLATE", "qm-agent-0.1.0")
	t.Setenv("QM_SANDBOX_KEY_REGION", "")
	t.Setenv("SANDBOX_ID_REGION", "use")
	t.Setenv("QM_TENANT_BUCKET_LOCATION", "")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string][2]string{
		"QM_SQL_INSTANCE":        {cfg.SQLInstance, "qm-tenants-staging"},
		"QM_SQL_CONNECTION_NAME": {cfg.SQLConnectionName, "example-project:us-central1:qm-tenants-staging"},
		"QM_SQL_PRIVATE_IP":      {cfg.SQLPrivateIP, "10.0.0.3"},
		"QM_LB_URL_MAP":          {cfg.LBURLMap, "qm-https-staging"},
		"QM_VPC_NETWORK":         {cfg.VPCNetwork, "example-network"},
		"QM_VPC_SUBNETWORK":      {cfg.VPCSubnetwork, "example-subnet"},
		"QM_RESEND_SECRET":       {cfg.ResendSecret, "qm-resend-api-key"},
		"QM_EMAIL_FROM":          {cfg.EmailFrom, "QM <no-reply@mail.qm.example.com>"},
		"QM_SANDBOX_TEMPLATE":    {cfg.SandboxTemplate, "qm-agent-0.1.0"},
	} {
		if got[0] != got[1] {
			t.Errorf("%s = %q, want %q", name, got[0], got[1])
		}
	}
	// The sandbox API URL is a base the steps concatenate onto, so the
	// trailing slash comes off once here rather than at every use.
	if cfg.SandboxAPIURL != "https://api.example.com" {
		t.Errorf("sandbox api url = %q", cfg.SandboxAPIURL)
	}
	// Normalized once, here: the readiness check and the bucket client must
	// not disagree about whether a value is a policy at all.
	if cfg.BucketLifecycleJSON != `{"rule":[]}` {
		t.Errorf("bucket lifecycle = %q", cfg.BucketLifecycleJSON)
	}
	t.Setenv("QM_TENANT_BUCKET_LIFECYCLE_JSON", "   ")
	if trimmed, err := LoadConfig(); err != nil || trimmed.BucketLifecycleJSON != "" {
		t.Errorf("whitespace-only lifecycle = %q err = %v", trimmed.BucketLifecycleJSON, err)
	}
	t.Setenv("QM_TENANT_BUCKET_LIFECYCLE_JSON", `{"rule":[]}`)

	// An unset bucket location follows the provisioner's region, as the
	// Terraform default does.
	if cfg.BucketLocation != "us-central1" {
		t.Errorf("bucket location = %q", cfg.BucketLocation)
	}
	// The cell's own region tags issued keys when no explicit override is
	// set, so a key the provisioner mints routes like any other.
	if cfg.SandboxKeyRegion != "use" {
		t.Errorf("sandbox key region = %q", cfg.SandboxKeyRegion)
	}

	// The region rides in the key as plaintext and the control plane reads
	// anything malformed as "no region", silently losing the
	// wrong-endpoint diagnostic the tag exists for. So it is refused here.
	for _, bad := range []string{"us-east-1", "USE", "a-very-long-region-token"} {
		t.Setenv("QM_SANDBOX_KEY_REGION", bad)
		if _, err := LoadConfig(); err == nil || !strings.Contains(err.Error(), "QM_SANDBOX_KEY_REGION") {
			t.Errorf("region %q: err = %v", bad, err)
		}
	}
	// Whitespace is trimmed rather than refused.
	t.Setenv("QM_SANDBOX_KEY_REGION", "  usw  ")
	if trimmed, err := LoadConfig(); err != nil || trimmed.SandboxKeyRegion != "usw" {
		t.Errorf("padded region = %q err = %v", trimmed.SandboxKeyRegion, err)
	}
}
