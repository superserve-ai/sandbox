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
