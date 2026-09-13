package provisioner

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/superserve-ai/sandbox/internal/qm/secrets"
	"github.com/superserve-ai/sandbox/internal/qm/tenantstore"
)

// Env is the deployment-wide configuration every step reads.
type Env struct {
	// Project is the GCP project tenant resources are created in.
	Project string
	// Region is the Cloud Run / Cloud SQL region.
	Region string
	// BaseDomain is the parent of every tenant hostname (qm.example.com →
	// <slug>.qm.example.com).
	BaseDomain string
	// Image is the QM container image tenants run.
	Image string
	// Stub makes the cloud-touching steps succeed without touching GCP,
	// recording placeholder resource names; for tests and local runs.
	Stub bool

	// Shared infrastructure each tenant is attached to. See qm.Config for
	// where these come from and why an empty one is fatal at startup
	// rather than at the step that needed it.
	SQLInstance         string
	SQLConnectionName   string
	SQLPrivateIP        string
	SQLAdminUser        string
	URLMap              string
	VPCNetwork          string
	VPCSubnetwork       string
	BucketLocation      string
	BucketLifecycleJSON string

	// Tenant runtime configuration. ResendSecret is platform-level: one
	// Secret Manager secret shared by every tenant, whose service account
	// is granted read access to it. AllowedEmailDomain is derived per
	// tenant from its admin address, not from here.
	ResendSecret     string
	EmailFrom        string
	SandboxAPIURL    string
	SandboxTemplate  string
	SandboxKeyRegion string
}

// Require reports the first of fields (name → value) that is empty, as an
// error naming it. Steps call it from Ready so a missing shared-
// infrastructure value stops the binary at startup rather than a tenant
// halfway through its plan.
func (e Env) Require(fields ...string) error {
	for i := 0; i+1 < len(fields); i += 2 {
		if strings.TrimSpace(fields[i+1]) == "" {
			return errors.New(fields[i] + " is required")
		}
	}
	return nil
}

// Tenant is the unit of work a step receives: the current row plus the
// environment, and the means to persist what the step produced.
type Tenant struct {
	Row tenantstore.Tenant
	Env Env

	store tenantstore.Store
}

// NewTenant binds a row to its store; the runner does this once per run.
func NewTenant(row tenantstore.Tenant, env Env, store tenantstore.Store) *Tenant {
	return &Tenant{Row: row, Env: env, store: store}
}

// Hostname is the tenant's DNS name under the base domain.
func (t *Tenant) Hostname() string {
	return t.Row.Slug + "." + t.Env.BaseDomain
}

// PublicURL is the origin the tenant's portal is served from.
func (t *Tenant) PublicURL() string {
	return "https://" + t.Hostname()
}

// SecretName is the Secret Manager name for one of the tenant's secrets.
func (t *Tenant) SecretName(name string) string {
	return secrets.TenantSecretName(t.Row.Slug, name)
}

// Record persists resource outputs via UpdateQMTenantResources and refreshes
// Row so later steps see them. Nil fields are left as they were.
func (t *Tenant) Record(ctx context.Context, r tenantstore.Resources) error {
	row, err := t.store.UpdateResources(ctx, t.Row.TeamID, t.Row.ID, r)
	if err != nil {
		return fmt.Errorf("record resources: %w", err)
	}
	t.Row = row
	return nil
}

// SetSecretRef records where one of the tenant's secrets lives.
func (t *Tenant) SetSecretRef(ctx context.Context, name, ref string) error {
	return t.store.SetSecretRef(ctx, t.Row.TeamID, t.Row.ID, name, ref)
}

// IssueSandboxKey mints the tenant's Superserve API key and points the row
// at it, returning the key's id.
func (t *Tenant) IssueSandboxKey(ctx context.Context, p tenantstore.SandboxKeyParams) (uuid.UUID, error) {
	return t.store.IssueSandboxKey(ctx, t.Row.TeamID, t.Row.ID, p)
}

// RevokeSandboxKey revokes the API key the tenant was issued, reporting
// whether it had one.
func (t *Tenant) RevokeSandboxKey(ctx context.Context) (bool, error) {
	return t.store.RevokeSandboxKey(ctx, t.Row.TeamID, t.Row.ID)
}

// SecretRefs lists the tenant's recorded secrets.
func (t *Tenant) SecretRefs(ctx context.Context) ([]tenantstore.SecretRef, error) {
	return t.store.ListSecretRefs(ctx, t.Row.TeamID, t.Row.ID)
}

// DeleteSecretRef forgets a secret that has been removed from Secret Manager.
func (t *Tenant) DeleteSecretRef(ctx context.Context, name string) error {
	return t.store.DeleteSecretRef(ctx, t.Row.TeamID, t.Row.ID, name)
}
