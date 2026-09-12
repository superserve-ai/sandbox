package provisioner

import (
	"context"
	"fmt"

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

// SecretRefs lists the tenant's recorded secrets.
func (t *Tenant) SecretRefs(ctx context.Context) ([]tenantstore.SecretRef, error) {
	return t.store.ListSecretRefs(ctx, t.Row.TeamID, t.Row.ID)
}

// DeleteSecretRef forgets a secret that has been removed from Secret Manager.
func (t *Tenant) DeleteSecretRef(ctx context.Context, name string) error {
	return t.store.DeleteSecretRef(ctx, t.Row.TeamID, t.Row.ID, name)
}
