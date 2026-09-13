package steps

import (
	"context"

	"github.com/superserve-ai/sandbox/internal/qm/provisioner"
	"github.com/superserve-ai/sandbox/internal/qm/tenantstore"
)

// ServiceSpec is what the tenant's Cloud Run service is deployed from.
type ServiceSpec struct {
	Name           string
	Image          string
	ServiceAccount string
	// Env is plain configuration (PUBLIC_URL, ADMIN_GRANTS, SIGN_IN, …).
	Env map[string]string
	// SecretEnv maps an env var to the Secret Manager name whose latest
	// version Cloud Run mounts into it.
	SecretEnv map[string]string
}

// ServiceStatus is what the step records after a deploy.
type ServiceStatus struct {
	URI      string
	Revision string
	ImageTag string
}

// CloudRunAdmin deploys the tenant service (Cloud Run Admin API, run/v2
// projects.locations.services).
type CloudRunAdmin interface {
	Get(ctx context.Context, name string) (status ServiceStatus, exists bool, err error)
	// Deploy creates or updates the service and waits for the revision
	// to become ready.
	Deploy(ctx context.Context, spec ServiceSpec) (ServiceStatus, error)
	Delete(ctx context.Context, name string) error
}

// cloudRun deploys the tenant's service. Outputs: Row.CloudRunService,
// Row.ImageTag, Row.PublicUrl (the public hostname, not the run.app URI;
// the load balancer step routes it).
type cloudRun struct {
	stubOnly
	c Clients
}

func (cloudRun) Name() string { return "cloud_run" }

func (s cloudRun) Run(ctx context.Context, t *provisioner.Tenant) error {
	name := ServiceName(t.Row.Slug)
	if t.Env.Stub {
		if t.Row.CloudRunService != nil {
			return provisioner.Skip("service " + *t.Row.CloudRunService + " already recorded")
		}
		image, public := t.Env.Image, t.PublicURL()
		return t.Record(ctx, tenantstore.Resources{CloudRunService: &name, ImageTag: &image, PublicURL: &public})
	}
	return provisioner.NotImplemented(s.Name())
}

func (s cloudRun) Rollback(ctx context.Context, t *provisioner.Tenant) error {
	if t.Row.CloudRunService == nil {
		return provisioner.Skip("no service recorded")
	}
	if t.Env.Stub {
		return nil
	}
	return provisioner.NotImplemented(s.Name())
}
