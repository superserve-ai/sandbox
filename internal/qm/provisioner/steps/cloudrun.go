package steps

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/superserve-ai/sandbox/internal/qm/provisioner"
	"github.com/superserve-ai/sandbox/internal/qm/tenantstore"
)

// ServiceSpec is what the tenant's Cloud Run service is deployed from. The
// shape of the runtime — one container, CPU always allocated, min and max
// instances both one — is fixed for every tenant and lives in the client,
// not here: it is an architecture decision, not a per-tenant knob.
type ServiceSpec struct {
	Name           string
	Image          string
	ServiceAccount string
	// Env is plain configuration (PUBLIC_WEB_URL, ADMIN_GRANTS, …).
	Env map[string]string
	// SecretEnv maps an env var to the Secret Manager name whose latest
	// version Cloud Run mounts into it.
	SecretEnv map[string]string
	// Network and Subnetwork put the service on the VPC, which is the only
	// route to the shared Cloud SQL instance's private IP.
	Network    string
	Subnetwork string
	// Labels tag the service with the tenant it belongs to.
	Labels map[string]string
}

// ServiceStatus is what the step records after a deploy.
type ServiceStatus struct {
	URI      string
	Revision string
	ImageTag string
}

// CloudRunAdmin deploys the tenant service (Cloud Run Admin API, run/v2
// projects.locations.services).
//
// Deploy must be idempotent: it creates the service or updates it in place,
// and returns once the new revision is serving. Delete on a service that
// does not exist is a no-op.
type CloudRunAdmin interface {
	Get(ctx context.Context, name string) (status ServiceStatus, exists bool, err error)
	// Deploy creates or updates the service and waits for the revision
	// to become ready.
	Deploy(ctx context.Context, spec ServiceSpec) (ServiceStatus, error)
	Delete(ctx context.Context, name string) error
}

var errNoCloudRunAdmin = errors.New("no cloud run client configured")

// cloudRun deploys the tenant's service. Outputs: Row.CloudRunService,
// Row.ImageTag, Row.PublicUrl (the public hostname, not the run.app URI;
// the load balancer step routes it).
//
// It also grants the tenant's identity read access to exactly the secrets
// the service mounts. That grant lives here rather than in the
// service_account step because the mounted set is only known at deploy
// time, and a secret added to the spec without a matching grant is a
// container that crashes on boot.
type cloudRun struct {
	c Clients
}

func (cloudRun) Name() string { return "cloud_run" }

func (s cloudRun) Ready(env provisioner.Env) error {
	if env.Stub {
		return nil
	}
	if env.ExecutesPlan {
		if s.c.Services == nil {
			return errNoCloudRunAdmin
		}
		if s.c.Accounts == nil {
			return errNoServiceAccountAdmin
		}
	}
	return env.Require(
		"QM_TENANT_IMAGE", env.Image,
		"QM_VPC_NETWORK", env.VPCNetwork,
		"QM_VPC_SUBNETWORK", env.VPCSubnetwork,
		"QM_SANDBOX_API_URL", env.SandboxAPIURL,
		"QM_SANDBOX_TEMPLATE", env.SandboxTemplate,
		// Sign-in fails closed without these two, and a tenant nobody can
		// sign in to is not a provisioned tenant.
		"QM_RESEND_SECRET", env.ResendSecret,
		"QM_EMAIL_FROM", env.EmailFrom,
	)
}

func (s cloudRun) Run(ctx context.Context, t *provisioner.Tenant) error {
	name := ServiceName(t.Row.Slug)
	if t.Env.Stub {
		if t.Row.CloudRunService != nil {
			return provisioner.Skip("service " + *t.Row.CloudRunService + " already recorded")
		}
		image, public := t.Env.Image, t.PublicURL()
		return t.Record(ctx, tenantstore.Resources{CloudRunService: &name, ImageTag: &image, PublicURL: &public})
	}
	if s.c.Services == nil {
		return errNoCloudRunAdmin
	}
	if s.c.Accounts == nil {
		return errNoServiceAccountAdmin
	}
	if t.Row.ServiceAccount == nil {
		return fmt.Errorf("cloud_run: the tenant has no service account recorded")
	}
	account := *t.Row.ServiceAccount

	env, err := TenantEnv(t)
	if err != nil {
		return fmt.Errorf("cloud_run: %w", err)
	}
	secretEnv, err := TenantSecretEnv(t)
	if err != nil {
		return fmt.Errorf("cloud_run: %w", err)
	}
	// Grants before the deploy, in a stable order so a retry's logs line
	// up with the first attempt's. Granting is idempotent, so this runs on
	// every attempt rather than only on the one that creates the service:
	// a secret rotated into the spec later still gets its binding.
	for _, secretName := range mountedSecrets(secretEnv) {
		if err := s.c.Accounts.GrantSecretAccess(ctx, secretName, account); err != nil {
			return fmt.Errorf("grant the tenant access to %s: %w", secretName, err)
		}
	}
	// Which shared secret this tenant was granted, recorded on the row.
	// The tenant's own secrets are deleted outright on teardown, so their
	// policies go with them; the platform's shared one outlives every
	// tenant, and if its configured name is rotated to a different
	// resource between now and teardown, the name in the environment is no
	// longer the binding that was made.
	if err := s.recordSharedGrant(ctx, t, t.Env.ResendSecret); err != nil {
		return err
	}

	status, err := s.c.Services.Deploy(ctx, ServiceSpec{
		Name:           name,
		Image:          t.Env.Image,
		ServiceAccount: account,
		Env:            env,
		SecretEnv:      secretEnv,
		Network:        t.Env.VPCNetwork,
		Subnetwork:     t.Env.VPCSubnetwork,
		Labels:         map[string]string{"qm-tenant": t.Row.Slug},
	})
	if err != nil {
		return fmt.Errorf("deploy the tenant's service: %w", err)
	}
	image := status.ImageTag
	if image == "" {
		image = t.Env.Image
	}
	// PublicUrl is the hostname the load balancer routes, not the run.app
	// URI: the tenant's own configuration is built from it, and the console
	// and the admin link both point at it.
	public := t.PublicURL()
	return t.Record(ctx, tenantstore.Resources{CloudRunService: &name, ImageTag: &image, PublicURL: &public})
}

// recordSharedGrant notes which platform secret this tenant's identity was
// granted access to. Nothing is stored under the tenant's own name for it;
// the reference is a record of the binding, not of a secret the tenant owns.
func (s cloudRun) recordSharedGrant(ctx context.Context, t *provisioner.Tenant, secretName string) error {
	if secretName == "" {
		return nil
	}
	if err := t.SetSecretRef(ctx, sharedSecretRef, secretName); err != nil {
		return fmt.Errorf("record the shared email key grant: %w", err)
	}
	return nil
}

// sharedGrants is every platform secret this tenant may hold a binding on:
// the one recorded when it was built and the one configured now.
func (s cloudRun) sharedGrants(ctx context.Context, t *provisioner.Tenant) []string {
	seen := map[string]bool{}
	var out []string
	add := func(name string) {
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		out = append(out, name)
	}
	// A failure to read the references is not fatal: the configured name is
	// still revoked, and the rest is bookkeeping for a rotation that may
	// never have happened.
	if refs, err := t.SecretRefs(ctx); err == nil {
		for _, ref := range refs {
			if ref.Name == sharedSecretRef {
				add(ref.SecretRef)
			}
		}
	}
	add(t.Env.ResendSecret)
	sort.Strings(out)
	return out
}

// mountedSecrets is the Secret Manager names a spec mounts, in a stable
// order so a retry's calls line up with the first attempt's.
func mountedSecrets(secretEnv map[string]string) []string {
	names := make([]string, 0, len(secretEnv))
	for _, secretName := range secretEnv {
		names = append(names, secretName)
	}
	sort.Strings(names)
	return names
}

// Rollback deletes the service. Derived name as well as recorded, so a
// deploy that succeeded and died before Record still gets torn down: a
// leaked tenant service is a container running at min-instance one, billed
// forever, holding connections to the shared database.
func (s cloudRun) Rollback(ctx context.Context, t *provisioner.Tenant) error {
	if t.Env.Stub {
		if t.Row.CloudRunService == nil {
			return provisioner.Skip("no service recorded")
		}
		return nil
	}
	if s.c.Services == nil {
		return errNoCloudRunAdmin
	}
	name := ServiceName(t.Row.Slug)
	if t.Row.CloudRunService != nil {
		name = *t.Row.CloudRunService
	}
	if err := s.c.Services.Delete(ctx, name); err != nil {
		return fmt.Errorf("delete the tenant's service: %w", err)
	}
	// The tenant's own secrets are deleted outright by the secrets step, so
	// their policies go with them. The platform's shared Resend secret does
	// not: it outlives every tenant, and IAM keeps a binding naming a
	// deleted principal, so without this every tenant that ever existed
	// accumulates on that one policy until its size limit stops new ones
	// being granted at all.
	if s.c.Accounts == nil {
		return errNoServiceAccountAdmin
	}
	account := ServiceAccountEmail(t.Env.Project, t.Row.Slug)
	if t.Row.ServiceAccount != nil {
		account = *t.Row.ServiceAccount
	}
	// Both the name the grant was recorded under and the one configured
	// now: they differ when the platform key has been rotated to a
	// different resource since this tenant was built, and the recorded one
	// is the binding that actually exists.
	for _, secretName := range s.sharedGrants(ctx, t) {
		if err := s.c.Accounts.RevokeSecretAccess(ctx, secretName, account); err != nil {
			return fmt.Errorf("revoke the tenant's access to the shared email key: %w", err)
		}
	}
	if err := t.DeleteSecretRef(ctx, sharedSecretRef); err != nil {
		return err
	}
	if t.Row.CloudRunService == nil {
		return provisioner.Skip("no service recorded")
	}
	return nil
}
