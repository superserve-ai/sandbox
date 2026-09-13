// Package steps holds the provisioning steps in plan order. Each cloud-
// touching step is its own file with the client interface it needs; the
// implementations behind those interfaces live in the gcp subpackage and
// are wired in cmd/qm-api.
//
// Under stub mode (Env.Stub, from QM_PROVISIONER_STUB=1) the cloud-touching
// steps record placeholder resource names instead of calling GCP, so the
// engine, the API and the console can be exercised without a project. Every
// step declares what it cannot run without through Ready, which
// provisioner.PlanReady checks once at startup: a run must never stop at a
// step that was never going to work, because by then the tenant already has
// a model key in Secret Manager and a half-built stack behind it.
package steps

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/superserve-ai/sandbox/internal/qm/provisioner"
	"github.com/superserve-ai/sandbox/internal/qm/secrets"
)

// Clients is every external dependency the plan needs. A nil field is fine
// in stub mode, where no step calls out; outside it, the step that needs a
// client says so from Ready and the binary refuses to start.
type Clients struct {
	Secrets      secrets.Store
	Databases    DatabaseAdmin
	Accounts     ServiceAccountAdmin
	Buckets      BucketAdmin
	Services     CloudRunAdmin
	LoadBalancer LoadBalancerAdmin
	// HTTP performs the health and smoke probes against the public URL.
	HTTP *http.Client
	// HealthTimeout, SmokeTimeout and ProbeInterval bound those probes.
	// Zero takes the defaults; they are settable so a test does not have
	// to wait out a ten-minute budget to watch one fail.
	HealthTimeout time.Duration
	SmokeTimeout  time.Duration
	ProbeInterval time.Duration
}

// All returns the plan in provision order; the deprovision plan is the
// reverse, running each step's Rollback. Order follows the dependencies:
// generated secrets first (the database step reads DATABASE_PASSWORD, the
// service account is granted access to them), then the identity, then the
// resources bound to it, then the sandbox key the service is configured
// with, then the service and its route, then the probes.
func All(c Clients) []provisioner.Step {
	if c.HTTP == nil {
		c.HTTP = defaultProbeClient()
	}
	if c.HealthTimeout <= 0 {
		c.HealthTimeout = defaultHealthTimeout
	}
	if c.SmokeTimeout <= 0 {
		c.SmokeTimeout = defaultSmokeTimeout
	}
	if c.ProbeInterval <= 0 {
		c.ProbeInterval = defaultProbeInterval
	}
	return []provisioner.Step{
		secretsStep{c: c},
		serviceAccount{c: c},
		database{c: c},
		bucket{c: c},
		sandboxKey{c: c},
		cloudRun{c: c},
		loadBalancer{c: c},
		healthCheck{c: c},
		smoke{c: c},
		adminLink{c: c},
	}
}

// Resource naming. Kept together so the length rules of each GCP resource
// type are visible in one place: slugs are up to 40 characters, which fits
// database, bucket and service names but not a service account id.

// DatabaseName is the tenant's database on the shared Cloud SQL instance.
func DatabaseName(slug string) string {
	return "qm_" + strings.ReplaceAll(slug, "-", "_")
}

// TenantLabelKey carries the tenant a runtime-created resource belongs to.
// The value is the tenant's id rather than its slug: the slug is chosen by
// whoever created the tenant, and this is the marker that decides whether an
// existing resource may be adopted.
const TenantLabelKey = "qm-tenant-id"

// TenantLabels are the labels every per-tenant resource carries. The slug is
// there for whoever is reading the console; the id is what is checked.
func TenantLabels(tenantID, slug string) map[string]string {
	return map[string]string{TenantLabelKey: tenantID, "qm-tenant": slug}
}

// TenantDescription is the marker for the per-tenant resources that take a
// description but no labels: service accounts, serverless NEGs and backend
// services. Same purpose as TenantLabels — it is what tells this tenant's
// resource apart from one that merely happens to have the name a slug
// derives.
func TenantDescription(tenantID, slug string) string {
	return "QM tenant " + slug + " (" + tenantID + ")"
}

// RoleName is the tenant's Postgres role on the shared instance. It shares
// the database's name: one role, one database, and nothing else on the
// instance the role may connect to.
func RoleName(slug string) string {
	return DatabaseName(slug)
}

// ServiceName is the tenant's Cloud Run service.
func ServiceName(slug string) string {
	return "qm-" + slug
}

// BucketName is the tenant's object storage bucket, project-prefixed
// because bucket names are global and bounded to the 63-character limit
// for names without dots; a slug that does not fit is truncated with a
// stable hash suffix, as for service accounts.
func BucketName(project, slug string) string {
	return bounded(project+"-qm-"+slug, slug, 63)
}

// ServiceAccountID fits the 6–30 character account-id limit: slugs that do
// not fit are truncated and given a stable hash suffix.
func ServiceAccountID(slug string) string {
	return bounded("qm-"+slug, slug, 30)
}

// bounded returns name unchanged when it fits max, else truncated to leave
// room for "-" plus six hex characters of the slug's hash, so distinct
// slugs stay distinct after truncation.
func bounded(name, slug string, max int) string {
	if len(name) <= max {
		return name
	}
	sum := sha256.Sum256([]byte(slug))
	suffix := "-" + hex.EncodeToString(sum[:])[:6]
	return strings.TrimRight(name[:max-len(suffix)], "-") + suffix
}

// ServiceAccountEmail is the account's principal form.
func ServiceAccountEmail(project, slug string) string {
	return ServiceAccountID(slug) + "@" + project + ".iam.gserviceaccount.com"
}
