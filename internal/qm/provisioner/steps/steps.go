// Package steps holds the provisioning steps in plan order. Each cloud-
// touching step is its own file with the client interface it needs; the
// implementations behind those interfaces are wired in cmd/qm-api. Until a
// real implementation lands, a step succeeds only in stub mode (Env.Stub,
// from QM_PROVISIONER_STUB=1), where it records placeholder resource names
// so the rest of the engine, the API and the console can be exercised.
package steps

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/superserve-ai/sandbox/internal/qm/provisioner"
	"github.com/superserve-ai/sandbox/internal/qm/secrets"
)

// Clients is every external dependency the plan needs. A nil field is fine
// in stub mode; outside it the step that needs the client returns
// NotImplemented until the client (and the step body) exists.
type Clients struct {
	Secrets      secrets.Store
	Databases    DatabaseAdmin
	Accounts     ServiceAccountAdmin
	Buckets      BucketAdmin
	Services     CloudRunAdmin
	LoadBalancer LoadBalancerAdmin
	// HTTP performs the health and smoke probes against the public URL.
	HTTP *http.Client
}

// stubOnly is embedded by the steps whose cloud implementations have not
// landed. They can only record placeholders, so provisioner.PlanReady
// refuses a non-stub binary rather than letting it accept tenants it would
// abandon halfway through building.
type stubOnly struct{}

var errStubOnly = errors.New("not implemented; set QM_PROVISIONER_STUB=1 to run the plan with placeholders")

func (stubOnly) Ready(env provisioner.Env) error {
	if env.Stub {
		return nil
	}
	return errStubOnly
}

// All returns the plan in provision order; the deprovision plan is the
// reverse, running each step's Rollback. Order follows the dependencies:
// generated secrets first (the database step reads DATABASE_PASSWORD, the
// service account is granted access to them), then the identity, then the
// resources bound to it, then the sandbox key the service is configured
// with, then the service and its route, then the probes.
func All(c Clients) []provisioner.Step {
	if c.HTTP == nil {
		c.HTTP = &http.Client{Timeout: 15 * time.Second}
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
