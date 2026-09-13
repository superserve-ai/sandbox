// Package tenantstore is the persistence boundary for hosted-QM tenants.
// Every operation is scoped to one team: the Postgres implementation opens
// a transaction, declares the team via SetQMTeamScope so the qm_api role's
// row policies apply, and commits; the in-memory implementation enforces
// the same scoping so handler and runner tests exercise it without a
// database.
package tenantstore

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"

	"github.com/superserve-ai/sandbox/internal/db"
)

type (
	Tenant    = db.QmTenant
	Event     = db.QmTenantEvent
	SecretRef = db.QmTenantSecret
)

// Tenant statuses, as constrained by qm.tenants.
const (
	StatusProvisioning   = "provisioning"
	StatusReady          = "ready"
	StatusFailed         = "failed"
	StatusDeprovisioning = "deprovisioning"
	StatusDeleted        = "deleted"
)

// Event statuses, as constrained by qm.tenant_events.
const (
	EventStarted = "started"
	EventOK      = "ok"
	EventFailed  = "failed"
	EventSkipped = "skipped"
)

var (
	ErrNotFound      = errors.New("tenant not found")
	ErrSlugTaken     = errors.New("slug is already taken")
	ErrTeamHasTenant = errors.New("team already has a tenant")
	// ErrTeamNotHomed means the team has been detached from this cell by a
	// team migration; nothing may be created for it here.
	ErrTeamNotHomed = errors.New("team is not homed in this cell")
	// ErrLocked means another provisioner run holds the tenant's lock.
	ErrLocked = errors.New("tenant is locked by another run")
	// ErrStatusConflict means TransitionStatus found the tenant in a status
	// other than the ones it was told to move from.
	ErrStatusConflict = errors.New("tenant status changed")
)

type CreateParams struct {
	Slug          string
	OrgName       string
	AdminEmail    string
	SignIn        string
	ModelProvider string
	Harness       string
	CreatedBy     *uuid.UUID
}

type EventParams struct {
	TenantID uuid.UUID
	Step     string
	Status   string
	Message  string
	// Detail is stored as jsonb; nil stores NULL.
	Detail json.RawMessage
}

// Resources is what provisioning produced. Nil fields are left untouched,
// so each step persists only its own outputs.
type Resources struct {
	PublicURL       *string
	ImageTag        *string
	CloudRunService *string
	DBName          *string
	BucketName      *string
	ServiceAccount  *string
	SandboxAPIKeyID *uuid.UUID
}

// Store is everything qm-api and the provisioner need from Postgres. Each
// call is its own transaction so a crash between calls loses nothing that
// was already recorded.
type Store interface {
	// CreateTenant inserts under the team's admission lock (shared with
	// team migration), refusing a team detached from this cell
	// (ErrTeamNotHomed), and enforces one tenant per team
	// (ErrTeamHasTenant) and global slug uniqueness (ErrSlugTaken).
	CreateTenant(ctx context.Context, teamID uuid.UUID, p CreateParams) (Tenant, error)
	GetTenant(ctx context.Context, teamID, tenantID uuid.UUID) (Tenant, error)
	// ListTenants omits deleted tenants.
	ListTenants(ctx context.Context, teamID uuid.UUID) ([]Tenant, error)
	// SetStatus, UpdateResources and SoftDelete return ErrNotFound for a
	// deleted tenant: deleted is terminal.
	SetStatus(ctx context.Context, teamID, tenantID uuid.UUID, status string) (Tenant, error)
	// TransitionStatus is SetStatus guarded by the statuses it may move
	// from (ErrStatusConflict otherwise), for request paths where two
	// callers may race for the same tenant.
	TransitionStatus(ctx context.Context, teamID, tenantID uuid.UUID, from []string, to string) (Tenant, error)
	UpdateResources(ctx context.Context, teamID, tenantID uuid.UUID, r Resources) (Tenant, error)
	SoftDelete(ctx context.Context, teamID, tenantID uuid.UUID) (Tenant, error)

	// InsertEvent, SetSecretRef and DeleteSecretRef are refused for a
	// deleted tenant (its child rows are frozen); write last words before
	// the soft delete.
	InsertEvent(ctx context.Context, teamID uuid.UUID, p EventParams) (Event, error)
	ListEvents(ctx context.Context, teamID, tenantID uuid.UUID) ([]Event, error)

	SetSecretRef(ctx context.Context, teamID, tenantID uuid.UUID, name, ref string) error
	ListSecretRefs(ctx context.Context, teamID, tenantID uuid.UUID) ([]SecretRef, error)
	DeleteSecretRef(ctx context.Context, teamID, tenantID uuid.UUID, name string) error

	// RevokeSandboxKey revokes the API key the tenant was issued, reporting
	// whether it had one. Teardown must do this rather than just forget the
	// reference: the key is bound to this cell, and team migration refuses
	// a cutover while a tenant still points at a live one. Idempotent.
	RevokeSandboxKey(ctx context.Context, teamID, tenantID uuid.UUID) (bool, error)

	// SlugAvailable answers across every team.
	SlugAvailable(ctx context.Context, teamID uuid.UUID, slug string) (bool, error)

	// Lock takes the tenant's run lock and holds it until release is
	// called; a second caller gets ErrLocked immediately rather than
	// waiting.
	Lock(ctx context.Context, teamID, tenantID uuid.UUID) (release func(), err error)
}
