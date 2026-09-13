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
	"time"

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

// Version identifies one generation of a tenant row: the status writes it
// has taken (UpdatedAt) and the events recorded against it (EventSeq). Two
// attempts at the same operation share a status, so callers whose writes
// must not clobber a newer attempt key on this instead.
type Version struct {
	UpdatedAt time.Time
	EventSeq  int64
}

func VersionOf(t Tenant) Version {
	return Version{UpdatedAt: t.UpdatedAt, EventSeq: t.EventSeq}
}

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

// SandboxKeyParams is the api_key row IssueSandboxKey inserts. The raw key
// is never passed: only its hash reaches the database, as for every other
// key the control plane issues.
type SandboxKeyParams struct {
	KeyHash string
	Name    string
	Scopes  []string
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
	// TransitionStatusIfUnchanged is TransitionStatus with an additional
	// check that the row is still the version the caller observed;
	// ErrStatusConflict when anything has written it since.
	TransitionStatusIfUnchanged(ctx context.Context, teamID, tenantID uuid.UUID, from []string, to string, at Version) (Tenant, error)
	UpdateResources(ctx context.Context, teamID, tenantID uuid.UUID, r Resources) (Tenant, error)
	SoftDelete(ctx context.Context, teamID, tenantID uuid.UUID) (Tenant, error)

	// InsertEvent, SetSecretRef and DeleteSecretRef are refused for a
	// deleted tenant (its child rows are frozen); write last words before
	// the soft delete.
	InsertEvent(ctx context.Context, teamID uuid.UUID, p EventParams) (Event, error)
	// InsertEventIfUnchanged is InsertEvent with the row-version check in
	// the same statement; ErrStatusConflict when the tenant has moved on.
	InsertEventIfUnchanged(ctx context.Context, teamID uuid.UUID, p EventParams, at Version) (Event, error)
	ListEvents(ctx context.Context, teamID, tenantID uuid.UUID) ([]Event, error)

	SetSecretRef(ctx context.Context, teamID, tenantID uuid.UUID, name, ref string) error
	ListSecretRefs(ctx context.Context, teamID, tenantID uuid.UUID) ([]SecretRef, error)
	DeleteSecretRef(ctx context.Context, teamID, tenantID uuid.UUID, name string) error

	// IssueSandboxKey mints the tenant's Superserve API key — the
	// credential its QM creates sandboxes with — and points the tenant row
	// at it in one statement, returning the key's id. Idempotent: a tenant
	// that already has a key gets that key's id back and no second key is
	// created. ErrNotFound when the tenant is gone.
	//
	// One statement matters more here than usual: an insert whose reference
	// was recorded separately could be interrupted in between and leave a
	// live credential on the team that nothing would ever revoke, because
	// teardown revokes only what the tenant row points at.
	IssueSandboxKey(ctx context.Context, teamID, tenantID uuid.UUID, p SandboxKeyParams) (uuid.UUID, error)

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
