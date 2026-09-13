package tenantstore

import (
	"context"
	"encoding/json"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Memory is an in-process Store with the same team scoping, uniqueness and
// terminal-state rules as the Postgres schema, for tests and local runs.
type Memory struct {
	mu      sync.Mutex
	tenants map[uuid.UUID]*Tenant
	events  map[uuid.UUID][]Event
	secrets map[uuid.UUID]map[string]string
	locked  map[uuid.UUID]bool
	// Now lets tests pin event timestamps.
	Now func() time.Time
	// Fail, when set, is returned by every operation; tests use it to make
	// the store itself the failure.
	Fail error
	// BeforeSetStatus, when set, can veto a status write; tests use it to
	// fail one terminal transition.
	BeforeSetStatus func(status string) error
	// BeforeSoftDelete likewise vetoes SoftDelete.
	BeforeSoftDelete func() error
	// Detached lists teams migrated away from this cell.
	Detached map[uuid.UUID]bool
	// RevokedKeys are the sandbox API keys RevokeSandboxKey has revoked.
	RevokedKeys map[uuid.UUID]bool
}

func NewMemory() *Memory {
	return &Memory{
		tenants: map[uuid.UUID]*Tenant{},
		events:  map[uuid.UUID][]Event{},
		secrets: map[uuid.UUID]map[string]string{},
		locked:  map[uuid.UUID]bool{},
		Now:     time.Now,

		RevokedKeys: map[uuid.UUID]bool{},
	}
}

func (m *Memory) scoped(teamID, tenantID uuid.UUID) (*Tenant, error) {
	t, ok := m.tenants[tenantID]
	if !ok || t.TeamID != teamID {
		return nil, ErrNotFound
	}
	return t, nil
}

// live is scoped plus the "deleted is terminal" write guard.
func (m *Memory) live(teamID, tenantID uuid.UUID) (*Tenant, error) {
	t, err := m.scoped(teamID, tenantID)
	if err != nil {
		return nil, err
	}
	if t.Status == StatusDeleted {
		return nil, ErrNotFound
	}
	return t, nil
}

func (m *Memory) CreateTenant(_ context.Context, teamID uuid.UUID, p CreateParams) (Tenant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return Tenant{}, m.Fail
	}
	if m.Detached[teamID] {
		return Tenant{}, ErrTeamNotHomed
	}
	for _, t := range m.tenants {
		if t.TeamID == teamID && t.Status != StatusDeleted {
			return Tenant{}, ErrTeamHasTenant
		}
	}
	for _, t := range m.tenants {
		if t.Slug == p.Slug {
			return Tenant{}, ErrSlugTaken
		}
	}
	now := m.Now()
	harness := p.Harness
	if harness == "" {
		harness = "pi"
	}
	t := &Tenant{
		ID: uuid.New(), TeamID: teamID, Slug: p.Slug, OrgName: p.OrgName, AdminEmail: p.AdminEmail,
		SignIn: p.SignIn, ModelProvider: p.ModelProvider, Harness: harness, Status: StatusProvisioning,
		CreatedAt: now, UpdatedAt: now,
	}
	if p.CreatedBy != nil {
		t.CreatedBy = pgtype.UUID{Bytes: *p.CreatedBy, Valid: true}
	}
	m.tenants[t.ID] = t
	return *t, nil
}

func (m *Memory) GetTenant(_ context.Context, teamID, tenantID uuid.UUID) (Tenant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return Tenant{}, m.Fail
	}
	t, err := m.scoped(teamID, tenantID)
	if err != nil {
		return Tenant{}, err
	}
	return *t, nil
}

func (m *Memory) ListTenants(_ context.Context, teamID uuid.UUID) ([]Tenant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return nil, m.Fail
	}
	out := []Tenant{}
	for _, t := range m.tenants {
		if t.TeamID == teamID && t.Status != StatusDeleted {
			out = append(out, *t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (m *Memory) SetStatus(_ context.Context, teamID, tenantID uuid.UUID, status string) (Tenant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return Tenant{}, m.Fail
	}
	if m.BeforeSetStatus != nil {
		if err := m.BeforeSetStatus(status); err != nil {
			return Tenant{}, err
		}
	}
	t, err := m.live(teamID, tenantID)
	if err != nil {
		return Tenant{}, err
	}
	t.Status = status
	t.UpdatedAt = m.Now()
	return *t, nil
}

func (m *Memory) TransitionStatus(_ context.Context, teamID, tenantID uuid.UUID, from []string, to string) (Tenant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return Tenant{}, m.Fail
	}
	if m.BeforeSetStatus != nil {
		if err := m.BeforeSetStatus(to); err != nil {
			return Tenant{}, err
		}
	}
	t, err := m.live(teamID, tenantID)
	if err != nil {
		return Tenant{}, err
	}
	if !slices.Contains(from, t.Status) {
		return Tenant{}, ErrStatusConflict
	}
	t.Status = to
	t.UpdatedAt = m.Now()
	return *t, nil
}

func (m *Memory) UpdateResources(_ context.Context, teamID, tenantID uuid.UUID, r Resources) (Tenant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return Tenant{}, m.Fail
	}
	t, err := m.live(teamID, tenantID)
	if err != nil {
		return Tenant{}, err
	}
	coalesce := func(dst **string, src *string) {
		if src != nil {
			v := *src
			*dst = &v
		}
	}
	coalesce(&t.PublicUrl, r.PublicURL)
	coalesce(&t.ImageTag, r.ImageTag)
	coalesce(&t.CloudRunService, r.CloudRunService)
	coalesce(&t.DbName, r.DBName)
	coalesce(&t.BucketName, r.BucketName)
	coalesce(&t.ServiceAccount, r.ServiceAccount)
	if r.SandboxAPIKeyID != nil {
		t.SandboxApiKeyID = pgtype.UUID{Bytes: *r.SandboxAPIKeyID, Valid: true}
	}
	t.UpdatedAt = m.Now()
	return *t, nil
}

func (m *Memory) SoftDelete(_ context.Context, teamID, tenantID uuid.UUID) (Tenant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return Tenant{}, m.Fail
	}
	if m.BeforeSoftDelete != nil {
		if err := m.BeforeSoftDelete(); err != nil {
			return Tenant{}, err
		}
	}
	t, err := m.live(teamID, tenantID)
	if err != nil {
		return Tenant{}, err
	}
	t.Status = StatusDeleted
	t.UpdatedAt = m.Now()
	return *t, nil
}

func (m *Memory) InsertEvent(_ context.Context, teamID uuid.UUID, p EventParams) (Event, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return Event{}, m.Fail
	}
	if _, err := m.live(teamID, p.TenantID); err != nil {
		return Event{}, err
	}
	e := Event{ID: uuid.New(), TenantID: p.TenantID, Step: p.Step, Status: p.Status, Seq: int64(len(m.events[p.TenantID]) + 1), At: m.Now()}
	if p.Message != "" {
		msg := p.Message
		e.Message = &msg
	}
	if len(p.Detail) > 0 {
		e.Detail = append(json.RawMessage(nil), p.Detail...)
	}
	m.events[p.TenantID] = append(m.events[p.TenantID], e)
	return e, nil
}

func (m *Memory) ListEvents(_ context.Context, teamID, tenantID uuid.UUID) ([]Event, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return nil, m.Fail
	}
	if _, err := m.scoped(teamID, tenantID); err != nil {
		return nil, err
	}
	return append([]Event{}, m.events[tenantID]...), nil
}

func (m *Memory) SetSecretRef(_ context.Context, teamID, tenantID uuid.UUID, name, ref string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	if _, err := m.live(teamID, tenantID); err != nil {
		return err
	}
	if m.secrets[tenantID] == nil {
		m.secrets[tenantID] = map[string]string{}
	}
	m.secrets[tenantID][name] = ref
	return nil
}

func (m *Memory) ListSecretRefs(_ context.Context, teamID, tenantID uuid.UUID) ([]SecretRef, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return nil, m.Fail
	}
	if _, err := m.scoped(teamID, tenantID); err != nil {
		return nil, err
	}
	out := []SecretRef{}
	for name, ref := range m.secrets[tenantID] {
		out = append(out, SecretRef{TenantID: tenantID, Name: name, SecretRef: ref})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *Memory) DeleteSecretRef(_ context.Context, teamID, tenantID uuid.UUID, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	if _, err := m.live(teamID, tenantID); err != nil {
		return err
	}
	delete(m.secrets[tenantID], name)
	return nil
}

// RevokeSandboxKey records the revocation the definer function performs in
// Postgres; RevokedKeys is what tests assert on.
func (m *Memory) RevokeSandboxKey(_ context.Context, teamID, tenantID uuid.UUID) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return false, m.Fail
	}
	// Scoped, not live: a tenant is retired before its teardown finishes.
	t, err := m.scoped(teamID, tenantID)
	if err != nil {
		return false, err
	}
	if !t.SandboxApiKeyID.Valid {
		return false, nil
	}
	m.RevokedKeys[uuid.UUID(t.SandboxApiKeyID.Bytes)] = true
	return true, nil
}

func (m *Memory) SlugAvailable(_ context.Context, _ uuid.UUID, slug string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return false, m.Fail
	}
	for _, t := range m.tenants {
		if t.Slug == slug {
			return false, nil
		}
	}
	return true, nil
}

func (m *Memory) Lock(_ context.Context, teamID, tenantID uuid.UUID) (func(), error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return nil, m.Fail
	}
	if _, err := m.scoped(teamID, tenantID); err != nil {
		return nil, err
	}
	if m.locked[tenantID] {
		return nil, ErrLocked
	}
	m.locked[tenantID] = true
	var once sync.Once
	return func() {
		once.Do(func() {
			m.mu.Lock()
			delete(m.locked, tenantID)
			m.mu.Unlock()
		})
	}, nil
}
