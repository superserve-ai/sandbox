package tenantstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/superserve-ai/sandbox/internal/db"
)

const pgUniqueViolation = "23505"

// Postgres is the Store backed by the qm_api role. The pool must connect as
// qm_api (or a role with the same grants): the scope call in every
// transaction is what makes the row policies select the team.
//
// Run locks are held in open transactions for as long as a run lasts, so
// they live on their own small pool: a burst of in-process runs can then
// wait for lock capacity, but can never hold every connection the store's
// own status and event writes need to make progress.
type Postgres struct {
	pool     *pgxpool.Pool
	lockPool *pgxpool.Pool
}

// lockPoolSize bounds concurrently held run locks per process; the job runs
// one, the service's in-process mode a handful.
const lockPoolSize = 4

// NewPostgres builds the store on pool and a lock pool with the same
// connection settings.
func NewPostgres(ctx context.Context, pool *pgxpool.Pool) (*Postgres, error) {
	cfg := pool.Config().Copy()
	cfg.MaxConns = lockPoolSize
	cfg.MinConns = 0
	cfg.MinIdleConns = 0
	lockPool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("lock pool: %w", err)
	}
	return &Postgres{pool: pool, lockPool: lockPool}, nil
}

// Close releases the lock pool; the main pool belongs to the caller.
func (s *Postgres) Close() {
	s.lockPool.Close()
}

// withTeamTx runs fn in a transaction scoped to teamID. The scope is
// transaction-local, so a pooled connection carries nothing over.
func (s *Postgres) withTeamTx(ctx context.Context, teamID uuid.UUID, fn func(q *db.Queries) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := db.New(tx)
	if err := q.SetQMTeamScope(ctx, teamID.String()); err != nil {
		return fmt.Errorf("set team scope: %w", err)
	}
	if err := fn(q); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Postgres) CreateTenant(ctx context.Context, teamID uuid.UUID, p CreateParams) (Tenant, error) {
	var t Tenant
	err := s.withTeamTx(ctx, teamID, func(q *db.Queries) error {
		// Three statements in one transaction, in this order: the lock,
		// then the homing check in its own statement so its snapshot
		// postdates the lock, then the insert.
		if err := q.LockQMTenantAdmission(ctx, teamID); err != nil {
			return err
		}
		homed, err := q.QMTeamHomedHere(ctx, teamID)
		if err != nil {
			return err
		}
		if !homed {
			return ErrTeamNotHomed
		}
		existing, err := q.ListQMTenantsByTeam(ctx, teamID)
		if err != nil {
			return err
		}
		if len(existing) > 0 {
			return ErrTeamHasTenant
		}
		params := db.CreateQMTenantParams{
			TeamID:        teamID,
			Slug:          p.Slug,
			OrgName:       p.OrgName,
			AdminEmail:    p.AdminEmail,
			SignIn:        p.SignIn,
			ModelProvider: p.ModelProvider,
		}
		if p.Harness != "" {
			params.Harness = &p.Harness
		}
		if p.CreatedBy != nil {
			params.CreatedBy = pgtype.UUID{Bytes: *p.CreatedBy, Valid: true}
		}
		t, err = q.CreateQMTenant(ctx, params)
		if pgCode(err) == pgUniqueViolation {
			// Two unique indexes can fire: the slug, or the partial index
			// that allows one live tenant per team (the pre-check above
			// gives the friendlier ordering; the index is the guard).
			if pgConstraint(err) == "qm_tenants_one_active_per_team" {
				return ErrTeamHasTenant
			}
			return ErrSlugTaken
		}
		return err
	})
	return t, err
}

func (s *Postgres) GetTenant(ctx context.Context, teamID, tenantID uuid.UUID) (Tenant, error) {
	var t Tenant
	err := s.withTeamTx(ctx, teamID, func(q *db.Queries) error {
		var err error
		t, err = q.GetQMTenant(ctx, db.GetQMTenantParams{ID: tenantID, TeamID: teamID})
		return notFound(err)
	})
	return t, err
}

func (s *Postgres) ListTenants(ctx context.Context, teamID uuid.UUID) ([]Tenant, error) {
	var ts []Tenant
	err := s.withTeamTx(ctx, teamID, func(q *db.Queries) error {
		var err error
		ts, err = q.ListQMTenantsByTeam(ctx, teamID)
		return err
	})
	return ts, err
}

func (s *Postgres) SetStatus(ctx context.Context, teamID, tenantID uuid.UUID, status string) (Tenant, error) {
	var t Tenant
	err := s.withTeamTx(ctx, teamID, func(q *db.Queries) error {
		var err error
		t, err = q.UpdateQMTenantStatus(ctx, db.UpdateQMTenantStatusParams{ID: tenantID, TeamID: teamID, Status: status})
		return notFound(err)
	})
	return t, err
}

func (s *Postgres) TransitionStatus(ctx context.Context, teamID, tenantID uuid.UUID, from []string, to string) (Tenant, error) {
	var t Tenant
	err := s.withTeamTx(ctx, teamID, func(q *db.Queries) error {
		var err error
		t, err = q.TransitionQMTenantStatus(ctx, db.TransitionQMTenantStatusParams{ID: tenantID, TeamID: teamID, Status: to, FromStatuses: from})
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		// No row matched: missing (or deleted) tenant, or a status the
		// caller did not expect. The follow-up read tells them apart; a
		// database error on that read is reported as such, not as absence.
		current, gerr := q.GetQMTenant(ctx, db.GetQMTenantParams{ID: tenantID, TeamID: teamID})
		switch {
		case errors.Is(gerr, pgx.ErrNoRows):
			return ErrNotFound
		case gerr != nil:
			return fmt.Errorf("re-read tenant after transition: %w", gerr)
		case current.Status == StatusDeleted:
			return ErrNotFound
		}
		return ErrStatusConflict
	})
	return t, err
}

func (s *Postgres) UpdateResources(ctx context.Context, teamID, tenantID uuid.UUID, r Resources) (Tenant, error) {
	var t Tenant
	err := s.withTeamTx(ctx, teamID, func(q *db.Queries) error {
		params := db.UpdateQMTenantResourcesParams{
			ID:              tenantID,
			TeamID:          teamID,
			PublicUrl:       r.PublicURL,
			ImageTag:        r.ImageTag,
			CloudRunService: r.CloudRunService,
			DbName:          r.DBName,
			BucketName:      r.BucketName,
			ServiceAccount:  r.ServiceAccount,
		}
		if r.SandboxAPIKeyID != nil {
			params.SandboxApiKeyID = pgtype.UUID{Bytes: *r.SandboxAPIKeyID, Valid: true}
		}
		var err error
		t, err = q.UpdateQMTenantResources(ctx, params)
		return notFound(err)
	})
	return t, err
}

func (s *Postgres) SoftDelete(ctx context.Context, teamID, tenantID uuid.UUID) (Tenant, error) {
	var t Tenant
	err := s.withTeamTx(ctx, teamID, func(q *db.Queries) error {
		var err error
		t, err = q.SoftDeleteQMTenant(ctx, db.SoftDeleteQMTenantParams{ID: tenantID, TeamID: teamID})
		return notFound(err)
	})
	return t, err
}

// InsertEvent takes its seq from the tenant's own counter, bumped in the
// same statement, so two writers (qm-api recording the trigger while the
// run it started records its first step) serialize on the tenant row
// rather than racing for a number.
func (s *Postgres) InsertEvent(ctx context.Context, teamID uuid.UUID, p EventParams) (Event, error) {
	var e Event
	err := s.withTeamTx(ctx, teamID, func(q *db.Queries) error {
		params := db.InsertQMTenantEventParams{TenantID: p.TenantID, Step: p.Step, Status: p.Status}
		if p.Message != "" {
			params.Message = &p.Message
		}
		if len(p.Detail) > 0 {
			params.Detail = []byte(p.Detail)
		}
		var err error
		// The insert selects its tenant row and yields nothing for a
		// retired tenant: its children are frozen.
		e, err = q.InsertQMTenantEvent(ctx, params)
		return notFound(err)
	})
	return e, err
}

func (s *Postgres) ListEvents(ctx context.Context, teamID, tenantID uuid.UUID) ([]Event, error) {
	var es []Event
	err := s.withTeamTx(ctx, teamID, func(q *db.Queries) error {
		var err error
		es, err = q.ListQMTenantEvents(ctx, tenantID)
		return err
	})
	return es, err
}

func (s *Postgres) SetSecretRef(ctx context.Context, teamID, tenantID uuid.UUID, name, ref string) error {
	return s.withTeamTx(ctx, teamID, func(q *db.Queries) error {
		_, err := q.SetQMTenantSecretRef(ctx, db.SetQMTenantSecretRefParams{TenantID: tenantID, Name: name, SecretRef: ref})
		return notFound(err)
	})
}

func (s *Postgres) ListSecretRefs(ctx context.Context, teamID, tenantID uuid.UUID) ([]SecretRef, error) {
	var refs []SecretRef
	err := s.withTeamTx(ctx, teamID, func(q *db.Queries) error {
		var err error
		refs, err = q.ListQMTenantSecretRefs(ctx, tenantID)
		return err
	})
	return refs, err
}

// DeleteSecretRef is idempotent: a reference that is already gone (or a
// tenant already retired, whose references are frozen) is not an error.
func (s *Postgres) DeleteSecretRef(ctx context.Context, teamID, tenantID uuid.UUID, name string) error {
	return s.withTeamTx(ctx, teamID, func(q *db.Queries) error {
		_, err := q.DeleteQMTenantSecretRef(ctx, db.DeleteQMTenantSecretRefParams{TenantID: tenantID, Name: name})
		return err
	})
}

func (s *Postgres) SlugAvailable(ctx context.Context, teamID uuid.UUID, slug string) (bool, error) {
	var ok bool
	err := s.withTeamTx(ctx, teamID, func(q *db.Queries) error {
		var err error
		ok, err = q.IsQMSlugAvailable(ctx, slug)
		return err
	})
	return ok, err
}

// Lock pins one lock-pool connection in an open transaction holding the
// tenant's advisory lock; release rolls that transaction back, which drops
// the lock, as does the connection dying with a crashed run.
func (s *Postgres) Lock(ctx context.Context, teamID, tenantID uuid.UUID) (func(), error) {
	conn, err := s.lockPool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire: %w", err)
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		conn.Release()
		return nil, fmt.Errorf("begin: %w", err)
	}
	release := func() {
		_ = tx.Rollback(context.WithoutCancel(ctx))
		conn.Release()
	}
	q := db.New(tx)
	if err := q.SetQMTeamScope(ctx, teamID.String()); err != nil {
		release()
		return nil, fmt.Errorf("set team scope: %w", err)
	}
	locked, err := q.TryLockQMTenant(ctx, tenantID.String())
	if err != nil {
		release()
		return nil, fmt.Errorf("try lock: %w", err)
	}
	if !locked {
		release()
		return nil, ErrLocked
	}
	return release, nil
}

func notFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func pgConstraint(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.ConstraintName
	}
	return ""
}

func pgCode(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}
