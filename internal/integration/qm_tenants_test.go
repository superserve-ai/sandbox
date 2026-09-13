//go:build integration

package integration

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/superserve-ai/sandbox/internal/db"
)

const (
	qmAPITestPassword     = "qm-api-integration-test"
	pgInsufficientPriv    = "42501"
	pgCheckViolation      = "23514"
	pgForeignKeyViolation = "23503"
	pgUniqueViolation     = "23505"
	qmTenantsMigration    = "20260912000001_qm_tenants.sql"
)

// connectAsQMAPI opens a real login session as qm_api so the assertions run
// against the role's own grants and row-level policies, not the BYPASSRLS
// superuser behind testPool.
func connectAsQMAPI(t *testing.T) *pgx.Conn {
	t.Helper()
	ctx := context.Background()
	if _, err := testPool.Exec(ctx, `ALTER ROLE qm_api PASSWORD '`+qmAPITestPassword+`'`); err != nil {
		t.Fatalf("set qm_api test password: %v", err)
	}
	cfg, err := pgx.ParseConfig(testDatabaseURL())
	if err != nil {
		t.Fatalf("parse database url: %v", err)
	}
	cfg.User = "qm_api"
	cfg.Password = qmAPITestPassword
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("connect as qm_api: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

// scopedQMTx begins a transaction on conn scoped to teamID the way qm-api
// will: the scope is transaction-local, so each tx declares its own.
func scopedQMTx(t *testing.T, conn *pgx.Conn, teamID uuid.UUID) (pgx.Tx, *db.Queries) {
	t.Helper()
	ctx := context.Background()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	q := db.New(tx)
	if err := q.SetQMTeamScope(ctx, teamID.String()); err != nil {
		t.Fatalf("set team scope: %v", err)
	}
	return tx, q
}

func seedQMTeamAndKey(t *testing.T) (uuid.UUID, uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	team, err := testQueries.CreateTeam(ctx, "qm-team-"+uuid.NewString()[:8])
	if err != nil {
		t.Fatalf("create team: %v", err)
	}
	userID := uuid.New()
	if _, err := testPool.Exec(ctx,
		`INSERT INTO profile (id, email, provider, provider_id) VALUES ($1, $2, 'google', $3)`,
		userID, "qm-"+userID.String()[:8]+"@example.com", "qm-"+userID.String()); err != nil {
		t.Fatalf("create profile: %v", err)
	}
	if _, err := testPool.Exec(ctx,
		`INSERT INTO team_memberships (team_id, user_id, status) VALUES ($1, $2, 'active')`,
		team.ID, userID); err != nil {
		t.Fatalf("create membership: %v", err)
	}
	key, err := testQueries.CreateAPIKeyV2(ctx, db.CreateAPIKeyV2Params{
		TeamID:  team.ID,
		KeyHash: "qm-" + uuid.NewString(),
		Name:    "qm-tenant-key",
		Scopes:  []string{},
	})
	if err != nil {
		t.Fatalf("create api key: %v", err)
	}
	return team.ID, key.ID
}

func pgErrCode(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

func newTenantParams(teamID uuid.UUID, slug string) db.CreateQMTenantParams {
	return db.CreateQMTenantParams{
		TeamID:        teamID,
		Slug:          slug,
		OrgName:       "Pilot Team",
		AdminEmail:    "admin@example.com",
		SignIn:        "magic_link",
		ModelProvider: "anthropic",
	}
}

func TestQMAPI_TenantLifecycleWithinTeamScope(t *testing.T) {
	ctx := context.Background()
	teamID, keyID := seedQMTeamAndKey(t)
	conn := connectAsQMAPI(t)
	slug := "pilot-team-" + uuid.NewString()[:8]

	tx, q := scopedQMTx(t, conn, teamID)

	available, err := q.IsQMSlugAvailable(ctx, slug)
	if err != nil || !available {
		t.Fatalf("slug available before create: available=%v err=%v", available, err)
	}

	tenant, err := q.CreateQMTenant(ctx, newTenantParams(teamID, slug))
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if tenant.Status != "provisioning" || tenant.Harness != "pi" {
		t.Fatalf("defaults: status=%q harness=%q", tenant.Status, tenant.Harness)
	}

	available, err = q.IsQMSlugAvailable(ctx, slug)
	if err != nil || available {
		t.Fatalf("slug available after create: available=%v err=%v", available, err)
	}

	got, err := q.GetQMTenant(ctx, db.GetQMTenantParams{ID: tenant.ID, TeamID: teamID})
	if err != nil || got.Slug != slug {
		t.Fatalf("get tenant: slug=%q err=%v", got.Slug, err)
	}
	listed, err := q.ListQMTenantsByTeam(ctx, teamID)
	if err != nil || len(listed) != 1 {
		t.Fatalf("list tenants: n=%d err=%v", len(listed), err)
	}

	publicURL := "https://" + slug + ".example.com"
	updated, err := q.UpdateQMTenantResources(ctx, db.UpdateQMTenantResourcesParams{
		ID:              tenant.ID,
		TeamID:          teamID,
		PublicUrl:       &publicURL,
		SandboxApiKeyID: pgtype.UUID{Bytes: keyID, Valid: true},
	})
	if err != nil {
		t.Fatalf("update resources: %v", err)
	}
	if updated.PublicUrl == nil || *updated.PublicUrl != publicURL || !updated.SandboxApiKeyID.Valid {
		t.Fatalf("resources not persisted: %+v", updated)
	}
	if updated.ImageTag != nil {
		t.Fatalf("omitted field overwritten: image_tag=%q", *updated.ImageTag)
	}

	ready, err := q.UpdateQMTenantStatus(ctx, db.UpdateQMTenantStatusParams{ID: tenant.ID, TeamID: teamID, Status: "ready"})
	if err != nil || ready.Status != "ready" {
		t.Fatalf("update status: status=%q err=%v", ready.Status, err)
	}

	msg := "service deployed"
	if _, err := q.InsertQMTenantEvent(ctx, db.InsertQMTenantEventParams{
		TenantID: tenant.ID,
		Step:     "cloud_run",
		Status:   "ok",
		Message:  &msg,
		Detail:   []byte(`{"revision":"r1"}`),
	}); err != nil {
		t.Fatalf("insert event: %v", err)
	}
	events, err := q.ListQMTenantEvents(ctx, tenant.ID)
	if err != nil || len(events) != 1 || events[0].Step != "cloud_run" {
		t.Fatalf("list events: n=%d err=%v", len(events), err)
	}

	secretRef := "projects/example/secrets/" + slug + "-db/versions/latest"
	if err := q.SetQMTenantSecretRef(ctx, db.SetQMTenantSecretRefParams{
		TenantID: tenant.ID, Name: "database_url", SecretRef: secretRef,
	}); err != nil {
		t.Fatalf("set secret ref: %v", err)
	}
	gotRef, err := q.GetQMTenantSecretRef(ctx, db.GetQMTenantSecretRefParams{TenantID: tenant.ID, Name: "database_url"})
	if err != nil || gotRef != secretRef {
		t.Fatalf("get secret ref: ref=%q err=%v", gotRef, err)
	}
	refs, err := q.ListQMTenantSecretRefs(ctx, tenant.ID)
	if err != nil || len(refs) != 1 {
		t.Fatalf("list secret refs: n=%d err=%v", len(refs), err)
	}

	var teamRows, keyRows int
	var membershipRows int
	if err := tx.QueryRow(ctx, `SELECT count(id) FROM public.team_memberships WHERE team_id = $1`, teamID).Scan(&membershipRows); err != nil {
		t.Fatalf("select public.team_memberships as qm_api: %v", err)
	}
	if err := tx.QueryRow(ctx, `SELECT count(id) FROM public.team WHERE id = $1`, teamID).Scan(&teamRows); err != nil {
		t.Fatalf("select public.team as qm_api: %v", err)
	}
	if err := tx.QueryRow(ctx, `SELECT count(id) FROM public.api_key WHERE id = $1`, keyID).Scan(&keyRows); err != nil {
		t.Fatalf("select public.api_key as qm_api: %v", err)
	}
	if teamRows != 1 || keyRows != 1 {
		t.Fatalf("qm_api cannot see its own team/key rows: team=%d key=%d", teamRows, keyRows)
	}

	deleted, err := q.SoftDeleteQMTenant(ctx, db.SoftDeleteQMTenantParams{ID: tenant.ID, TeamID: teamID})
	if err != nil || deleted.Status != "deleted" {
		t.Fatalf("soft delete: status=%q err=%v", deleted.Status, err)
	}
	if _, err := q.SoftDeleteQMTenant(ctx, db.SoftDeleteQMTenantParams{ID: tenant.ID, TeamID: teamID}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("second soft delete should match no row, got %v", err)
	}
	listed, err = q.ListQMTenantsByTeam(ctx, teamID)
	if err != nil || len(listed) != 0 {
		t.Fatalf("deleted tenant still listed: n=%d err=%v", len(listed), err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

func TestQMAPI_RowsAreInvisibleOutsideTeamScope(t *testing.T) {
	ctx := context.Background()
	teamA, _ := seedQMTeamAndKey(t)
	teamB, _ := seedQMTeamAndKey(t)
	slug := "scoped-" + uuid.NewString()[:8]

	tenant, err := testQueries.CreateQMTenant(ctx, newTenantParams(teamA, slug))
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	conn := connectAsQMAPI(t)

	t.Run("other team", func(t *testing.T) {
		tx, q := scopedQMTx(t, conn, teamB)
		if _, err := q.GetQMTenant(ctx, db.GetQMTenantParams{ID: tenant.ID, TeamID: teamA}); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("team A tenant visible from team B scope: %v", err)
		}
		if _, err := q.CreateQMTenant(ctx, newTenantParams(teamA, "cross-"+uuid.NewString()[:8])); pgErrCode(err) != pgInsufficientPriv {
			t.Fatalf("insert for another team should violate RLS, got %v", err)
		}
		_ = tx.Rollback(ctx)

		tx, q = scopedQMTx(t, conn, teamB)
		available, err := q.IsQMSlugAvailable(ctx, slug)
		if err != nil || available {
			t.Fatalf("slug taken by another team reported available: available=%v err=%v", available, err)
		}
		var keyRows int
		if err := tx.QueryRow(ctx, `SELECT count(id) FROM public.api_key WHERE team_id = $1`, teamA).Scan(&keyRows); err != nil {
			t.Fatalf("select api_key: %v", err)
		}
		if keyRows != 0 {
			t.Fatalf("team A api keys visible from team B scope: %d", keyRows)
		}
	})

	t.Run("no scope", func(t *testing.T) {
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM qm.tenants`).Scan(&n); err != nil {
			t.Fatalf("select tenants: %v", err)
		}
		if n != 0 {
			t.Fatalf("unscoped session sees %d tenants", n)
		}
		if _, err := db.New(tx).CreateQMTenant(ctx, newTenantParams(teamA, "unscoped-"+uuid.NewString()[:8])); pgErrCode(err) != pgInsufficientPriv {
			t.Fatalf("unscoped insert should violate RLS, got %v", err)
		}
	})
}

func TestQMAPI_HasNoAccessToSandboxTables(t *testing.T) {
	ctx := context.Background()
	teamID, _ := seedQMTeamAndKey(t)
	conn := connectAsQMAPI(t)

	for _, stmt := range []string{
		`SELECT * FROM public.sandbox`,
		`SELECT * FROM public.team_member`,
		`SELECT credential_store_config FROM public.team`,
		`SELECT key_hash FROM public.api_key`,
		`DELETE FROM qm.tenants`,
		`UPDATE qm.tenant_events SET status = 'ok'`,
		`DELETE FROM qm.tenant_events`,
		`INSERT INTO public.team (name) VALUES ('qm-api-should-not-write')`,
		`CREATE TABLE qm.scratch (id int)`,
	} {
		tx, _ := scopedQMTx(t, conn, teamID)
		_, err := tx.Exec(ctx, stmt)
		if pgErrCode(err) != pgInsufficientPriv {
			t.Errorf("%s: want permission error, got %v", stmt, err)
		}
		_ = tx.Rollback(ctx)
	}
}

func TestQMAPI_RejectsInvalidSlugs(t *testing.T) {
	ctx := context.Background()
	teamID, _ := seedQMTeamAndKey(t)
	conn := connectAsQMAPI(t)

	for _, slug := range []string{
		"ab",
		"-leading",
		"trailing-",
		"UpperCase",
		"under_score",
		"dot.ted",
		strings.Repeat("a", 41),
	} {
		tx, q := scopedQMTx(t, conn, teamID)
		_, err := q.CreateQMTenant(ctx, newTenantParams(teamID, slug))
		if pgErrCode(err) != pgCheckViolation {
			t.Errorf("slug %q: want check violation, got %v", slug, err)
		}
		_ = tx.Rollback(ctx)
	}

	for _, slug := range []string{"abc", strings.Repeat("z", 40)} {
		tx, q := scopedQMTx(t, conn, teamID)
		if _, err := q.CreateQMTenant(ctx, newTenantParams(teamID, slug)); err != nil {
			t.Errorf("valid slug %q rejected: %v", slug, err)
		}
		_ = tx.Rollback(ctx)
	}
}

func TestQMMigrationIsIdempotent(t *testing.T) {
	ctx := context.Background()
	dir, err := migrationsDir()
	if err != nil {
		t.Fatal(err)
	}
	sql, err := os.ReadFile(filepath.Join(dir, qmTenantsMigration))
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	if _, err := testPool.Exec(ctx, string(sql)); err != nil {
		t.Fatalf("re-applying migration on a migrated database failed: %v", err)
	}
	if strings.Contains(strings.ToLower(string(sql)), "password '") {
		t.Fatal("migration hardcodes a password literal")
	}
}

// A tenant may only ever point at a sandbox API key its own team owns. RLS does
// not take part in foreign-key checks, so the composite key carries the team.
func TestQMAPI_RejectsAPIKeyOwnedByAnotherTeam(t *testing.T) {
	ctx := context.Background()
	teamID, ownKeyID := seedQMTeamAndKey(t)
	_, foreignKeyID := seedQMTeamAndKey(t)
	conn := connectAsQMAPI(t)
	tx, q := scopedQMTx(t, conn, teamID)

	tenant, err := q.CreateQMTenant(ctx, newTenantParams(teamID, "pilot-team-"+uuid.NewString()[:8]))
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	_, err = q.UpdateQMTenantResources(ctx, db.UpdateQMTenantResourcesParams{
		ID:              tenant.ID,
		TeamID:          teamID,
		SandboxApiKeyID: pgtype.UUID{Bytes: foreignKeyID, Valid: true},
	})
	if code := pgErrCode(err); code != pgForeignKeyViolation {
		t.Fatalf("key from another team: want %s, got err=%v", pgForeignKeyViolation, err)
	}

	// The failed statement aborted the transaction; start a fresh one.
	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	tx, q = scopedQMTx(t, conn, teamID)
	tenant, err = q.CreateQMTenant(ctx, newTenantParams(teamID, "pilot-team-"+uuid.NewString()[:8]))
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	updated, err := q.UpdateQMTenantResources(ctx, db.UpdateQMTenantResourcesParams{
		ID:              tenant.ID,
		TeamID:          teamID,
		SandboxApiKeyID: pgtype.UUID{Bytes: ownKeyID, Valid: true},
	})
	if err != nil || !updated.SandboxApiKeyID.Valid || updated.SandboxApiKeyID.Bytes != ownKeyID {
		t.Fatalf("own key: err=%v valid=%v", err, updated.SandboxApiKeyID.Valid)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// Deleting the key (the expired-key sweep) releases the reference without
	// touching the tenant or its team.
	if _, err := testPool.Exec(ctx, `DELETE FROM public.api_key WHERE id = $1`, ownKeyID); err != nil {
		t.Fatalf("delete api key: %v", err)
	}
	var stillTeam uuid.UUID
	var released pgtype.UUID
	if err := testPool.QueryRow(ctx, `SELECT team_id, sandbox_api_key_id FROM qm.tenants WHERE id = $1`, tenant.ID).Scan(&stillTeam, &released); err != nil {
		t.Fatalf("reload tenant: %v", err)
	}
	if stillTeam != teamID || released.Valid {
		t.Fatalf("after key deletion: team=%s (want %s) keyValid=%v (want false)", stillTeam, teamID, released.Valid)
	}
}

func TestQMAPI_DeletedTenantStaysDeleted(t *testing.T) {
	ctx := context.Background()
	teamID, _ := seedQMTeamAndKey(t)
	conn := connectAsQMAPI(t)
	_, q := scopedQMTx(t, conn, teamID)

	tenant, err := q.CreateQMTenant(ctx, newTenantParams(teamID, "pilot-team-"+uuid.NewString()[:8]))
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if _, err := q.SoftDeleteQMTenant(ctx, db.SoftDeleteQMTenantParams{ID: tenant.ID, TeamID: teamID}); err != nil {
		t.Fatalf("soft delete: %v", err)
	}
	_, err = q.UpdateQMTenantStatus(ctx, db.UpdateQMTenantStatusParams{ID: tenant.ID, TeamID: teamID, Status: "ready"})
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("status update after delete: want no rows, got err=%v", err)
	}
	url := "https://resurrected.example.com"
	_, err = q.UpdateQMTenantResources(ctx, db.UpdateQMTenantResourcesParams{ID: tenant.ID, TeamID: teamID, PublicUrl: &url})
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("resources update after delete: want no rows, got err=%v", err)
	}
	got, err := q.GetQMTenant(ctx, db.GetQMTenantParams{ID: tenant.ID, TeamID: teamID})
	if err != nil || got.Status != "deleted" {
		t.Fatalf("deleted tenant: status=%q err=%v", got.Status, err)
	}
}

func TestQMAPI_OneActiveTenantPerTeam(t *testing.T) {
	ctx := context.Background()
	teamID, _ := seedQMTeamAndKey(t)
	conn := connectAsQMAPI(t)
	tx, q := scopedQMTx(t, conn, teamID)

	first, err := q.CreateQMTenant(ctx, newTenantParams(teamID, "pilot-team-"+uuid.NewString()[:8]))
	if err != nil {
		t.Fatalf("create first tenant: %v", err)
	}
	_, err = q.CreateQMTenant(ctx, newTenantParams(teamID, "pilot-team-"+uuid.NewString()[:8]))
	if code := pgErrCode(err); code != pgUniqueViolation {
		t.Fatalf("second active tenant: want %s, got err=%v", pgUniqueViolation, err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	_, q = scopedQMTx(t, conn, teamID)
	first, err = q.CreateQMTenant(ctx, newTenantParams(teamID, "pilot-team-"+uuid.NewString()[:8]))
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if _, err := q.SoftDeleteQMTenant(ctx, db.SoftDeleteQMTenantParams{ID: first.ID, TeamID: teamID}); err != nil {
		t.Fatalf("soft delete: %v", err)
	}
	if _, err := q.CreateQMTenant(ctx, newTenantParams(teamID, "pilot-team-"+uuid.NewString()[:8])); err != nil {
		t.Fatalf("create after delete: %v", err)
	}
}

func TestQMAPI_EventsInOneTransactionKeepInsertionOrder(t *testing.T) {
	ctx := context.Background()
	teamID, _ := seedQMTeamAndKey(t)
	conn := connectAsQMAPI(t)
	_, q := scopedQMTx(t, conn, teamID)
	tenant, err := q.CreateQMTenant(ctx, newTenantParams(teamID, "pilot-team-"+uuid.NewString()[:8]))
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	steps := []string{"database", "identity", "secrets", "deploy", "edge"}
	for _, step := range steps {
		if _, err := q.InsertQMTenantEvent(ctx, db.InsertQMTenantEventParams{TenantID: tenant.ID, Step: step, Status: "ok"}); err != nil {
			t.Fatalf("insert event %s: %v", step, err)
		}
	}
	events, err := q.ListQMTenantEvents(ctx, tenant.ID)
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	for i, ev := range events {
		if ev.Step != steps[i] {
			t.Fatalf("event %d: got %q want %q", i, ev.Step, steps[i])
		}
	}
}

func TestQMAPI_NoTenantForATeamDetachedFromThisCell(t *testing.T) {
	ctx := context.Background()
	teamID, _ := seedQMTeamAndKey(t)
	if _, err := testPool.Exec(ctx, `DELETE FROM public.team_memberships WHERE team_id = $1`, teamID); err != nil {
		t.Fatalf("detach team memberships: %v", err)
	}
	conn := connectAsQMAPI(t)
	_, q := scopedQMTx(t, conn, teamID)
	_, err := q.CreateQMTenant(ctx, newTenantParams(teamID, "pilot-team-"+uuid.NewString()[:8]))
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("tenant admission for a detached team: want no rows, got err=%v", err)
	}
}
