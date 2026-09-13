//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/qm"
	"github.com/superserve-ai/sandbox/internal/qm/adminlink"
	"github.com/superserve-ai/sandbox/internal/qm/provisioner"
	"github.com/superserve-ai/sandbox/internal/qm/provisioner/steps"
	"github.com/superserve-ai/sandbox/internal/qm/secrets"
	"github.com/superserve-ai/sandbox/internal/qm/tenantstore"
)

func qmAPIStore(t *testing.T, pool *pgxpool.Pool) *tenantstore.Postgres {
	t.Helper()
	store, err := tenantstore.NewPostgres(context.Background(), pool)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	return store
}

// qmAPIPool is the pool qm-api runs on: the qm_api role, so every assertion
// goes through its grants, policies and the definer functions.
func qmAPIPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	if _, err := testPool.Exec(ctx, `ALTER ROLE qm_api PASSWORD '`+qmAPITestPassword+`'`); err != nil {
		t.Fatalf("set qm_api test password: %v", err)
	}
	cfg, err := pgxpool.ParseConfig(testDatabaseURL())
	if err != nil {
		t.Fatalf("parse database url: %v", err)
	}
	cfg.ConnConfig.User = "qm_api"
	cfg.ConnConfig.Password = qmAPITestPassword
	cfg.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("connect pool as qm_api: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func seedQMKey(t *testing.T, teamID uuid.UUID, name string, createdBy *uuid.UUID) (raw string, id uuid.UUID) {
	t.Helper()
	raw = "ss_live_" + uuid.NewString()
	params := db.CreateAPIKeyV2Params{TeamID: teamID, KeyHash: qm.HashAPIKey(raw), Name: name, Scopes: []string{}}
	if createdBy != nil {
		params.CreatedBy = pgtype.UUID{Bytes: *createdBy, Valid: true}
	}
	key, err := testQueries.CreateAPIKeyV2(context.Background(), params)
	if err != nil {
		t.Fatalf("create api key: %v", err)
	}
	return raw, key.ID
}

func seedQMMember(t *testing.T, teamID uuid.UUID, status string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	userID := uuid.New()
	if _, err := testPool.Exec(ctx, `INSERT INTO profile (id, email) VALUES ($1, $2)`, userID, userID.String()+"@example.com"); err != nil {
		t.Fatalf("insert profile: %v", err)
	}
	if status != "" {
		if _, err := testPool.Exec(ctx, `INSERT INTO team_memberships (team_id, user_id, status) VALUES ($1, $2, $3)`, teamID, userID, status); err != nil {
			t.Fatalf("insert membership: %v", err)
		}
	}
	return userID
}

func TestQMAPI_KeyResolverThroughDefinerFunction(t *testing.T) {
	ctx := context.Background()
	teamID, _ := seedQMTeamAndKey(t)
	resolver := qm.NewPostgresKeyResolver(qmAPIPool(t))

	rawPlain, keyID := seedQMKey(t, teamID, "sdk", nil)
	p, err := resolver.Resolve(ctx, qm.HashAPIKey(rawPlain))
	if err != nil || p.TeamID != teamID || p.KeyID != keyID || p.ReadOnly || p.ActorID != nil {
		t.Fatalf("plain key: %+v err=%v", p, err)
	}
	// No actor: authenticates, holds nothing.
	if ok, err := resolver.Can(ctx, p, qm.PermissionRead); err != nil || ok {
		t.Errorf("actorless key can read: ok=%v err=%v", ok, err)
	}
	// Usage is recorded through the definer function.
	resolver.Touch(ctx, p)
	deadline := time.Now().Add(5 * time.Second)
	for {
		var lastUsed *time.Time
		if err := testPool.QueryRow(ctx, `SELECT last_used_at FROM api_key WHERE id = $1`, keyID).Scan(&lastUsed); err != nil {
			t.Fatal(err)
		}
		if lastUsed != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("last_used_at not recorded")
		}
		time.Sleep(50 * time.Millisecond)
	}

	if _, err := resolver.Resolve(ctx, qm.HashAPIKey("ss_live_never_issued")); !errors.Is(err, qm.ErrKeyNotFound) {
		t.Errorf("unknown key: err = %v", err)
	}

	if err := testQueries.RevokeAPIKeyV2(ctx, keyID); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve(ctx, qm.HashAPIKey(rawPlain)); !errors.Is(err, qm.ErrKeyNotFound) {
		t.Errorf("revoked key: err = %v", err)
	}

	rawExpired, expiredID := seedQMKey(t, teamID, "sdk-expired", nil)
	if _, err := testPool.Exec(ctx, `UPDATE api_key SET expires_at = now() - interval '1 minute' WHERE id = $1`, expiredID); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve(ctx, qm.HashAPIKey(rawExpired)); !errors.Is(err, qm.ErrKeyNotFound) {
		t.Errorf("expired key: err = %v", err)
	}

	// Permissions come from the actor's team role, through the same query
	// the control plane runs.
	owner := seedQMMember(t, teamID, "active")
	seedTeamRoleAssignment(t, ctx, owner, mustRoleID(t, ctx, "team_owner"), teamID)
	rawOwner, _ := seedQMKey(t, teamID, "__console_proxy__", &owner)
	p, err = resolver.Resolve(ctx, qm.HashAPIKey(rawOwner))
	if err != nil || p.ActorID == nil || *p.ActorID != owner || p.ReadOnly {
		t.Fatalf("proxy key for an owner: %+v err=%v", p, err)
	}
	for perm, want := range map[string]bool{qm.PermissionRead: true, qm.PermissionWrite: true} {
		if ok, err := resolver.Can(ctx, p, perm); err != nil || ok != want {
			t.Errorf("owner %s: ok=%v err=%v want %v", perm, ok, err, want)
		}
	}

	viewer := seedQMMember(t, teamID, "active")
	seedTeamRoleAssignment(t, ctx, viewer, mustRoleID(t, ctx, "viewer"), teamID)
	rawViewer, _ := seedQMKey(t, teamID, "__console_proxy__", &viewer)
	p, err = resolver.Resolve(ctx, qm.HashAPIKey(rawViewer))
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := resolver.Can(ctx, p, qm.PermissionRead); !ok {
		t.Error("viewer cannot read")
	}
	if ok, _ := resolver.Can(ctx, p, qm.PermissionWrite); ok {
		t.Error("viewer can write")
	}

	// A former member keeps nothing, whatever role rows remain.
	former := seedQMMember(t, teamID, "active")
	seedTeamRoleAssignment(t, ctx, former, mustRoleID(t, ctx, "team_owner"), teamID)
	if _, err := testPool.Exec(ctx, `UPDATE team_memberships SET status = 'inactive' WHERE team_id = $1 AND user_id = $2`, teamID, former); err != nil {
		t.Fatal(err)
	}
	rawFormer, _ := seedQMKey(t, teamID, "__console_proxy__", &former)
	p, err = resolver.Resolve(ctx, qm.HashAPIKey(rawFormer))
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := resolver.Can(ctx, p, qm.PermissionRead); ok {
		t.Error("inactive member can read")
	}
	// A member of one team holds nothing in another.
	otherTeam, _ := seedQMTeamAndKey(t)
	if ok, _ := resolver.Can(ctx, qm.Principal{TeamID: otherTeam, ActorID: &owner}, qm.PermissionRead); ok {
		t.Error("owner of team A can read team B")
	}

	admin := seedQMMember(t, teamID, "")
	rawImp, _ := seedQMKey(t, teamID, "__console_impersonation__", &admin)
	p, err = resolver.Resolve(ctx, qm.HashAPIKey(rawImp))
	if err != nil || !p.ReadOnly || p.ActorID != nil {
		t.Fatalf("impersonation key: %+v err=%v", p, err)
	}
	if ok, _ := resolver.Can(ctx, p, qm.PermissionRead); ok {
		t.Error("impersonation key holds team permissions")
	}
}

func TestQMAPI_PostgresStoreRules(t *testing.T) {
	ctx := context.Background()
	teamA, _ := seedQMTeamAndKey(t)
	teamB, _ := seedQMTeamAndKey(t)
	store := qmAPIStore(t, qmAPIPool(t))
	slug := "pilot-team-" + uuid.NewString()[:8]
	create := tenantstore.CreateParams{Slug: slug, OrgName: "Pilot Team", AdminEmail: "admin@example.com", SignIn: "magic_link", ModelProvider: "anthropic"}

	tenant, err := store.CreateTenant(ctx, teamA, create)
	if err != nil || tenant.Status != tenantstore.StatusProvisioning || tenant.Harness != "pi" {
		t.Fatalf("create: %+v err=%v", tenant, err)
	}
	second := create
	second.Slug = "another-" + uuid.NewString()[:8]
	if _, err := store.CreateTenant(ctx, teamA, second); !errors.Is(err, tenantstore.ErrTeamHasTenant) {
		t.Errorf("second tenant for the team: err = %v", err)
	}
	if _, err := store.CreateTenant(ctx, teamB, create); !errors.Is(err, tenantstore.ErrSlugTaken) {
		t.Errorf("slug reuse across teams: err = %v", err)
	}
	if _, err := store.GetTenant(ctx, teamB, tenant.ID); !errors.Is(err, tenantstore.ErrNotFound) {
		t.Errorf("cross-team get: err = %v", err)
	}
	if ok, err := store.SlugAvailable(ctx, teamB, slug); err != nil || ok {
		t.Errorf("slug availability across teams: ok=%v err=%v", ok, err)
	}
	// A team detached by migration (no memberships here) is refused.
	detached, _ := seedQMTeamAndKey(t)
	if _, err := testPool.Exec(ctx, `DELETE FROM team_memberships WHERE team_id = $1`, detached); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateTenant(ctx, detached, second); !errors.Is(err, tenantstore.ErrTeamNotHomed) {
		t.Errorf("detached team: err = %v", err)
	}

	release, err := store.Lock(ctx, teamA, tenant.ID)
	if err != nil {
		t.Fatalf("lock: %v", err)
	}
	if _, err := store.Lock(ctx, teamA, tenant.ID); !errors.Is(err, tenantstore.ErrLocked) {
		t.Errorf("second lock: err = %v", err)
	}
	// Another tenant's lock is a different key: a run must never exit
	// because an unrelated tenant happens to be provisioning.
	bCreate := create
	bCreate.Slug = "pilot-team-" + uuid.NewString()[:8]
	bTenant, err := store.CreateTenant(ctx, teamB, bCreate)
	if err != nil {
		t.Fatalf("create tenant for team B: %v", err)
	}
	bRelease, err := store.Lock(ctx, teamB, bTenant.ID)
	if err != nil {
		t.Fatalf("lock a second tenant while the first is held: %v", err)
	}
	bRelease()
	release()
	release2, err := store.Lock(ctx, teamA, tenant.ID)
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	release2()

	if _, err := store.InsertEvent(ctx, teamA, tenantstore.EventParams{TenantID: tenant.ID, Step: "run", Status: "started", Message: "provision started", Detail: json.RawMessage(`{"mode":"provision"}`)}); err != nil {
		t.Fatalf("insert event: %v", err)
	}
	events, err := store.ListEvents(ctx, teamA, tenant.ID)
	if err != nil || len(events) != 1 || events[0].ID == uuid.Nil {
		t.Fatalf("events = %+v err=%v", events, err)
	}
	if _, err := store.TransitionStatus(ctx, teamA, tenant.ID, []string{tenantstore.StatusReady}, tenantstore.StatusDeprovisioning); !errors.Is(err, tenantstore.ErrStatusConflict) {
		t.Errorf("transition from a status the tenant is not in: err = %v", err)
	}
	if moved, err := store.TransitionStatus(ctx, teamA, tenant.ID, []string{tenantstore.StatusProvisioning, tenantstore.StatusFailed}, tenantstore.StatusFailed); err != nil || moved.Status != tenantstore.StatusFailed {
		t.Errorf("transition from the current status: %+v err=%v", moved, err)
	}
	if _, err := store.TransitionStatus(ctx, teamB, tenant.ID, []string{tenantstore.StatusFailed}, tenantstore.StatusReady); !errors.Is(err, tenantstore.ErrNotFound) {
		t.Errorf("cross-team transition: err = %v", err)
	}
	if _, err := store.SoftDelete(ctx, teamA, tenant.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.TransitionStatus(ctx, teamA, tenant.ID, []string{tenantstore.StatusDeleted}, tenantstore.StatusReady); !errors.Is(err, tenantstore.ErrNotFound) {
		t.Errorf("transition out of deleted: err = %v", err)
	}
	// A retired tenant's children are frozen: the policy refuses inserts.
	if _, err := store.InsertEvent(ctx, teamA, tenantstore.EventParams{TenantID: tenant.ID, Step: "run", Status: "ok"}); err == nil {
		t.Error("event insert on a deleted tenant succeeded")
	}
	if got, err := store.ListEvents(ctx, teamA, tenant.ID); err != nil || len(got) != 1 {
		t.Errorf("events of a deleted tenant: n=%d err=%v", len(got), err)
	}
	if _, err := store.SetStatus(ctx, teamA, tenant.ID, tenantstore.StatusReady); !errors.Is(err, tenantstore.ErrNotFound) {
		t.Errorf("status write after delete: err = %v", err)
	}
	// Deleted tenants no longer count against the one-per-team rule.
	if _, err := store.CreateTenant(ctx, teamA, second); err != nil {
		t.Errorf("create after delete: %v", err)
	}
}

func TestQMAPI_StubRunnerAgainstPostgres(t *testing.T) {
	ctx := context.Background()
	teamID, _ := seedQMTeamAndKey(t)
	store := qmAPIStore(t, qmAPIPool(t))
	fake := secrets.NewFake()
	slug := "pilot-team-" + uuid.NewString()[:8]
	tenant, err := store.CreateTenant(ctx, teamID, tenantstore.CreateParams{Slug: slug, OrgName: "Pilot Team", AdminEmail: "admin@example.com", SignIn: "magic_link", ModelProvider: "openai"})
	if err != nil {
		t.Fatal(err)
	}
	runner := &provisioner.Runner{
		Store: store,
		Env:   provisioner.Env{Project: "example-project", Region: "us-central1", BaseDomain: "qm.example.com", Image: "qm:test", Stub: true},
		Steps: steps.All(steps.Clients{Secrets: fake}),
		Log:   zerolog.Nop(),
	}
	if err := runner.Run(ctx, teamID, tenant.ID, provisioner.ModeProvision); err != nil {
		t.Fatalf("provision: %v", err)
	}
	row, err := store.GetTenant(ctx, teamID, tenant.ID)
	if err != nil || row.Status != tenantstore.StatusReady || row.PublicUrl == nil || *row.PublicUrl != "https://"+slug+".qm.example.com" || row.DbName == nil {
		t.Fatalf("after provision: %+v err=%v", row, err)
	}
	events, _ := store.ListEvents(ctx, teamID, tenant.ID)
	if len(events) == 0 || events[len(events)-1].Step != provisioner.RunStep || events[len(events)-1].Status != tenantstore.EventOK {
		t.Fatalf("events = %+v", events)
	}
	if _, err := store.SetStatus(ctx, teamID, tenant.ID, tenantstore.StatusDeprovisioning); err != nil {
		t.Fatal(err)
	}
	if err := runner.Run(ctx, teamID, tenant.ID, provisioner.ModeDeprovision); err != nil {
		t.Fatalf("deprovision: %v", err)
	}
	row, _ = store.GetTenant(ctx, teamID, tenant.ID)
	if row.Status != tenantstore.StatusDeleted {
		t.Errorf("after deprovision: status=%s", row.Status)
	}
	if refs, _ := store.ListSecretRefs(ctx, teamID, tenant.ID); len(refs) != 0 {
		t.Errorf("secret refs survived: %+v", refs)
	}
	if fake.Has("qm-" + slug + "-PORTAL_SESSION_SECRET") {
		t.Error("portal secret survived deprovision")
	}
}

func TestQMAPI_HTTPEndToEndInProcess(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx := context.Background()
	teamID, _ := seedQMTeamAndKey(t)
	member := seedQMMember(t, teamID, "active")
	seedTeamRoleAssignment(t, ctx, member, mustRoleID(t, ctx, "team_owner"), teamID)
	rawKey, _ := seedQMKey(t, teamID, "__console_proxy__", &member)
	pool := qmAPIPool(t)
	store := qmAPIStore(t, pool)
	fake := secrets.NewFake()
	runner := &provisioner.Runner{
		Store: store,
		Env:   provisioner.Env{Project: "example-project", Region: "us-central1", BaseDomain: "qm.example.com", Image: "qm:test", Stub: true},
		Steps: steps.All(steps.Clients{Secrets: fake}),
		Log:   zerolog.Nop(),
	}
	trigger := &provisioner.InProcess{Runner: runner, Log: zerolog.Nop()}
	h := &qm.Handlers{Store: store, Secrets: fake, Trigger: trigger, Log: zerolog.Nop()}
	router := qm.SetupRouter(h, qm.NewPostgresKeyResolver(pool), zerolog.Nop())

	do := func(method, path string, body any) (int, map[string]any) {
		var buf bytes.Buffer
		if body != nil {
			_ = json.NewEncoder(&buf).Encode(body)
		}
		req := httptest.NewRequest(method, path, &buf)
		req.Header.Set("X-API-Key", rawKey)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		out := map[string]any{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}

	slug := "pilot-team-" + uuid.NewString()[:8]
	code, body := do(http.MethodPost, "/v1/qm/tenants", map[string]any{
		"slug": slug, "orgName": "Pilot Team", "adminEmail": "admin@example.com",
		"signIn": "magic_link", "modelProvider": "anthropic", "modelKey": "sk-ant-integration-fixture-key",
	})
	if code != http.StatusAccepted {
		t.Fatalf("create: %d %v", code, body)
	}
	id := body["tenant"].(map[string]any)["id"].(string)
	trigger.Wait()

	code, body = do(http.MethodGet, "/v1/qm/tenants/"+id, nil)
	if code != http.StatusOK || body["tenant"].(map[string]any)["status"] != "ready" {
		t.Fatalf("get after provision: %d %v", code, body)
	}
	if !fake.Has("qm-" + slug + "-ANTHROPIC_API_KEY") {
		t.Error("model key not in the secret store")
	}
	var leaked bool
	for _, e := range body["events"].([]any) {
		raw, _ := json.Marshal(e)
		if bytes.Contains(raw, []byte("sk-ant-integration")) {
			leaked = true
		}
	}
	if leaked {
		t.Error("model key appears in the event log")
	}

	code, body = do(http.MethodPost, "/v1/qm/tenants/"+id+"/admin-link", nil)
	if code != http.StatusOK {
		t.Fatalf("admin link: %d %v", code, body)
	}
	secret, _ := fake.Get(ctx, "qm-"+slug+"-PORTAL_SESSION_SECRET")
	token, err := adminlink.TokenFromURL(body["url"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if adminlink.Verify(token, string(secret), "https://"+slug+".qm.example.com", time.Now()) == nil {
		t.Error("portal verifier rejected the minted link")
	}

	if code, body = do(http.MethodDelete, "/v1/qm/tenants/"+id, nil); code != http.StatusAccepted {
		t.Fatalf("delete: %d %v", code, body)
	}
	trigger.Wait()
	if code, _ = do(http.MethodGet, "/v1/qm/tenants/"+id, nil); code != http.StatusNotFound {
		t.Errorf("get after deprovision: %d, want 404", code)
	}
	if code, body = do(http.MethodGet, "/v1/qm/tenants", nil); code != http.StatusOK || len(body["tenants"].([]any)) != 0 {
		t.Errorf("list after deprovision: %d %v", code, body)
	}
}
