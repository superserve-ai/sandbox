//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

var (
	testPool         *pgxpool.Pool
	testQueries      *db.Queries
	testSystemTeamID uuid.UUID
)

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://postgres:postgres@localhost:5432/sandbox_test?sslmode=disable"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var err error
	testPool, err = pgxpool.New(ctx, dbURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot connect to test database: %v\n", err)
		os.Exit(1)
	}
	defer testPool.Close()

	if err := testPool.Ping(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "cannot ping test database: %v\n", err)
		os.Exit(1)
	}

	if err := resetTestSchema(ctx, testPool); err != nil {
		fmt.Fprintf(os.Stderr, "reset test schema: %v\n", err)
		os.Exit(1)
	}

	if err := applyMigrations(ctx, testPool); err != nil {
		fmt.Fprintf(os.Stderr, "migration failed: %v\n", err)
		os.Exit(1)
	}

	testQueries = db.New(testPool)

	if err := seedSystemTemplate(ctx, testQueries); err != nil {
		fmt.Fprintf(os.Stderr, "seed system template: %v\n", err)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

func resetTestSchema(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`)
	return err
}

// seedSystemTemplate creates the system team + a ready `superserve/base`
// template so CreateSandbox's default from_template lookup resolves. Every
// integration test that POSTs /sandboxes without an explicit from_template
// relies on this.
func seedSystemTemplate(ctx context.Context, q *db.Queries) error {
	team, err := q.CreateTeam(ctx, "superserve-system")
	if err != nil {
		return fmt.Errorf("create system team: %w", err)
	}
	testSystemTeamID = team.ID

	tpl, err := q.CreateTemplate(ctx, db.CreateTemplateParams{
		TeamID:    team.ID,
		Name:      "superserve/base",
		BuildSpec: []byte(`{"from":"test","steps":[]}`),
		Vcpu:      1,
		MemoryMib: 1024,
		DiskMib:   4096,
	})
	if err != nil {
		return fmt.Errorf("create superserve/base: %w", err)
	}

	// Flip to 'ready' with plausible paths so handlers.go's ready-check
	// passes. The stubVMD ignores these values.
	_, err = testPool.Exec(ctx,
		`UPDATE template SET status = 'ready',
		   rootfs_path = '/tmp/test/rootfs.ext4',
		   snapshot_path = '/tmp/test/vmstate.snap',
		   mem_path = '/tmp/test/mem.snap',
		   size_bytes = 0,
		   built_at = now()
		 WHERE id = $1`, tpl.ID)
	if err != nil {
		return fmt.Errorf("mark superserve/base ready: %w", err)
	}
	return nil
}

// applyMigrations reads SQL files from supabase/migrations/ and executes them
// in order against the test database. Uses IF NOT EXISTS / OR REPLACE so it is
// safe to run repeatedly against the same database.
func applyMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	// Walk up from the test file to the repo root (contains supabase/).
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, "supabase", "migrations")); err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return fmt.Errorf("could not find supabase/migrations from %s", dir)
		}
		dir = parent
	}

	entries, err := os.ReadDir(filepath.Join(dir, "supabase", "migrations"))
	if err != nil {
		return fmt.Errorf("read migrations dir: %w", err)
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, "supabase", "migrations", e.Name()))
		if err != nil {
			return fmt.Errorf("read %s: %w", e.Name(), err)
		}
		if _, err := pool.Exec(ctx, string(data)); err != nil {
			return fmt.Errorf("exec %s: %w", e.Name(), err)
		}
	}
	return nil
}

// stubVMD satisfies VMDClient without a real VM daemon. Stubs return plausible
// values so that HTTP handlers can complete and write to the DB.
type stubVMD struct{}

func (s *stubVMD) DestroyInstance(_ context.Context, _ string, _ bool) error { return nil }
func (s *stubVMD) PauseInstance(_ context.Context, _, _ string) (string, string, error) {
	return "/snapshots/disk.snap", "/snapshots/mem.snap", nil
}
func (s *stubVMD) ResumeInstance(_ context.Context, _, _, _ string) (string, uint32, uint32, error) {
	return "10.0.0.1", 1, 1024, nil
}
func (s *stubVMD) RestoreSnapshot(_ context.Context, _, _, _, _, _, _, _ string, _ map[string]string) (string, uint32, uint32, error) {
	return "10.0.0.1", 1, 1024, nil
}
func (s *stubVMD) InjectSandboxEnv(_ context.Context, _ string, _ map[string]string, _ string) error {
	return nil
}
func (s *stubVMD) ListDir(_ context.Context, _, _ string) ([]vmdclient.DirEntry, error) {
	return nil, nil
}
func (s *stubVMD) UpdateSandboxNetwork(_ context.Context, _ string, _, _, _ []string) error {
	return nil
}
func (s *stubVMD) InvalidateSecret(_ context.Context, _ string) error        { return nil }
func (s *stubVMD) RevokeSandbox(_ context.Context, _ string) error           { return nil }
func (s *stubVMD) InvalidateSandboxRules(_ context.Context, _ string) error  { return nil }
func (s *stubVMD) DeleteSnapshot(_ context.Context, _, _, _ string) error    { return nil }
func (s *stubVMD) DeleteSandboxSnapshots(_ context.Context, _ string) error  { return nil }
func (s *stubVMD) DeleteTemplateArtifacts(_ context.Context, _ string) error { return nil }
func (s *stubVMD) DeleteBuildArtifacts(_ context.Context, _, _ string) error { return nil }
func (s *stubVMD) ListBuildArtifacts(_ context.Context) ([]vmdclient.BuildArtifactEntry, error) {
	return nil, nil
}

func (s *stubVMD) BuildTemplate(_ context.Context, _ vmdclient.BuildTemplateInput) (string, error) {
	return "build-stub", nil
}
func (s *stubVMD) GetBuildStatus(_ context.Context, _ string) (vmdclient.BuildStatusResult, error) {
	return vmdclient.BuildStatusResult{Status: "ready"}, nil
}
func (s *stubVMD) CancelBuild(_ context.Context, _ string) error { return nil }
func (s *stubVMD) StreamBuildLogs(_ context.Context, _ string, _ func(vmdclient.BuildLogEvent) error) error {
	return nil
}

// seedTeamAndKey inserts a team owner plus API key pair.
// Most integration tests exercise high-risk endpoints and need write access.
func seedTeamAndKey(t *testing.T) (uuid.UUID, string) {
	teamID, rawKey, _ := seedTeamAndKeyWithRole(t, "team_owner")
	return teamID, rawKey
}

// seedTeamAndKeyWithRole inserts a team, owner profile, active membership, and
// API key for the requested team role. Returns (teamID, rawKey, profileID).
func seedTeamAndKeyWithRole(t *testing.T, roleName string) (uuid.UUID, string, uuid.UUID) {
	t.Helper()
	ctx := context.Background()

	team, err := testQueries.CreateTeam(ctx, "team-"+uuid.New().String()[:8])
	if err != nil {
		t.Fatalf("seedTeamAndKeyWithRole: create team: %v", err)
	}

	profileID := uuid.New()
	if _, err := testPool.Exec(ctx,
		`INSERT INTO profile (id, email, provider, provider_id) VALUES ($1, $2, 'google', $3)`,
		profileID,
		fmt.Sprintf("%s-%s@example.com", roleName, profileID.String()[:8]),
		"google-"+profileID.String()[:8],
	); err != nil {
		t.Fatalf("seedTeamAndKeyWithRole: insert profile: %v", err)
	}
	if _, err := testPool.Exec(ctx,
		`INSERT INTO team_memberships (team_id, user_id, status) VALUES ($1, $2, 'active')`,
		team.ID,
		profileID,
	); err != nil {
		t.Fatalf("seedTeamAndKeyWithRole: insert membership: %v", err)
	}
	roleID, err := roleIDByName(ctx, roleName)
	if err != nil {
		t.Fatalf("seedTeamAndKeyWithRole: lookup role %s: %v", roleName, err)
	}
	if _, err := testPool.Exec(ctx,
		`INSERT INTO user_role_assignments (user_id, role_id, scope_type, team_id) VALUES ($1, $2, 'team', $3)`,
		profileID,
		roleID,
		team.ID,
	); err != nil {
		t.Fatalf("seedTeamAndKeyWithRole: insert assignment: %v", err)
	}

	rawKey := "sk-test-" + uuid.New().String()
	hash := sha256.Sum256([]byte(rawKey))
	keyHash := hex.EncodeToString(hash[:])

	_, err = testQueries.CreateAPIKeyV2(ctx, db.CreateAPIKeyV2Params{
		TeamID:    team.ID,
		KeyHash:   keyHash,
		Name:      "test-key",
		Scopes:    []string{},
		CreatedBy: pgtype.UUID{Bytes: profileID, Valid: true},
	})
	if err != nil {
		t.Fatalf("seedTeamAndKeyWithRole: create api key: %v", err)
	}

	return team.ID, rawKey, profileID
}

func seedKeyForExistingTeamWithRole(t *testing.T, teamID uuid.UUID, roleName string) string {
	t.Helper()
	ctx := context.Background()

	profileID := uuid.New()
	if _, err := testPool.Exec(ctx,
		`INSERT INTO profile (id, email, provider, provider_id) VALUES ($1, $2, 'google', $3)`,
		profileID,
		fmt.Sprintf("%s-%s@example.com", roleName, profileID.String()[:8]),
		"google-"+profileID.String()[:8],
	); err != nil {
		t.Fatalf("seedKeyForExistingTeamWithRole: insert profile: %v", err)
	}
	if _, err := testPool.Exec(ctx,
		`INSERT INTO team_memberships (team_id, user_id, status) VALUES ($1, $2, 'active')`,
		teamID,
		profileID,
	); err != nil {
		t.Fatalf("seedKeyForExistingTeamWithRole: insert membership: %v", err)
	}
	roleID, err := roleIDByName(ctx, roleName)
	if err != nil {
		t.Fatalf("seedKeyForExistingTeamWithRole: lookup role %s: %v", roleName, err)
	}
	if _, err := testPool.Exec(ctx,
		`INSERT INTO user_role_assignments (user_id, role_id, scope_type, team_id) VALUES ($1, $2, 'team', $3)`,
		profileID,
		roleID,
		teamID,
	); err != nil {
		t.Fatalf("seedKeyForExistingTeamWithRole: insert assignment: %v", err)
	}

	rawKey := "sk-test-" + uuid.New().String()
	hash := sha256.Sum256([]byte(rawKey))
	keyHash := hex.EncodeToString(hash[:])

	_, err = testQueries.CreateAPIKeyV2(ctx, db.CreateAPIKeyV2Params{
		TeamID:    teamID,
		KeyHash:   keyHash,
		Name:      "test-key",
		Scopes:    []string{},
		CreatedBy: pgtype.UUID{Bytes: profileID, Valid: true},
	})
	if err != nil {
		t.Fatalf("seedKeyForExistingTeamWithRole: create api key: %v", err)
	}

	return rawKey
}

// seedTeamAndKeyNoCreator inserts a team/API key pair without a creator profile.
// Use this only for tests that explicitly verify null actor attribution.
func seedTeamAndKeyNoCreator(t *testing.T) (uuid.UUID, string) {
	t.Helper()
	ctx := context.Background()

	team, err := testQueries.CreateTeam(ctx, "team-"+uuid.New().String()[:8])
	if err != nil {
		t.Fatalf("seedTeamAndKeyNoCreator: create team: %v", err)
	}

	rawKey := "sk-test-" + uuid.New().String()
	hash := sha256.Sum256([]byte(rawKey))
	keyHash := hex.EncodeToString(hash[:])

	_, err = testQueries.CreateAPIKeyV2(ctx, db.CreateAPIKeyV2Params{
		TeamID:  team.ID,
		KeyHash: keyHash,
		Name:    "test-key",
		Scopes:  []string{},
	})
	if err != nil {
		t.Fatalf("seedTeamAndKeyNoCreator: create api key: %v", err)
	}

	return team.ID, rawKey
}

func seedConsoleImpersonationKey(t *testing.T, teamID uuid.UUID, scopes []string, expiresAt *time.Time) string {
	t.Helper()
	ctx := context.Background()

	rawKey := "sk-test-" + uuid.New().String()
	hash := sha256.Sum256([]byte(rawKey))
	keyHash := hex.EncodeToString(hash[:])

	params := db.CreateAPIKeyV2Params{
		TeamID:  teamID,
		KeyHash: keyHash,
		Name:    "__console_impersonation__",
		Scopes:  append([]string{}, scopes...),
	}
	if expiresAt != nil {
		params.ExpiresAt = pgtype.Timestamptz{Time: *expiresAt, Valid: true}
	}

	if _, err := testQueries.CreateAPIKeyV2(ctx, params); err != nil {
		t.Fatalf("seedConsoleImpersonationKey: create api key: %v", err)
	}

	return rawKey
}

// seedTeamKeyAndProfile is like seedTeamAndKey but also seeds a profile row
// and sets api_key.created_by to it. Returns (teamID, rawKey, profileID).
func seedTeamKeyAndProfile(t *testing.T) (uuid.UUID, string, uuid.UUID) {
	t.Helper()
	ctx := context.Background()

	team, err := testQueries.CreateTeam(ctx, "team-"+uuid.New().String()[:8])
	if err != nil {
		t.Fatalf("seedTeamKeyAndProfile: create team: %v", err)
	}

	profileID := uuid.New()
	if _, err := testPool.Exec(ctx,
		`INSERT INTO profile (id, email) VALUES ($1, $2)`,
		profileID, fmt.Sprintf("test-%s@example.com", profileID.String()[:8]),
	); err != nil {
		t.Fatalf("seedTeamKeyAndProfile: insert profile: %v", err)
	}
	if _, err := testPool.Exec(ctx,
		`INSERT INTO team_memberships (team_id, user_id, status) VALUES ($1, $2, 'active')`,
		team.ID,
		profileID,
	); err != nil {
		t.Fatalf("seedTeamKeyAndProfile: insert membership: %v", err)
	}
	roleID, err := roleIDByName(ctx, "team_owner")
	if err != nil {
		t.Fatalf("seedTeamKeyAndProfile: lookup role team_owner: %v", err)
	}
	if _, err := testPool.Exec(ctx,
		`INSERT INTO user_role_assignments (user_id, role_id, scope_type, team_id) VALUES ($1, $2, 'team', $3)`,
		profileID,
		roleID,
		team.ID,
	); err != nil {
		t.Fatalf("seedTeamKeyAndProfile: insert assignment: %v", err)
	}

	rawKey := "sk-test-" + uuid.New().String()
	hash := sha256.Sum256([]byte(rawKey))
	keyHash := hex.EncodeToString(hash[:])

	_, err = testQueries.CreateAPIKeyV2(ctx, db.CreateAPIKeyV2Params{
		TeamID:    team.ID,
		KeyHash:   keyHash,
		Name:      "test-key",
		Scopes:    []string{},
		CreatedBy: pgtype.UUID{Bytes: profileID, Valid: true},
	})
	if err != nil {
		t.Fatalf("seedTeamKeyAndProfile: create api key: %v", err)
	}

	return team.ID, rawKey, profileID
}

func roleIDByName(ctx context.Context, roleName string) (uuid.UUID, error) {
	var id uuid.UUID
	if err := testPool.QueryRow(ctx, `SELECT id FROM roles WHERE name = $1`, roleName).Scan(&id); err != nil {
		return uuid.Nil, err
	}
	return id, nil
}

// newRouter builds a router scoped to the current test. Using t.Context()
// ensures the rate limiter's cleanup goroutine exits when the test ends,
// preventing goroutine leaks across hundreds of test invocations.
// testHandlers tracks every api.Handlers built for a test router so do()/
// doBinary() can wait for fire-and-forget bookkeeping writes (ActivateSandbox,
// FinalizePause) after each request. Integration tests chain lifecycle calls
// (create → pause → resume) and assert DB state right after a response, so
// they rely on transitions having landed; the async window itself is covered
// by unit tests. Tests here never run in parallel, so a plain slice is fine.
var testHandlers []*api.Handlers

func registerTestHandlers(h *api.Handlers) {
	testHandlers = append(testHandlers, h)
}

func waitBookkeeping() {
	for _, h := range testHandlers {
		h.WaitAsyncBookkeeping()
	}
}

func newRouter(t *testing.T) *gin.Engine {
	t.Helper()
	cfg := &config.Config{
		Port:         "0",
		VMDAddress:   "localhost:0",
		SystemTeamID: testSystemTeamID.String(),
	}
	h := api.NewHandlers(&stubVMD{}, testQueries, cfg)
	h.Pool = testPool
	registerTestHandlers(h)
	return api.SetupRouter(t.Context(), h, testPool)
}

func do(r *gin.Engine, method, path, apiKey, body string) *httptest.ResponseRecorder {
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, bodyReader)
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	waitBookkeeping()
	return w
}

func doBinary(r *gin.Engine, method, path, apiKey string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/octet-stream")
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	waitBookkeeping()
	return w
}

func mustJSON(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("parse JSON: %v\nbody: %s", err, w.Body.String())
	}
	return m
}

func assertFloatNear(t *testing.T, got, want float64) {
	t.Helper()
	if math.Abs(got-want) > 0.000000000001 {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestIntegration_Auth_HealthNoKeyRequired(t *testing.T) {
	w := do(newRouter(t), "GET", "/health", "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("health: expected 200, got %d", w.Code)
	}
}

func TestIntegration_Auth_MissingKey(t *testing.T) {
	w := do(newRouter(t), "POST", "/sandboxes", "", `{"name":"x"}`)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestIntegration_Auth_InvalidKey(t *testing.T) {
	w := do(newRouter(t), "POST", "/sandboxes", "sk-does-not-exist", `{"name":"x"}`)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestIntegration_Auth_RevokedKey(t *testing.T) {
	ctx := context.Background()
	_, rawKey := seedTeamAndKey(t)

	hash := sha256.Sum256([]byte(rawKey))
	keyHash := hex.EncodeToString(hash[:])
	rec, err := testQueries.GetAPIKeyByHashV2(ctx, keyHash)
	if err != nil {
		t.Fatalf("get key: %v", err)
	}
	if err := testQueries.RevokeAPIKeyV2(ctx, rec.ID); err != nil {
		t.Fatalf("revoke key: %v", err)
	}

	w := do(newRouter(t), "POST", "/sandboxes", rawKey, `{"name":"x"}`)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestIntegration_GetBillingPricing(t *testing.T) {
	teamID, apiKey, _ := seedTeamAndKeyWithRole(t, "viewer")
	r := newRouter(t)

	w := do(r, "GET", "/billing/pricing?team_id="+teamID.String(), apiKey, "")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if got := w.Header().Get("Cache-Control"); got != "private, max-age=60" {
		t.Fatalf("Cache-Control = %q, want private, max-age=60", got)
	}
	if got := w.Header().Get("Vary"); got != "X-API-Key" {
		t.Fatalf("Vary = %q, want X-API-Key", got)
	}

	body := decodeBillingPricingResponse(t, w)
	assertPaygPricingResponse(t, body)
}

func TestIntegration_GetPublicBillingPricing(t *testing.T) {
	w := do(newRouter(t), "GET", "/billing/pricing/public", "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if got := w.Header().Get("Cache-Control"); got != "public, max-age=300, s-maxage=300" {
		t.Fatalf("Cache-Control = %q, want public, max-age=300, s-maxage=300", got)
	}
	if got := w.Header().Get("Vary"); got != "" {
		t.Fatalf("Vary = %q, want empty", got)
	}

	body := decodeBillingPricingResponse(t, w)
	assertPaygPricingResponse(t, body)
}

func TestIntegration_GetBillingPricingUsesNewestEffectiveRate(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey, _ := seedTeamAndKeyWithRole(t, "viewer")
	planKey := "test-plan-" + uuid.New().String()
	now := time.Now().UTC()

	if _, err := testPool.Exec(ctx, `
		INSERT INTO pricing_plan (key, name, currency, active)
		VALUES ($1, 'Integration test pricing', 'USD', true)
	`, planKey); err != nil {
		t.Fatalf("insert pricing plan: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO pricing_rate (plan_key, resource, unit, price_usd, effective_from)
		VALUES
			($1, 'vcpu', 'second', 0.000011, $2),
			($1, 'vcpu', 'second', 0.000022, $3),
			($1, 'memory_gib', 'second', 0.0000045, $2),
			($1, 'storage_gib', 'second', 0.00000003, $2)
	`, planKey, now.Add(-2*time.Hour), now.Add(-time.Hour)); err != nil {
		t.Fatalf("insert pricing rates: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_pricing_plan (team_id, plan_key, effective_from)
		VALUES ($1, $2, $3)
	`, teamID, planKey, now.Add(-3*time.Hour)); err != nil {
		t.Fatalf("assign pricing plan: %v", err)
	}

	w := do(newRouter(t), "GET", "/billing/pricing", apiKey, "")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeBillingPricingResponse(t, w)
	if body.PlanKey != planKey {
		t.Fatalf("plan_key = %q, want %q", body.PlanKey, planKey)
	}
	if len(body.Rates) != 3 {
		t.Fatalf("rates length = %d, want 3", len(body.Rates))
	}
	rates := billingRatesByResource(t, body)
	assertFloatNear(t, rates["vcpu"].PriceUSD, 0.000022)
}

func TestIntegration_GetBillingPricingMissingRequiredRateReturns503(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey, _ := seedTeamAndKeyWithRole(t, "viewer")
	planKey := "missing-rate-plan-" + uuid.New().String()
	now := time.Now().UTC()

	if _, err := testPool.Exec(ctx, `
		INSERT INTO pricing_plan (key, name, currency, active)
		VALUES ($1, 'Missing rate integration pricing', 'USD', true)
	`, planKey); err != nil {
		t.Fatalf("insert pricing plan: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO pricing_rate (plan_key, resource, unit, price_usd, effective_from)
		VALUES
			($1, 'vcpu', 'second', 0.000011, $2),
			($1, 'memory_gib', 'second', 0.0000045, $2)
	`, planKey, now.Add(-time.Hour)); err != nil {
		t.Fatalf("insert incomplete pricing rates: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_pricing_plan (team_id, plan_key, effective_from)
		VALUES ($1, $2, $3)
	`, teamID, planKey, now.Add(-time.Hour)); err != nil {
		t.Fatalf("assign pricing plan: %v", err)
	}

	w := do(newRouter(t), "GET", "/billing/pricing", apiKey, "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for missing required rate, got %d: %s", w.Code, w.Body.String())
	}
}

func TestIntegration_GetPublicBillingPricingInactivePaygReturns503(t *testing.T) {
	ctx := context.Background()
	if _, err := testPool.Exec(ctx, `UPDATE pricing_plan SET active = false WHERE key = 'payg'`); err != nil {
		t.Fatalf("deactivate payg: %v", err)
	}
	defer func() {
		if _, err := testPool.Exec(context.Background(), `UPDATE pricing_plan SET active = true WHERE key = 'payg'`); err != nil {
			t.Fatalf("restore payg: %v", err)
		}
	}()

	w := do(newRouter(t), "GET", "/billing/pricing/public", "", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for inactive payg pricing, got %d: %s", w.Code, w.Body.String())
	}
}

func TestIntegration_GetBillingPricingInactiveTeamPlanFallsBackToPayg(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey, _ := seedTeamAndKeyWithRole(t, "viewer")
	planKey := "inactive-plan-" + uuid.New().String()
	now := time.Now().UTC()

	if _, err := testPool.Exec(ctx, `
		INSERT INTO pricing_plan (key, name, currency, active)
		VALUES ($1, 'Inactive integration pricing', 'USD', false)
	`, planKey); err != nil {
		t.Fatalf("insert inactive pricing plan: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO pricing_rate (plan_key, resource, unit, price_usd, effective_from)
		VALUES
			($1, 'vcpu', 'second', 0.000099, $2),
			($1, 'memory_gib', 'second', 0.000099, $2),
			($1, 'storage_gib', 'second', 0.000099, $2)
	`, planKey, now.Add(-time.Hour)); err != nil {
		t.Fatalf("insert inactive pricing rates: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_pricing_plan (team_id, plan_key, effective_from)
		VALUES ($1, $2, $3)
	`, teamID, planKey, now.Add(-time.Hour)); err != nil {
		t.Fatalf("assign inactive pricing plan: %v", err)
	}

	w := do(newRouter(t), "GET", "/billing/pricing", apiKey, "")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 fallback to payg, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeBillingPricingResponse(t, w)
	assertPaygPricingResponse(t, body)
}

type billingPricingTestResponse struct {
	PlanKey  string `json:"plan_key"`
	PlanName string `json:"plan_name"`
	Currency string `json:"currency"`
	Rates    []struct {
		Resource       string  `json:"resource"`
		Unit           string  `json:"unit"`
		PriceUSD       float64 `json:"price_usd"`
		PriceUSDHourly float64 `json:"price_usd_hourly"`
	} `json:"rates"`
}

func decodeBillingPricingResponse(t *testing.T, w *httptest.ResponseRecorder) billingPricingTestResponse {
	t.Helper()
	var body billingPricingTestResponse
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse pricing response: %v\nbody: %s", err, w.Body.String())
	}
	return body
}

func assertPaygPricingResponse(t *testing.T, body billingPricingTestResponse) {
	t.Helper()
	if body.PlanKey != "payg" {
		t.Fatalf("plan_key = %q, want payg", body.PlanKey)
	}
	if body.PlanName != "Pay-as-you-go" {
		t.Fatalf("plan_name = %q, want Pay-as-you-go", body.PlanName)
	}
	if body.Currency != "USD" {
		t.Fatalf("currency = %q, want USD", body.Currency)
	}
	if len(body.Rates) != 3 {
		t.Fatalf("rates length = %d, want 3", len(body.Rates))
	}

	rates := billingRatesByResource(t, body)
	for resource, want := range map[string]struct {
		price      float64
		hourlyRate float64
	}{
		"vcpu":        {price: 0.000014, hourlyRate: 0.0504},
		"memory_gib":  {price: 0.0000045, hourlyRate: 0.0162},
		"storage_gib": {price: 0.00000003, hourlyRate: 0.000108},
	} {
		got, ok := rates[resource]
		if !ok {
			t.Fatalf("missing pricing rate for %s", resource)
		}
		if got.Unit != "second" {
			t.Fatalf("%s unit = %q, want second", resource, got.Unit)
		}
		assertFloatNear(t, got.PriceUSD, want.price)
		assertFloatNear(t, got.PriceUSDHourly, want.hourlyRate)
	}
}

func billingRatesByResource(t *testing.T, body billingPricingTestResponse) map[string]struct {
	Resource       string
	Unit           string
	PriceUSD       float64
	PriceUSDHourly float64
} {
	t.Helper()
	rates := make(map[string]struct {
		Resource       string
		Unit           string
		PriceUSD       float64
		PriceUSDHourly float64
	}, len(body.Rates))
	for _, rate := range body.Rates {
		if _, exists := rates[rate.Resource]; exists {
			t.Fatalf("duplicate pricing rate for %s", rate.Resource)
		}
		rates[rate.Resource] = struct {
			Resource       string
			Unit           string
			PriceUSD       float64
			PriceUSDHourly float64
		}{
			Resource:       rate.Resource,
			Unit:           rate.Unit,
			PriceUSD:       rate.PriceUSD,
			PriceUSDHourly: rate.PriceUSDHourly,
		}
	}
	return rates
}

func TestIntegration_CreateSandbox_Success(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	w := do(r, "POST", "/sandboxes", apiKey, `{"name":"my-box"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	body := mustJSON(t, w)
	sandboxID, _ := uuid.Parse(body["id"].(string))
	if sandboxID == uuid.Nil {
		t.Fatal("response missing valid id")
	}
	if body["name"] != "my-box" {
		t.Errorf("name = %q, want my-box", body["name"])
	}
	if body["status"] != "active" {
		t.Errorf("status = %q, want active", body["status"])
	}

	// DB record is active immediately since creation is synchronous.
	sb, err := testQueries.GetSandbox(ctx, db.GetSandboxParams{ID: sandboxID, TeamID: teamID})
	if err != nil {
		t.Fatalf("sandbox not found in DB: %v", err)
	}
	if sb.VcpuCount != 1 {
		t.Errorf("vcpu_count = %d, want 1", sb.VcpuCount)
	}
	if sb.MemoryMib != 1024 {
		t.Errorf("memory_mib = %d, want 1024", sb.MemoryMib)
	}
}

func TestIntegration_ListSandboxes(t *testing.T) {
	_, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	// Create two sandboxes.
	for i, name := range []string{"list-box-1", "list-box-2"} {
		cw := do(r, "POST", "/sandboxes", apiKey, fmt.Sprintf(`{"name":%q}`, name))
		if cw.Code != http.StatusCreated {
			t.Fatalf("create[%d]: %d %s", i, cw.Code, cw.Body.String())
		}
	}

	lw := do(r, "GET", "/sandboxes", apiKey, "")
	if lw.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d: %s", lw.Code, lw.Body.String())
	}

	var list []map[string]interface{}
	if err := json.Unmarshal(lw.Body.Bytes(), &list); err != nil {
		t.Fatalf("parse list response: %v", err)
	}
	if len(list) < 2 {
		t.Errorf("expected at least 2 sandboxes, got %d", len(list))
	}
	// Every item must have an id and a status.
	for _, item := range list {
		if item["id"] == nil {
			t.Error("list item missing id")
		}
		if item["status"] == nil {
			t.Error("list item missing status")
		}
	}
}

func TestIntegration_GetSandbox(t *testing.T) {
	_, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"get-box"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", cw.Code, cw.Body.String())
	}
	sid := mustJSON(t, cw)["id"].(string)

	gw := do(r, "GET", "/sandboxes/"+sid, apiKey, "")
	if gw.Code != http.StatusOK {
		t.Fatalf("get: expected 200, got %d: %s", gw.Code, gw.Body.String())
	}
	gb := mustJSON(t, gw)
	if gb["id"] != sid {
		t.Errorf("id = %q, want %q", gb["id"], sid)
	}
	if gb["name"] != "get-box" {
		t.Errorf("name = %q, want get-box", gb["name"])
	}
}

func TestIntegration_GetSandbox_NotFound(t *testing.T) {
	_, apiKey := seedTeamAndKey(t)
	w := do(newRouter(t), "GET", "/sandboxes/"+uuid.New().String(), apiKey, "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestIntegration_ListSandboxes_TeamIsolation(t *testing.T) {
	_, apiKeyA := seedTeamAndKey(t)
	_, apiKeyB := seedTeamAndKey(t)
	r := newRouter(t)

	// Team A creates a sandbox.
	cw := do(r, "POST", "/sandboxes", apiKeyA, `{"name":"iso-list-box"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", cw.Code, cw.Body.String())
	}
	sid := mustJSON(t, cw)["id"].(string)

	// Team B list should not include team A's sandbox.
	lw := do(r, "GET", "/sandboxes", apiKeyB, "")
	if lw.Code != http.StatusOK {
		t.Fatalf("list: %d", lw.Code)
	}
	var list []map[string]interface{}
	json.Unmarshal(lw.Body.Bytes(), &list) //nolint:errcheck
	for _, item := range list {
		if item["id"] == sid {
			t.Error("team B can see team A's sandbox in list — isolation broken")
		}
	}
}

func TestIntegration_CreateSandbox_ValidationError(t *testing.T) {
	_, apiKey := seedTeamAndKey(t)
	// Missing required fields.
	w := do(newRouter(t), "POST", "/sandboxes", apiKey, `{}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestIntegration_PauseSandbox_Success(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"pause-box"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", cw.Code, cw.Body.String())
	}
	sid := mustJSON(t, cw)["id"].(string)

	pw := do(r, "POST", "/sandboxes/"+sid+"/pause", apiKey, "")
	if pw.Code != http.StatusNoContent {
		t.Fatalf("pause: expected 204, got %d: %s", pw.Code, pw.Body.String())
	}

	// DB: sandbox is paused, snapshot record exists and is linked.
	sandboxID, _ := uuid.Parse(sid)
	sb, err := testQueries.GetSandbox(ctx, db.GetSandboxParams{ID: sandboxID, TeamID: teamID})
	if err != nil {
		t.Fatalf("get sandbox: %v", err)
	}
	if sb.Status != db.SandboxStatusPaused {
		t.Errorf("DB status = %q, want paused", sb.Status)
	}
	if !sb.SnapshotID.Valid {
		t.Fatal("sandbox snapshot_id should be set after pause")
	}

	snapID := uuid.UUID(sb.SnapshotID.Bytes)
	snap, err := testQueries.GetSnapshot(ctx, db.GetSnapshotParams{ID: snapID, TeamID: teamID})
	if err != nil {
		t.Fatalf("snapshot not found in DB: %v", err)
	}
	if snap.Path != "/snapshots/disk.snap" {
		t.Errorf("snapshot path = %q, want /snapshots/disk.snap", snap.Path)
	}
	if snap.Trigger != "pause" {
		t.Errorf("snapshot trigger = %q, want pause", snap.Trigger)
	}
}

func TestIntegration_PauseSandbox_AlreadyPaused(t *testing.T) {
	_, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"paused-box"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d", cw.Code)
	}
	sid := mustJSON(t, cw)["id"].(string)

	do(r, "POST", "/sandboxes/"+sid+"/pause", apiKey, "") // first pause

	w := do(r, "POST", "/sandboxes/"+sid+"/pause", apiKey, "") // second pause → conflict
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409 on double-pause, got %d: %s", w.Code, w.Body.String())
	}
}

func TestIntegration_ResumeSandbox_Success(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"resume-box"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", cw.Code, cw.Body.String())
	}
	sid := mustJSON(t, cw)["id"].(string)
	pw := do(r, "POST", "/sandboxes/"+sid+"/pause", apiKey, "")
	if pw.Code != http.StatusNoContent {
		t.Fatalf("pause: %d %s", pw.Code, pw.Body.String())
	}

	rw := do(r, "POST", "/sandboxes/"+sid+"/resume", apiKey, "")
	if rw.Code != http.StatusOK {
		t.Fatalf("resume: expected 200, got %d: %s", rw.Code, rw.Body.String())
	}
	if mustJSON(t, rw)["status"] != "active" {
		t.Errorf("resume status = %q, want active", mustJSON(t, rw)["status"])
	}

	// DB: active again.
	time.Sleep(50 * time.Millisecond)
	sandboxID, _ := uuid.Parse(sid)
	sb, err := testQueries.GetSandbox(ctx, db.GetSandboxParams{ID: sandboxID, TeamID: teamID})
	if err != nil {
		t.Fatalf("get sandbox: %v", err)
	}
	if sb.Status != db.SandboxStatusActive {
		t.Errorf("DB status = %q, want active", sb.Status)
	}
}

func TestIntegration_ResumeSandbox_QuotaBlocked(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	// Cap the team at a single active sandbox.
	if _, err := testPool.Exec(ctx, `UPDATE team SET max_sandboxes = 1 WHERE id = $1`, teamID); err != nil {
		t.Fatalf("set max_sandboxes: %v", err)
	}

	// Create A, then pause it — under active-only counting this frees the slot.
	cwA := do(r, "POST", "/sandboxes", apiKey, `{"name":"box-a"}`)
	if cwA.Code != http.StatusCreated {
		t.Fatalf("create A: %d %s", cwA.Code, cwA.Body.String())
	}
	sidA := mustJSON(t, cwA)["id"].(string)
	if pw := do(r, "POST", "/sandboxes/"+sidA+"/pause", apiKey, ""); pw.Code != http.StatusNoContent {
		t.Fatalf("pause A: %d %s", pw.Code, pw.Body.String())
	}

	cwB := do(r, "POST", "/sandboxes", apiKey, `{"name":"box-b"}`)
	if cwB.Code != http.StatusCreated {
		t.Fatalf("create B (slot should be free after pausing A): %d %s", cwB.Code, cwB.Body.String())
	}

	// Resuming A would exceed the cap → 429, A stays paused.
	rw := do(r, "POST", "/sandboxes/"+sidA+"/resume", apiKey, "")
	if rw.Code != http.StatusTooManyRequests {
		t.Fatalf("resume A: expected 429, got %d: %s", rw.Code, rw.Body.String())
	}

	sandboxIDA, _ := uuid.Parse(sidA)
	sb, err := testQueries.GetSandbox(ctx, db.GetSandboxParams{ID: sandboxIDA, TeamID: teamID})
	if err != nil {
		t.Fatalf("get A: %v", err)
	}
	if sb.Status != db.SandboxStatusPaused {
		t.Errorf("A status = %q, want paused (resume must be rejected)", sb.Status)
	}
}

// Quota frees the slot at BeginPause ('pausing' left the counted set), so the
// documented pause-then-create workflow can't transiently 429 while the
// fire-and-forget FinalizePause is still in flight. Exercise the window
// directly: gate write only, no finalize, then create at the cap.
func TestIntegration_QuotaSlotFreedAtBeginPause(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	if _, err := testPool.Exec(ctx, `UPDATE team SET max_sandboxes = 1 WHERE id = $1`, teamID); err != nil {
		t.Fatalf("set max_sandboxes: %v", err)
	}

	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"gate-a"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create A: %d %s", cw.Code, cw.Body.String())
	}
	sandboxID := uuid.MustParse(mustJSON(t, cw)["id"].(string))

	// The pause gate write alone — FinalizePause deliberately never runs,
	// simulating the async bookkeeping still in flight (or lost to a crash).
	if _, err := testQueries.BeginPause(ctx, db.BeginPauseParams{ID: sandboxID, TeamID: teamID}); err != nil {
		t.Fatalf("BeginPause: %v", err)
	}

	cwB := do(r, "POST", "/sandboxes", apiKey, `{"name":"gate-b"}`)
	if cwB.Code != http.StatusCreated {
		t.Fatalf("create B while A is 'pausing': %d %s (slot must free at BeginPause)", cwB.Code, cwB.Body.String())
	}
}

// A pause revert (pausing→active) must never be quota-capped: the VM never
// stopped, and the reaper escalates a failed revert to terminal 'failed' on a
// healthy VM. At cap: A pausing, B created into the freed slot — reverting A
// must succeed as a transient cap+1, not raise SS001.
func TestIntegration_PauseRevertExemptFromQuota(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	if _, err := testPool.Exec(ctx, `UPDATE team SET max_sandboxes = 1 WHERE id = $1`, teamID); err != nil {
		t.Fatalf("set max_sandboxes: %v", err)
	}

	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"revert-a"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create A: %d %s", cw.Code, cw.Body.String())
	}
	sandboxID := uuid.MustParse(mustJSON(t, cw)["id"].(string))

	if _, err := testQueries.BeginPause(ctx, db.BeginPauseParams{ID: sandboxID, TeamID: teamID}); err != nil {
		t.Fatalf("BeginPause: %v", err)
	}
	if cwB := do(r, "POST", "/sandboxes", apiKey, `{"name":"revert-b"}`); cwB.Code != http.StatusCreated {
		t.Fatalf("create B into freed slot: %d %s", cwB.Code, cwB.Body.String())
	}

	// The reaper/API revert path: pausing→active via UpdateSandboxStatus.
	if err := testQueries.UpdateSandboxStatus(ctx, db.UpdateSandboxStatusParams{
		ID:     sandboxID,
		Status: db.SandboxStatusActive,
		TeamID: teamID,
	}); err != nil {
		t.Fatalf("pausing→active revert must be exempt from the cap, got: %v", err)
	}

	var count int
	if err := testPool.QueryRow(ctx, `SELECT active_sandbox_count FROM team WHERE id = $1`, teamID).Scan(&count); err != nil {
		t.Fatalf("read count: %v", err)
	}
	if count != 2 {
		t.Errorf("active_sandbox_count = %d, want 2 (transient overcommit recorded, not blocked)", count)
	}
}

func TestIntegration_ResumeSandbox_ActiveConflict(t *testing.T) {
	_, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"active-box"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d", cw.Code)
	}
	sid := mustJSON(t, cw)["id"].(string)

	w := do(r, "POST", "/sandboxes/"+sid+"/resume", apiKey, "")
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409 resuming active sandbox, got %d: %s", w.Code, w.Body.String())
	}
}

func countOpenIntervals(t *testing.T, ctx context.Context, sandboxID uuid.UUID) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(ctx,
		`SELECT count(*) FROM sandbox_active_interval WHERE sandbox_id = $1 AND ended_at IS NULL`,
		sandboxID).Scan(&n); err != nil {
		t.Fatalf("count open intervals: %v", err)
	}
	return n
}

func countOpenStorageIntervals(t *testing.T, ctx context.Context, sandboxID uuid.UUID) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(ctx,
		`SELECT count(*) FROM sandbox_storage_interval WHERE sandbox_id = $1 AND ended_at IS NULL`,
		sandboxID).Scan(&n); err != nil {
		t.Fatalf("count open storage intervals: %v", err)
	}
	return n
}

func countOpenComputeBillingIntervals(t *testing.T, ctx context.Context, sandboxID uuid.UUID) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(ctx,
		`SELECT count(*) FROM sandbox_compute_billing_interval WHERE sandbox_id = $1 AND ended_at IS NULL`,
		sandboxID).Scan(&n); err != nil {
		t.Fatalf("count open compute billing intervals: %v", err)
	}
	return n
}

func TestIntegration_SandboxBillingIntervalsLifecycle(t *testing.T) {
	ctx := context.Background()
	_, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"billing-lifecycle"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", cw.Code, cw.Body.String())
	}
	sandboxID := uuid.MustParse(mustJSON(t, cw)["id"].(string))

	var vcpu, memoryMib, diskMib int
	if err := testPool.QueryRow(ctx, `
		SELECT c.vcpu_count, c.memory_mib, s.disk_mib
		FROM sandbox_compute_billing_interval c
		JOIN sandbox_storage_interval s USING (sandbox_id)
		WHERE c.sandbox_id = $1 AND c.ended_at IS NULL AND s.ended_at IS NULL
	`, sandboxID).Scan(&vcpu, &memoryMib, &diskMib); err != nil {
		t.Fatalf("read opened billing intervals: %v", err)
	}
	if vcpu != 1 || memoryMib != 1024 || diskMib != 4096 {
		t.Fatalf("opened dimensions = vcpu:%d memory:%d disk:%d, want 1/1024/4096", vcpu, memoryMib, diskMib)
	}

	if pw := do(r, "POST", "/sandboxes/"+sandboxID.String()+"/pause", apiKey, ""); pw.Code != http.StatusNoContent {
		t.Fatalf("pause: %d %s", pw.Code, pw.Body.String())
	}
	if open := countOpenIntervals(t, ctx, sandboxID); open != 0 {
		t.Fatalf("open compute intervals after pause = %d, want 0", open)
	}
	if open := countOpenComputeBillingIntervals(t, ctx, sandboxID); open != 0 {
		t.Fatalf("open compute billing intervals after pause = %d, want 0", open)
	}
	if open := countOpenStorageIntervals(t, ctx, sandboxID); open != 1 {
		t.Fatalf("open storage intervals after pause = %d, want 1", open)
	}

	if dw := do(r, "DELETE", "/sandboxes/"+sandboxID.String(), apiKey, ""); dw.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", dw.Code, dw.Body.String())
	}
	if open := countOpenStorageIntervals(t, ctx, sandboxID); open != 0 {
		t.Fatalf("open storage intervals after delete = %d, want 0", open)
	}
}

func TestIntegration_BillingMetricsWriteFeatureFlag(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_feature_flag (team_id, key, enabled)
		VALUES ($1, 'billing_metrics_write', false)
		ON CONFLICT (team_id, key) DO UPDATE SET enabled = EXCLUDED.enabled
	`, teamID); err != nil {
		t.Fatalf("disable billing_metrics_write: %v", err)
	}

	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"billing-flag-off"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", cw.Code, cw.Body.String())
	}
	sandboxID := uuid.MustParse(mustJSON(t, cw)["id"].(string))

	if open := countOpenIntervals(t, ctx, sandboxID); open != 1 {
		t.Fatalf("active interval should still open when billing write flag is off; got %d", open)
	}
	if open := countOpenComputeBillingIntervals(t, ctx, sandboxID); open != 0 {
		t.Fatalf("open compute billing intervals with flag off = %d, want 0", open)
	}
	if open := countOpenStorageIntervals(t, ctx, sandboxID); open != 0 {
		t.Fatalf("open storage intervals with flag off = %d, want 0", open)
	}
}

func TestIntegration_PricingRatesUseNewestEffectiveVersion(t *testing.T) {
	ctx := context.Background()
	planKey := "test-plan-" + uuid.New().String()
	now := time.Now().UTC()

	insertPricingPlanForTest(t, ctx, planKey, true)
	if _, err := testPool.Exec(ctx, `
		INSERT INTO pricing_rate (plan_key, resource, unit, price_usd, effective_from)
		VALUES
			($1, 'vcpu', 'second', 0.000011, $2),
			($1, 'vcpu', 'second', 0.000022, $3),
			($1, 'memory_gib', 'second', 0.0000045, $2),
			($1, 'storage_gib', 'second', 0.00000003, $2)
	`, planKey, now.Add(-2*time.Hour), now.Add(-time.Hour)); err != nil {
		t.Fatalf("insert pricing rates: %v", err)
	}

	rates, err := testQueries.ListActivePricingRates(ctx, planKey)
	if err != nil {
		t.Fatalf("list active pricing rates: %v", err)
	}
	if len(rates) != 3 {
		t.Fatalf("rates length = %d, want 3", len(rates))
	}
	wantPrices := map[string]float64{
		"vcpu":        0.000022,
		"memory_gib":  0.0000045,
		"storage_gib": 0.00000003,
	}
	seen := map[string]bool{}
	for _, rate := range rates {
		want, ok := wantPrices[rate.Resource]
		if !ok {
			t.Errorf("unexpected pricing resource %q", rate.Resource)
			continue
		}
		seen[rate.Resource] = true
		if got := numericFloat64(t, rate.PriceUsd); got != want {
			t.Errorf("%s price = %v, want %v", rate.Resource, got, want)
		}
	}
	for resource := range wantPrices {
		if !seen[resource] {
			t.Errorf("missing pricing rate for %s", resource)
		}
	}
}

func TestIntegration_PricingRatesForPlanAtUseRequestedTime(t *testing.T) {
	ctx := context.Background()
	planKey := "test-plan-" + uuid.New().String()
	now := time.Now().UTC()

	insertPricingPlanForTest(t, ctx, planKey, true)
	if _, err := testPool.Exec(ctx, `
		INSERT INTO pricing_rate (plan_key, resource, unit, price_usd, effective_from)
		VALUES
			($1, 'vcpu', 'second', 0.000011, $2),
			($1, 'vcpu', 'second', 0.000022, $3),
			($1, 'memory_gib', 'second', 0.0000045, $2),
			($1, 'storage_gib', 'second', 0.00000003, $2)
	`, planKey, now.Add(-2*time.Hour), now.Add(time.Hour)); err != nil {
		t.Fatalf("insert pricing rates: %v", err)
	}

	rates, err := testQueries.ListPricingRatesForPlanAt(ctx, db.ListPricingRatesForPlanAtParams{
		PlanKey:     planKey,
		EffectiveAt: now,
	})
	if err != nil {
		t.Fatalf("list pricing rates for time: %v", err)
	}
	if len(rates) != 3 {
		t.Fatalf("rates length = %d, want 3", len(rates))
	}
	wantPrices := map[string]float64{
		"vcpu":        0.000011,
		"memory_gib":  0.0000045,
		"storage_gib": 0.00000003,
	}
	seen := map[string]bool{}
	for _, rate := range rates {
		want, ok := wantPrices[rate.Resource]
		if !ok {
			t.Errorf("unexpected pricing resource %q", rate.Resource)
			continue
		}
		seen[rate.Resource] = true
		if got := numericFloat64(t, rate.PriceUsd); got != want {
			t.Errorf("%s price = %v, want %v", rate.Resource, got, want)
		}
	}
	for resource := range wantPrices {
		if !seen[resource] {
			t.Errorf("missing pricing rate for %s", resource)
		}
	}
}

func TestIntegration_PricingRatesForPlanAtIncludesInactivePlan(t *testing.T) {
	ctx := context.Background()
	planKey := "inactive-historical-plan-" + uuid.New().String()
	now := time.Now().UTC()

	insertPricingPlanForTest(t, ctx, planKey, false)
	if _, err := testPool.Exec(ctx, `
		INSERT INTO pricing_rate (plan_key, resource, unit, price_usd, effective_from)
		VALUES
			($1, 'vcpu', 'second', 0.000011, $2),
			($1, 'memory_gib', 'second', 0.0000045, $2),
			($1, 'storage_gib', 'second', 0.00000003, $2)
	`, planKey, now.Add(-time.Hour)); err != nil {
		t.Fatalf("insert inactive historical pricing rates: %v", err)
	}

	rates, err := testQueries.ListPricingRatesForPlanAt(ctx, db.ListPricingRatesForPlanAtParams{
		PlanKey:     planKey,
		EffectiveAt: now,
	})
	if err != nil {
		t.Fatalf("list pricing rates for inactive plan: %v", err)
	}
	if len(rates) != 3 {
		t.Fatalf("rates length = %d, want 3 for historical inactive plan", len(rates))
	}
}

func TestIntegration_InactiveTeamPricingPlanFallsBackToPayg(t *testing.T) {
	ctx := context.Background()
	teamID, _ := seedTeamAndKey(t)
	planKey := "inactive-plan-" + uuid.New().String()

	insertPricingPlanForTest(t, ctx, planKey, false)
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_pricing_plan (team_id, plan_key, effective_from)
		VALUES ($1, $2, now() - interval '1 hour')
	`, teamID, planKey); err != nil {
		t.Fatalf("assign inactive pricing plan: %v", err)
	}

	resolved, err := testQueries.GetTeamActivePricingPlan(ctx, teamID)
	if err != nil {
		t.Fatalf("get team active pricing plan: %v", err)
	}
	if resolved != "payg" {
		t.Fatalf("pricing plan = %q, want payg fallback", resolved)
	}
}

func insertPricingPlanForTest(t *testing.T, ctx context.Context, planKey string, active bool) {
	t.Helper()
	if _, err := testPool.Exec(ctx, `
		INSERT INTO pricing_plan (key, name, currency, active)
		VALUES ($1, 'Integration test pricing', 'USD', $2)
	`, planKey, active); err != nil {
		t.Fatalf("insert pricing plan: %v", err)
	}
}

func TestIntegration_BillingPeriodRollupFuturePeriodIsZero(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"future-rollup"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", cw.Code, cw.Body.String())
	}

	periodStart := time.Now().UTC().Add(2 * time.Hour).Truncate(time.Hour)
	periodEnd := periodStart.Add(time.Hour)
	usage, err := testQueries.GetTeamBillingUsage(ctx, db.GetTeamBillingUsageParams{
		TeamID:      teamID,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
	})
	if err != nil {
		t.Fatalf("future get usage: %v", err)
	}
	if got := numericFloat64(t, usage.VcpuSeconds); got != 0 {
		t.Fatalf("future vcpu seconds = %v, want 0", got)
	}

	rollup, err := testQueries.UpsertTeamBillingUsage(ctx, db.UpsertTeamBillingUsageParams{
		TeamID:      teamID,
		PeriodStart: pgtype.Timestamptz{Time: periodStart, Valid: true},
		PeriodEnd:   pgtype.Timestamptz{Time: periodEnd, Valid: true},
	})
	if err != nil {
		t.Fatalf("future upsert usage: %v", err)
	}
	if got := numericFloat64(t, rollup.VcpuSeconds); got != 0 {
		t.Fatalf("future rollup vcpu seconds = %v, want 0", got)
	}
}

func TestIntegration_HourlyRollupFeatureFlagDoesNotOverwriteWithZero(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"hourly-flag-gate"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", cw.Code, cw.Body.String())
	}

	hourStart := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)
	hourEnd := hourStart.Add(time.Hour)
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_billing_usage_hourly (
			team_id, hour_start, hour_end, vcpu_seconds, memory_mib_seconds, storage_mib_seconds
		)
		VALUES ($1, $2, $3, 123, 456, 789)
	`, teamID, hourStart, hourEnd); err != nil {
		t.Fatalf("seed hourly row: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_feature_flag (team_id, key, enabled)
		VALUES ($1, 'billing_hourly_rollups', false)
		ON CONFLICT (team_id, key) DO UPDATE SET enabled = EXCLUDED.enabled
	`, teamID); err != nil {
		t.Fatalf("disable hourly rollups: %v", err)
	}

	if _, err := testQueries.UpsertTeamBillingUsageHour(ctx, db.UpsertTeamBillingUsageHourParams{
		TeamID:    teamID,
		HourStart: pgtype.Timestamptz{Time: hourStart, Valid: true},
		HourEnd:   pgtype.Timestamptz{Time: hourEnd, Valid: true},
	}); err == nil {
		t.Fatal("expected no hourly row returned while billing_hourly_rollups is disabled")
	}

	var vcpu int
	if err := testPool.QueryRow(ctx, `
		SELECT vcpu_seconds::int
		FROM team_billing_usage_hourly
		WHERE team_id = $1 AND hour_start = $2
	`, teamID, hourStart).Scan(&vcpu); err != nil {
		t.Fatalf("read hourly row: %v", err)
	}
	if vcpu != 123 {
		t.Fatalf("hourly row was overwritten while flag disabled: got %d", vcpu)
	}
}

func TestIntegration_FinalizeBillingPeriodFinalizesUsage(t *testing.T) {
	ctx := context.Background()
	teamID, _ := seedTeamAndKey(t)
	periodStart := time.Now().UTC().Truncate(time.Hour).Add(-24 * time.Hour)
	periodEnd := periodStart.Add(24 * time.Hour)

	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_feature_flag (team_id, key, enabled)
		VALUES ($1, 'billing_export_enabled', true)
		ON CONFLICT (team_id, key) DO UPDATE SET enabled = EXCLUDED.enabled
	`, teamID); err != nil {
		t.Fatalf("enable billing export: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_billing_usage (
			team_id, period_start, period_end, vcpu_seconds, memory_mib_seconds, storage_mib_seconds
		)
		VALUES ($1, $2, $3, 1, 2, 3)
	`, teamID, periodStart, periodEnd); err != nil {
		t.Fatalf("seed usage: %v", err)
	}
	if _, err := testQueries.UpsertTeamBillingPeriod(ctx, db.UpsertTeamBillingPeriodParams{
		TeamID:      teamID,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
		Status:      "approved",
	}); err != nil {
		t.Fatalf("upsert period: %v", err)
	}
	if _, err := testQueries.MarkTeamBillingPeriodExported(ctx, db.MarkTeamBillingPeriodExportedParams{
		TeamID:      teamID,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
	}); err != nil {
		t.Fatalf("export period: %v", err)
	}
	if _, err := testQueries.FinalizeTeamBillingPeriod(ctx, db.FinalizeTeamBillingPeriodParams{
		TeamID:      teamID,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
	}); err != nil {
		t.Fatalf("finalize period: %v", err)
	}

	var finalizedAt *time.Time
	if err := testPool.QueryRow(ctx, `
		SELECT finalized_at
		FROM team_billing_usage
		WHERE team_id = $1 AND period_start = $2 AND period_end = $3
	`, teamID, periodStart, periodEnd).Scan(&finalizedAt); err != nil {
		t.Fatalf("read usage finalized_at: %v", err)
	}
	if finalizedAt == nil {
		t.Fatal("team_billing_usage.finalized_at is NULL after period finalization")
	}
}

func TestIntegration_BillingExportFeatureFlag(t *testing.T) {
	ctx := context.Background()
	teamID, _ := seedTeamAndKey(t)
	periodStart := time.Now().UTC().Truncate(time.Hour)
	periodEnd := periodStart.Add(24 * time.Hour)

	if _, err := testQueries.UpsertTeamBillingPeriod(ctx, db.UpsertTeamBillingPeriodParams{
		TeamID:      teamID,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
		Status:      "approved",
	}); err != nil {
		t.Fatalf("upsert billing period: %v", err)
	}

	if _, err := testQueries.UpsertTeamBillingUsage(ctx, db.UpsertTeamBillingUsageParams{
		TeamID:      teamID,
		PeriodStart: pgtype.Timestamptz{Time: periodStart, Valid: true},
		PeriodEnd:   pgtype.Timestamptz{Time: periodEnd, Valid: true},
	}); err != nil {
		t.Fatalf("upsert billing usage before export: %v", err)
	}

	if _, err := testQueries.MarkTeamBillingPeriodExported(ctx, db.MarkTeamBillingPeriodExportedParams{
		TeamID:      teamID,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
	}); err == nil {
		t.Fatal("expected billing export to be gated off by default")
	}

	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_feature_flag (team_id, key, enabled)
		VALUES ($1, 'billing_export_enabled', true)
		ON CONFLICT (team_id, key) DO UPDATE SET enabled = EXCLUDED.enabled
	`, teamID); err != nil {
		t.Fatalf("enable billing_export_enabled: %v", err)
	}

	if _, err := testQueries.MarkTeamBillingPeriodExported(ctx, db.MarkTeamBillingPeriodExportedParams{
		TeamID:      teamID,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
	}); err != nil {
		t.Fatalf("expected billing export after enabling flag: %v", err)
	}
}

func TestIntegration_HourlyRollupBoundsOpenIntervalsAtNow(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_feature_flag (team_id, key, enabled)
		VALUES ($1, 'tenant_usage_dashboard', true)
		ON CONFLICT (team_id, key) DO UPDATE SET enabled = EXCLUDED.enabled
	`, teamID); err != nil {
		t.Fatalf("enable tenant dashboard: %v", err)
	}

	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"hourly-open-bound"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", cw.Code, cw.Body.String())
	}
	sandboxID := uuid.MustParse(mustJSON(t, cw)["id"].(string))

	hourStart := time.Now().UTC().Truncate(time.Hour)
	hourEnd := hourStart.Add(time.Hour)
	startedAt := time.Now().UTC().Add(-5 * time.Minute)
	if startedAt.Before(hourStart) {
		startedAt = hourStart
	}

	if _, err := testPool.Exec(ctx, `
		UPDATE sandbox_compute_billing_interval
		SET started_at = $2, ended_at = NULL, end_reason = NULL,
		    vcpu_count = 1, memory_mib = 1024
		WHERE sandbox_id = $1 AND ended_at IS NULL
	`, sandboxID, startedAt); err != nil {
		t.Fatalf("set compute interval: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		UPDATE sandbox_storage_interval
		SET started_at = $2, ended_at = NULL, end_reason = NULL,
		    disk_mib = 1024
		WHERE sandbox_id = $1 AND ended_at IS NULL
	`, sandboxID, startedAt); err != nil {
		t.Fatalf("set storage interval: %v", err)
	}

	row, err := testQueries.UpsertTeamBillingUsageHour(ctx, db.UpsertTeamBillingUsageHourParams{
		TeamID:    teamID,
		HourStart: pgtype.Timestamptz{Time: hourStart, Valid: true},
		HourEnd:   pgtype.Timestamptz{Time: hourEnd, Valid: true},
	})
	if err != nil {
		t.Fatalf("upsert hourly usage: %v", err)
	}

	vcpuSeconds := numericFloat64(t, row.VcpuSeconds)
	if vcpuSeconds >= 3600 {
		t.Fatalf("current-hour open interval was charged to hour_end: got %v seconds", vcpuSeconds)
	}
	if vcpuSeconds <= 0 {
		t.Fatalf("current-hour open interval should have positive elapsed usage, got %v", vcpuSeconds)
	}
}

func TestIntegration_SandboxBillingIntervalsStorageStaysOpenOnFailed(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"billing-failed"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", cw.Code, cw.Body.String())
	}
	sandboxID := uuid.MustParse(mustJSON(t, cw)["id"].(string))

	if open := countOpenComputeBillingIntervals(t, ctx, sandboxID); open != 1 {
		t.Fatalf("open compute billing intervals before fail = %d, want 1", open)
	}
	if open := countOpenStorageIntervals(t, ctx, sandboxID); open != 1 {
		t.Fatalf("open storage intervals before fail = %d, want 1", open)
	}

	if err := testQueries.MarkSandboxFailedInTeam(ctx, db.MarkSandboxFailedInTeamParams{
		ID:     sandboxID,
		TeamID: teamID,
	}); err != nil {
		t.Fatalf("mark failed: %v", err)
	}

	if open := countOpenComputeBillingIntervals(t, ctx, sandboxID); open != 0 {
		t.Fatalf("open compute billing intervals after fail = %d, want 0", open)
	}
	if open := countOpenStorageIntervals(t, ctx, sandboxID); open != 1 {
		t.Fatalf("open storage intervals after fail = %d, want 1 because failed sandboxes retain disk", open)
	}
}

func TestIntegration_BillingIntervalsEnforceSandboxTenant(t *testing.T) {
	ctx := context.Background()
	_, apiKey := seedTeamAndKey(t)
	otherTeamID, _ := seedTeamAndKey(t)
	r := newRouter(t)

	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"billing-tenant-fk"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", cw.Code, cw.Body.String())
	}
	sandboxID := uuid.MustParse(mustJSON(t, cw)["id"].(string))

	_, err := testPool.Exec(ctx, `
		INSERT INTO sandbox_compute_billing_interval (
			sandbox_id, team_id, vcpu_count, memory_mib
		)
		VALUES ($1, $2, 1, 1024)
	`, sandboxID, otherTeamID)
	if err == nil {
		t.Fatal("expected cross-team compute billing interval to violate FK")
	}

	_, err = testPool.Exec(ctx, `
		INSERT INTO sandbox_storage_interval (sandbox_id, team_id, disk_mib)
		VALUES ($1, $2, 4096)
	`, sandboxID, otherTeamID)
	if err == nil {
		t.Fatal("expected cross-team storage interval to violate FK")
	}
}

func TestIntegration_GetTeamBillingUsage(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"billing-aggregate"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", cw.Code, cw.Body.String())
	}
	sandboxID := uuid.MustParse(mustJSON(t, cw)["id"].(string))

	periodStart := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	periodEnd := periodStart.Add(100 * time.Second)
	if _, err := testPool.Exec(ctx, `
		UPDATE sandbox_compute_billing_interval
		SET started_at = $2, ended_at = $3, end_reason = 'paused',
		    vcpu_count = 2, memory_mib = 2048
		WHERE sandbox_id = $1 AND ended_at IS NULL
	`, sandboxID, periodStart.Add(10*time.Second), periodStart.Add(40*time.Second)); err != nil {
		t.Fatalf("set deterministic compute interval: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		UPDATE sandbox_storage_interval
		SET started_at = $2, ended_at = $3, end_reason = 'deleted',
		    disk_mib = 4096
		WHERE sandbox_id = $1 AND ended_at IS NULL
	`, sandboxID, periodStart.Add(5*time.Second), periodStart.Add(65*time.Second)); err != nil {
		t.Fatalf("set deterministic storage interval: %v", err)
	}

	usage, err := testQueries.GetTeamBillingUsage(ctx, db.GetTeamBillingUsageParams{
		TeamID:      teamID,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
	})
	if err != nil {
		t.Fatalf("get team billing usage: %v", err)
	}

	vcpuSeconds := numericFloat64(t, usage.VcpuSeconds)
	memoryGibSeconds := numericFloat64(t, usage.MemoryGibSeconds)
	storageGibSeconds := numericFloat64(t, usage.StorageGibSeconds)
	if vcpuSeconds != 60 || memoryGibSeconds != 60 || storageGibSeconds != 240 {
		t.Fatalf("usage = vcpu:%v memory:%v storage:%v, want 60/60/240",
			vcpuSeconds, memoryGibSeconds, storageGibSeconds)
	}

	rollup, err := testQueries.UpsertTeamBillingUsage(ctx, db.UpsertTeamBillingUsageParams{
		TeamID:      teamID,
		PeriodStart: pgtype.Timestamptz{Time: periodStart, Valid: true},
		PeriodEnd:   pgtype.Timestamptz{Time: periodEnd, Valid: true},
	})
	if err != nil {
		t.Fatalf("upsert team billing usage: %v", err)
	}
	if got := numericFloat64(t, rollup.VcpuSeconds); got != 60 {
		t.Fatalf("rollup vcpu seconds = %v, want 60", got)
	}
	if got := numericFloat64(t, rollup.MemoryMibSeconds); got != 61_440 {
		t.Fatalf("rollup memory MiB seconds = %v, want 61440", got)
	}
	if got := numericFloat64(t, rollup.StorageMibSeconds); got != 245_760 {
		t.Fatalf("rollup storage MiB seconds = %v, want 245760", got)
	}
}

func TestIntegration_BillingRollupWorkersProcessDistinctJobs(t *testing.T) {
	ctx := context.Background()
	teamA, _ := seedTeamAndKey(t)
	teamB, _ := seedTeamAndKey(t)
	hourStart := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)
	hourEnd := hourStart.Add(time.Hour)

	enableBillingHourlyRollups(t, ctx, teamA)
	enableBillingHourlyRollups(t, ctx, teamB)
	insertBillingRollupJob(t, ctx, teamA, hourStart, hourEnd, "pending", "", time.Time{}, 0)
	insertBillingRollupJob(t, ctx, teamB, hourStart, hourEnd, "pending", "", time.Time{}, 0)

	cfg := billing.HourlyRollupConfig{
		BatchSize:    1,
		MaxAttempts:  5,
		LockDuration: time.Minute,
	}
	billing.ProcessJobsForTest(ctx, testPool, testQueries, cfg, "rollup-worker-a")
	billing.ProcessJobsForTest(ctx, testPool, testQueries, cfg, "rollup-worker-b")

	var completed int
	if err := testPool.QueryRow(ctx, `
		SELECT count(*)
		FROM billing_rollup_job
		WHERE team_id IN ($1, $2)
		  AND hour_start = $3
		  AND status = 'completed'
	`, teamA, teamB, hourStart).Scan(&completed); err != nil {
		t.Fatalf("count completed rollup jobs: %v", err)
	}
	if completed != 2 {
		t.Fatalf("completed rollup jobs = %d, want 2", completed)
	}

	var hourlyRows int
	if err := testPool.QueryRow(ctx, `
		SELECT count(*)
		FROM team_billing_usage_hourly
		WHERE team_id IN ($1, $2)
		  AND hour_start = $3
	`, teamA, teamB, hourStart).Scan(&hourlyRows); err != nil {
		t.Fatalf("count hourly usage rows: %v", err)
	}
	if hourlyRows != 2 {
		t.Fatalf("hourly usage rows = %d, want 2", hourlyRows)
	}
}

func TestIntegration_BillingRollupStaleLockIsClaimable(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey := seedTeamAndKey(t)
	r := newRouter(t)
	hourStart := time.Now().UTC().Truncate(time.Hour).Add(-2 * time.Hour)
	hourEnd := hourStart.Add(time.Hour)
	staleLockedUntil := time.Now().UTC().Add(-time.Minute)

	enableBillingHourlyRollups(t, ctx, teamID)
	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"stale-rollup-reclaim"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", cw.Code, cw.Body.String())
	}
	sandboxID := uuid.MustParse(mustJSON(t, cw)["id"].(string))
	if _, err := testPool.Exec(ctx, `
		UPDATE sandbox_compute_billing_interval
		SET started_at = $2, ended_at = $3, end_reason = 'paused',
		    vcpu_count = 1, memory_mib = 1024
		WHERE sandbox_id = $1 AND ended_at IS NULL
	`, sandboxID, hourStart.Add(5*time.Second), hourStart.Add(30*time.Second)); err != nil {
		t.Fatalf("set compute interval: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		UPDATE sandbox_storage_interval
		SET started_at = $2, ended_at = $3, end_reason = 'deleted',
		    disk_mib = 1024
		WHERE sandbox_id = $1 AND ended_at IS NULL
	`, sandboxID, hourStart.Add(5*time.Second), hourStart.Add(30*time.Second)); err != nil {
		t.Fatalf("set storage interval: %v", err)
	}

	jobID := insertBillingRollupJob(t, ctx, teamID, hourStart, hourEnd, "running", "stale-worker", staleLockedUntil, 5)
	if _, err := billing.EnqueueHourForTest(ctx, testPool, hourStart, hourEnd); err != nil {
		t.Fatalf("enqueue hour with stale running job: %v", err)
	}

	cfg := billing.HourlyRollupConfig{
		BatchSize:    1,
		MaxAttempts:  5,
		LockDuration: time.Minute,
	}
	jobs, err := billing.ClaimJobsForTest(ctx, testPool, cfg, "replacement-worker")
	if err != nil {
		t.Fatalf("claim stale rollup job: %v", err)
	}
	if len(jobs) != 1 {
		t.Fatalf("claimed jobs = %d, want 1", len(jobs))
	}
	if jobs[0].ID != jobID {
		t.Fatalf("claimed job id = %s, want %s", jobs[0].ID, jobID)
	}

	var status, lockedBy string
	var attemptCount int
	if err := testPool.QueryRow(ctx, `
		SELECT status, locked_by, attempt_count
		FROM billing_rollup_job
		WHERE id = $1
	`, jobID).Scan(&status, &lockedBy, &attemptCount); err != nil {
		t.Fatalf("read claimed stale job: %v", err)
	}
	if status != "running" {
		t.Fatalf("status = %q, want running", status)
	}
	if lockedBy != "replacement-worker" {
		t.Fatalf("locked_by = %q, want replacement-worker", lockedBy)
	}
	if attemptCount != 5 {
		t.Fatalf("attempt_count = %d, want 5", attemptCount)
	}
}

func TestIntegration_BillingRollupSchedulerPreservesPendingRetryBackoff(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey := seedTeamAndKey(t)
	r := newRouter(t)
	hourStart := time.Now().UTC().Truncate(time.Hour).Add(-2 * time.Hour)
	hourEnd := hourStart.Add(time.Hour)
	nextAttemptAt := time.Now().UTC().Add(30 * time.Minute)

	enableBillingHourlyRollups(t, ctx, teamID)
	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"rollup-preserve-backoff"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", cw.Code, cw.Body.String())
	}
	sandboxID := uuid.MustParse(mustJSON(t, cw)["id"].(string))
	if _, err := testPool.Exec(ctx, `
		UPDATE sandbox_compute_billing_interval
		SET started_at = $2, ended_at = $3, end_reason = 'paused',
		    vcpu_count = 1, memory_mib = 1024
		WHERE sandbox_id = $1 AND ended_at IS NULL
	`, sandboxID, hourStart.Add(5*time.Second), hourStart.Add(30*time.Second)); err != nil {
		t.Fatalf("set compute interval: %v", err)
	}

	if _, err := testPool.Exec(ctx, `
		INSERT INTO billing_rollup_job (
			team_id, hour_start, hour_end, status, attempt_count, next_attempt_at, last_error
		)
		VALUES ($1, $2, $3, 'pending', 2, $4, 'temporary failure')
	`, teamID, hourStart, hourEnd, nextAttemptAt); err != nil {
		t.Fatalf("insert pending retry job: %v", err)
	}
	if _, err := billing.EnqueueHourForTest(ctx, testPool, hourStart, hourEnd); err != nil {
		t.Fatalf("enqueue hour with pending retry job: %v", err)
	}

	var gotNextAttemptAt time.Time
	var gotLastError string
	var gotAttemptCount int
	if err := testPool.QueryRow(ctx, `
		SELECT next_attempt_at, last_error, attempt_count
		FROM billing_rollup_job
		WHERE team_id = $1 AND hour_start = $2
	`, teamID, hourStart).Scan(&gotNextAttemptAt, &gotLastError, &gotAttemptCount); err != nil {
		t.Fatalf("read pending retry job: %v", err)
	}
	if gotNextAttemptAt.Before(nextAttemptAt.Add(-time.Second)) {
		t.Fatalf("next_attempt_at = %s, want preserved near %s", gotNextAttemptAt, nextAttemptAt)
	}
	if gotLastError != "temporary failure" {
		t.Fatalf("last_error = %q, want preserved", gotLastError)
	}
	if gotAttemptCount != 2 {
		t.Fatalf("attempt_count = %d, want 2", gotAttemptCount)
	}
}

func TestIntegration_BillingRollupBackfillCursorAdvancesAfterEnqueue(t *testing.T) {
	ctx := context.Background()
	resetBillingRollupBackfillState(t, ctx)
	teamID, apiKey := seedTeamAndKey(t)
	r := newRouter(t)
	now := time.Now().UTC().Truncate(time.Hour)
	backfillStart := now.Add(-48 * time.Hour)
	firstHourEnd := backfillStart.Add(time.Hour)

	enableBillingHourlyRollups(t, ctx, teamID)
	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"rollup-backfill-cursor"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", cw.Code, cw.Body.String())
	}
	sandboxID := uuid.MustParse(mustJSON(t, cw)["id"].(string))
	seedComputeBillingInterval(t, ctx, sandboxID, teamID, backfillStart.Add(5*time.Second), backfillStart.Add(30*time.Second))

	if _, err := testPool.Exec(ctx, `
		INSERT INTO billing_rollup_team_backfill_state (team_id, next_hour_start)
		VALUES ($1, $2)
		ON CONFLICT (team_id) DO UPDATE
		SET next_hour_start = EXCLUDED.next_hour_start
	`, teamID, backfillStart); err != nil {
		t.Fatalf("seed team backfill cursor: %v", err)
	}

	enqueued, err := billing.EnqueueBackfillForTest(ctx, testPool, billing.HourlyRollupConfig{
		LookbackHours:         24,
		BackfillLookbackHours: 72,
		BackfillBatchHours:    1,
	}, now)
	if err != nil {
		t.Fatalf("enqueue backfill: %v", err)
	}
	if enqueued == 0 {
		t.Fatal("expected backfill to enqueue at least one job")
	}

	var cursor time.Time
	if err := testPool.QueryRow(ctx, `
		SELECT next_hour_start
		FROM billing_rollup_team_backfill_state
		WHERE team_id = $1
	`, teamID).Scan(&cursor); err != nil {
		t.Fatalf("read team backfill cursor: %v", err)
	}
	if !cursor.Equal(firstHourEnd) {
		t.Fatalf("cursor = %s, want advanced to %s after successful enqueue", cursor, firstHourEnd)
	}
}

func TestIntegration_BillingRollupTeamBackfillCursorAdvanceToleratesConcurrentAdvance(t *testing.T) {
	ctx := context.Background()
	resetBillingRollupBackfillState(t, ctx)
	teamID, _ := seedTeamAndKey(t)
	fromHour := time.Now().UTC().Truncate(time.Hour).Add(-48 * time.Hour)
	toHour := fromHour.Add(24 * time.Hour)
	concurrentCursor := fromHour.Add(time.Hour)

	if _, err := testPool.Exec(ctx, `
		INSERT INTO billing_rollup_team_backfill_state (team_id, next_hour_start)
		VALUES ($1, $2)
	`, teamID, concurrentCursor); err != nil {
		t.Fatalf("seed concurrent team backfill cursor: %v", err)
	}
	if err := billing.AdvanceTeamBackfillCursorForTest(ctx, testPool, teamID, fromHour, toHour); err != nil {
		t.Fatalf("advance team cursor after concurrent progress: %v", err)
	}

	var cursor time.Time
	if err := testPool.QueryRow(ctx, `
		SELECT next_hour_start
		FROM billing_rollup_team_backfill_state
		WHERE team_id = $1
	`, teamID).Scan(&cursor); err != nil {
		t.Fatalf("read team backfill cursor: %v", err)
	}
	if !cursor.Equal(toHour) {
		t.Fatalf("cursor = %s, want advanced to %s", cursor, toHour)
	}
	if err := billing.AdvanceTeamBackfillCursorForTest(ctx, testPool, teamID, fromHour, toHour); err != nil {
		t.Fatalf("advance team cursor should be idempotent once already advanced: %v", err)
	}
}

func TestIntegration_BillingRollupBackfillDoesNotAdvanceDisabledTeamCursor(t *testing.T) {
	ctx := context.Background()
	resetBillingRollupBackfillState(t, ctx)
	teamID, apiKey := seedTeamAndKey(t)
	r := newRouter(t)
	now := time.Now().UTC().Truncate(time.Hour)
	oldHourStart := now.Add(-48 * time.Hour)
	oldHourEnd := oldHourStart.Add(time.Hour)

	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_feature_flag (team_id, key, enabled)
		VALUES
			($1, 'billing_metrics_write', true),
			($1, 'billing_hourly_rollups', false)
		ON CONFLICT (team_id, key) DO UPDATE SET enabled = EXCLUDED.enabled
	`, teamID); err != nil {
		t.Fatalf("configure billing feature flags: %v", err)
	}
	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"rollup-backfill-disabled-team"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", cw.Code, cw.Body.String())
	}
	sandboxID := uuid.MustParse(mustJSON(t, cw)["id"].(string))
	seedComputeBillingInterval(t, ctx, sandboxID, teamID, oldHourStart.Add(5*time.Second), oldHourStart.Add(30*time.Second))

	if _, err := billing.EnqueueBackfillForTest(ctx, testPool, billing.HourlyRollupConfig{
		LookbackHours:         24,
		BackfillLookbackHours: 72,
		BackfillBatchHours:    72,
	}, now); err != nil {
		t.Fatalf("enqueue disabled backfill: %v", err)
	}

	var disabledTeamJobs int
	if err := testPool.QueryRow(ctx, `
		SELECT count(*)
		FROM billing_rollup_job
		WHERE team_id = $1
	`, teamID).Scan(&disabledTeamJobs); err != nil {
		t.Fatalf("count disabled team backfill jobs: %v", err)
	}
	if disabledTeamJobs != 0 {
		t.Fatalf("disabled team backfill jobs = %d, want 0", disabledTeamJobs)
	}

	var cursorRows int
	if err := testPool.QueryRow(ctx, `
		SELECT count(*)
		FROM billing_rollup_team_backfill_state
		WHERE team_id = $1
	`, teamID).Scan(&cursorRows); err != nil {
		t.Fatalf("count disabled team backfill cursor rows: %v", err)
	}
	if cursorRows != 0 {
		t.Fatalf("disabled team backfill cursor rows = %d, want 0", cursorRows)
	}

	enableBillingHourlyRollups(t, ctx, teamID)
	enqueued, err := billing.EnqueueBackfillForTest(ctx, testPool, billing.HourlyRollupConfig{
		LookbackHours:         24,
		BackfillLookbackHours: 72,
		BackfillBatchHours:    72,
	}, now)
	if err != nil {
		t.Fatalf("enqueue enabled backfill: %v", err)
	}
	if enqueued == 0 {
		t.Fatal("expected newly enabled team to enqueue historical backfill job")
	}

	var jobs int
	if err := testPool.QueryRow(ctx, `
		SELECT count(*)
		FROM billing_rollup_job
		WHERE team_id = $1
		  AND hour_start = $2
		  AND hour_end = $3
	`, teamID, oldHourStart, oldHourEnd).Scan(&jobs); err != nil {
		t.Fatalf("count newly enabled team backfill jobs: %v", err)
	}
	if jobs != 1 {
		t.Fatalf("newly enabled team backfill jobs = %d, want 1", jobs)
	}
}

func TestIntegration_BillingRollupBackfillEnqueuesBeforeRollingWindow(t *testing.T) {
	ctx := context.Background()
	resetBillingRollupBackfillState(t, ctx)
	teamID, apiKey := seedTeamAndKey(t)
	r := newRouter(t)
	now := time.Now().UTC().Truncate(time.Hour)
	oldHourStart := now.Add(-48 * time.Hour)
	oldHourEnd := oldHourStart.Add(time.Hour)

	enableBillingHourlyRollups(t, ctx, teamID)
	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"rollup-backfill-old-hour"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", cw.Code, cw.Body.String())
	}
	sandboxID := uuid.MustParse(mustJSON(t, cw)["id"].(string))
	if _, err := testPool.Exec(ctx, `
		UPDATE sandbox_compute_billing_interval
		SET started_at = $2, ended_at = $3, end_reason = 'paused',
		    vcpu_count = 1, memory_mib = 1024
		WHERE sandbox_id = $1 AND ended_at IS NULL
	`, sandboxID, oldHourStart.Add(5*time.Second), oldHourStart.Add(30*time.Second)); err != nil {
		t.Fatalf("set compute interval: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		UPDATE sandbox_storage_interval
		SET started_at = $2, ended_at = $3, end_reason = 'deleted',
		    disk_mib = 1024
		WHERE sandbox_id = $1 AND ended_at IS NULL
	`, sandboxID, oldHourStart.Add(5*time.Second), oldHourStart.Add(30*time.Second)); err != nil {
		t.Fatalf("set storage interval: %v", err)
	}

	enqueued, err := billing.EnqueueBackfillForTest(ctx, testPool, billing.HourlyRollupConfig{
		LookbackHours:         24,
		BackfillLookbackHours: 72,
		BackfillBatchHours:    72,
	}, now)
	if err != nil {
		t.Fatalf("enqueue backfill: %v", err)
	}
	if enqueued == 0 {
		t.Fatal("expected backfill to enqueue at least one old rollup job")
	}

	var jobs int
	if err := testPool.QueryRow(ctx, `
		SELECT count(*)
		FROM billing_rollup_job
		WHERE team_id = $1
		  AND hour_start = $2
		  AND hour_end = $3
	`, teamID, oldHourStart, oldHourEnd).Scan(&jobs); err != nil {
		t.Fatalf("count backfilled jobs: %v", err)
	}
	if jobs != 1 {
		t.Fatalf("backfilled jobs = %d, want 1", jobs)
	}
}

func resetBillingRollupBackfillState(t *testing.T, ctx context.Context) {
	t.Helper()
	if _, err := testPool.Exec(ctx, `DELETE FROM billing_rollup_backfill_state WHERE name = 'hourly'`); err != nil {
		t.Fatalf("reset billing rollup backfill state: %v", err)
	}
	if _, err := testPool.Exec(ctx, `DELETE FROM billing_rollup_team_backfill_state`); err != nil {
		t.Fatalf("reset billing rollup team backfill state: %v", err)
	}
}

func seedComputeBillingInterval(t *testing.T, ctx context.Context, sandboxID uuid.UUID, teamID uuid.UUID, startedAt time.Time, endedAt time.Time) {
	t.Helper()
	if _, err := testPool.Exec(ctx, `
		DELETE FROM sandbox_compute_billing_interval
		WHERE sandbox_id = $1
	`, sandboxID); err != nil {
		t.Fatalf("clear compute billing intervals: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO sandbox_compute_billing_interval (
			sandbox_id, team_id, vcpu_count, memory_mib, started_at, ended_at, end_reason
		)
		VALUES ($1, $2, 1, 1024, $3, $4, 'paused')
	`, sandboxID, teamID, startedAt, endedAt); err != nil {
		t.Fatalf("insert compute billing interval: %v", err)
	}
}

func enableBillingHourlyRollups(t *testing.T, ctx context.Context, teamID uuid.UUID) {
	t.Helper()
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_feature_flag (team_id, key, enabled)
		VALUES
			($1, 'billing_metrics_write', true),
			($1, 'billing_hourly_rollups', true)
		ON CONFLICT (team_id, key) DO UPDATE SET enabled = EXCLUDED.enabled
	`, teamID); err != nil {
		t.Fatalf("enable billing rollup feature flags: %v", err)
	}
}

func insertBillingRollupJob(
	t *testing.T,
	ctx context.Context,
	teamID uuid.UUID,
	hourStart time.Time,
	hourEnd time.Time,
	status string,
	lockedBy string,
	lockedUntil time.Time,
	attemptCount int,
) uuid.UUID {
	t.Helper()

	var jobID uuid.UUID
	if status == "running" {
		if err := testPool.QueryRow(ctx, `
			INSERT INTO billing_rollup_job (
				team_id, hour_start, hour_end, status, attempt_count,
				locked_by, locked_until, next_attempt_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, now() - interval '1 minute')
			RETURNING id
		`, teamID, hourStart, hourEnd, status, attemptCount, lockedBy, lockedUntil).Scan(&jobID); err != nil {
			t.Fatalf("insert running billing rollup job: %v", err)
		}
		return jobID
	}

	if err := testPool.QueryRow(ctx, `
		INSERT INTO billing_rollup_job (
			team_id, hour_start, hour_end, status, attempt_count, next_attempt_at
		)
		VALUES ($1, $2, $3, $4, $5, now() - interval '1 minute')
		RETURNING id
	`, teamID, hourStart, hourEnd, status, attemptCount).Scan(&jobID); err != nil {
		t.Fatalf("insert billing rollup job: %v", err)
	}
	return jobID
}

func TestIntegration_TeamCreditLedgerRejectsCrossTeamGrant(t *testing.T) {
	ctx := context.Background()
	grantTeamID, _ := seedTeamAndKey(t)
	ledgerTeamID, _ := seedTeamAndKey(t)

	var grantID uuid.UUID
	if err := testPool.QueryRow(ctx, `
		INSERT INTO team_credit_grant (
			team_id, amount_usd, remaining_usd, reason
		)
		VALUES ($1, 10.00, 10.00, 'test grant')
		RETURNING id
	`, grantTeamID).Scan(&grantID); err != nil {
		t.Fatalf("insert credit grant: %v", err)
	}

	_, err := testPool.Exec(ctx, `
		INSERT INTO team_credit_ledger (
			team_id, grant_id, amount_usd, reason
		)
		VALUES ($1, $2, -1.00, 'cross-team attribution should fail')
	`, ledgerTeamID, grantID)
	if err == nil {
		t.Fatal("expected cross-team credit ledger grant reference to fail")
	}
}

func numericFloat64(t *testing.T, n pgtype.Numeric) float64 {
	t.Helper()
	v, err := n.Float64Value()
	if err != nil {
		t.Fatalf("convert numeric: %v", err)
	}
	if !v.Valid {
		t.Fatal("numeric is null")
	}
	return v.Float64
}

// waitForSandboxStatus polls until the sandbox reaches want (or fails), rather
// than sleeping a fixed interval that goes flaky under load.
func waitForSandboxStatus(t *testing.T, ctx context.Context, id, teamID uuid.UUID, want db.SandboxStatus) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		sb, err := testQueries.GetSandbox(ctx, db.GetSandboxParams{ID: id, TeamID: teamID})
		if err != nil {
			t.Fatalf("get sandbox: %v", err)
		}
		if sb.Status == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("sandbox status = %q, want %q (timed out)", sb.Status, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A stale OPEN interval (a prior transition that failed to close it) must not
// break resume: before ON CONFLICT it collided and the handler tore the VM
// down. Now the open row is reused and resume succeeds.
func TestIntegration_ResumeSandbox_StaleOpenInterval(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"stale-box"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", cw.Code, cw.Body.String())
	}
	sid := mustJSON(t, cw)["id"].(string)
	sandboxID, _ := uuid.Parse(sid)

	if pw := do(r, "POST", "/sandboxes/"+sid+"/pause", apiKey, ""); pw.Code != http.StatusNoContent {
		t.Fatalf("pause: %d %s", pw.Code, pw.Body.String())
	}

	// Simulate the orphan: open a second interval while the sandbox is paused,
	// leaving its row dangling exactly as a missed close would.
	if err := testQueries.OpenSandboxActiveInterval(ctx, db.OpenSandboxActiveIntervalParams{
		SandboxID: sandboxID,
		TeamID:    teamID,
	}); err != nil {
		t.Fatalf("seed stale interval: %v", err)
	}
	if open := countOpenIntervals(t, ctx, sandboxID); open != 1 {
		t.Fatalf("setup: open intervals = %d, want 1", open)
	}

	rw := do(r, "POST", "/sandboxes/"+sid+"/resume", apiKey, "")
	if rw.Code != http.StatusOK {
		t.Fatalf("resume with stale interval: expected 200, got %d: %s", rw.Code, rw.Body.String())
	}

	waitForSandboxStatus(t, ctx, sandboxID, teamID, db.SandboxStatusActive)
	// ON CONFLICT DO NOTHING reuses the existing open row — no duplicate.
	if open := countOpenIntervals(t, ctx, sandboxID); open != 1 {
		t.Errorf("open intervals after resume = %d, want 1", open)
	}
}

// The reaper's orphan sweep closes intervals left open while their sandbox is
// no longer active, but only once the settle window has passed.
func TestIntegration_CloseOrphanedActiveIntervals(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"orphan-box"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", cw.Code, cw.Body.String())
	}
	sid := mustJSON(t, cw)["id"].(string)
	sandboxID, _ := uuid.Parse(sid)

	if pw := do(r, "POST", "/sandboxes/"+sid+"/pause", apiKey, ""); pw.Code != http.StatusNoContent {
		t.Fatalf("pause: %d %s", pw.Code, pw.Body.String())
	}
	if err := testQueries.OpenSandboxActiveInterval(ctx, db.OpenSandboxActiveIntervalParams{
		SandboxID: sandboxID,
		TeamID:    teamID,
	}); err != nil {
		t.Fatalf("seed stale interval: %v", err)
	}

	// Within the settle window → sweep must leave the fresh transition alone.
	if _, err := testQueries.CloseOrphanedActiveIntervals(ctx); err != nil {
		t.Fatalf("sweep (fresh): %v", err)
	}
	if open := countOpenIntervals(t, ctx, sandboxID); open != 1 {
		t.Errorf("within settle window: open = %d, want 1 (untouched)", open)
	}

	// Backdate past the settle window → sweep now closes the orphan.
	if _, err := testPool.Exec(ctx,
		`UPDATE sandbox SET updated_at = now() - interval '10 minutes' WHERE id = $1`, sandboxID); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	n, err := testQueries.CloseOrphanedActiveIntervals(ctx)
	if err != nil {
		t.Fatalf("sweep (settled): %v", err)
	}
	if n < 1 {
		t.Errorf("sweep closed %d rows, want >= 1", n)
	}
	if open := countOpenIntervals(t, ctx, sandboxID); open != 0 {
		t.Errorf("after settle window: open = %d, want 0 (closed)", open)
	}
}

// pauseAndRevert calls FinalizePause from 'resuming', not 'pausing'. Confirm on
// real Postgres that it has no source-status precondition: it flips to paused.
func TestIntegration_FinalizePause_FromResuming(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"finalize-resuming"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", cw.Code, cw.Body.String())
	}
	sid := mustJSON(t, cw)["id"].(string)
	sandboxID, _ := uuid.Parse(sid)
	// Pause first for a deterministic state, then force 'resuming' directly.
	if pw := do(r, "POST", "/sandboxes/"+sid+"/pause", apiKey, ""); pw.Code != http.StatusNoContent {
		t.Fatalf("pause: %d %s", pw.Code, pw.Body.String())
	}
	if _, err := testPool.Exec(ctx,
		`UPDATE sandbox SET status = 'resuming' WHERE id = $1`, sandboxID); err != nil {
		t.Fatalf("force resuming: %v", err)
	}

	mem := "/snapshots/" + sid + "/mem.snap"
	snapID, err := testQueries.FinalizePause(ctx, db.FinalizePauseParams{
		ID:      sandboxID,
		TeamID:  teamID,
		Path:    "/snapshots/" + sid + "/vmstate.snap",
		MemPath: &mem,
		Trigger: "resume_revert",
	})
	if err != nil {
		t.Fatalf("FinalizePause from resuming failed (status precondition?): %v", err)
	}
	if snapID == uuid.Nil {
		t.Fatal("FinalizePause returned nil snapshot id")
	}

	sb, err := testQueries.GetSandbox(ctx, db.GetSandboxParams{ID: sandboxID, TeamID: teamID})
	if err != nil {
		t.Fatalf("get sandbox: %v", err)
	}
	if sb.Status != db.SandboxStatusPaused {
		t.Errorf("status after FinalizePause = %q, want paused", sb.Status)
	}
}

// ---------------------------------------------------------------------------
// DELETE /sandboxes/:id
// ---------------------------------------------------------------------------

func TestIntegration_DeleteSandbox_Success(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"del-box"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", cw.Code, cw.Body.String())
	}
	sid := mustJSON(t, cw)["id"].(string)
	sandboxID, _ := uuid.Parse(sid)

	dw := do(r, "DELETE", "/sandboxes/"+sid, apiKey, "")
	if dw.Code != http.StatusNoContent {
		t.Fatalf("delete: expected 204, got %d: %s", dw.Code, dw.Body.String())
	}

	_, err := testQueries.GetSandbox(ctx, db.GetSandboxParams{ID: sandboxID, TeamID: teamID})
	if err == nil {
		t.Fatal("expected sandbox to be gone after delete")
	}

	// The revocation row is written in the same statement as the soft-delete.
	var revoked int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM sandbox_revocation WHERE sandbox_id = $1`, sandboxID).Scan(&revoked); err != nil {
		t.Fatalf("revocation query: %v", err)
	}
	if revoked != 1 {
		t.Errorf("sandbox_revocation rows = %d, want 1", revoked)
	}
}

// TestIntegration_DeleteStaleTransitionalSandbox proves DELETE claims a
// crash-wedged (stale) transitional sandbox but still 409s a live transition.
func TestIntegration_DeleteStaleTransitionalSandbox(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	insert := func(updatedAt time.Time) uuid.UUID {
		id := uuid.New()
		if _, err := testPool.Exec(ctx,
			`INSERT INTO sandbox (id, team_id, name, status, host_id, updated_at) VALUES ($1,$2,$3,'resuming','host-1',$4)`,
			id, teamID, "wedged", updatedAt); err != nil {
			t.Fatalf("insert: %v", err)
		}
		return id
	}

	// Stale (> grace) resuming row: the worker is provably gone, so it's deletable.
	stale := insert(time.Now().Add(-30 * time.Minute))
	if dw := do(r, "DELETE", "/sandboxes/"+stale.String(), apiKey, ""); dw.Code != http.StatusNoContent {
		t.Fatalf("delete stale transitional: got %d, want 204: %s", dw.Code, dw.Body.String())
	}

	// Fresh resuming row: a live transition must not be deletable (409).
	fresh := insert(time.Now())
	if fw := do(r, "DELETE", "/sandboxes/"+fresh.String(), apiKey, ""); fw.Code != http.StatusConflict {
		t.Fatalf("delete fresh transitional: got %d, want 409: %s", fw.Code, fw.Body.String())
	}
}

func TestIntegration_DeleteSandbox_NotFound(t *testing.T) {
	_, apiKey := seedTeamAndKey(t)
	w := do(newRouter(t), "DELETE", "/sandboxes/"+uuid.New().String(), apiKey, "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestIntegration_TeamIsolation_Delete(t *testing.T) {
	_, apiKeyA := seedTeamAndKey(t)
	_, apiKeyB := seedTeamAndKey(t)
	r := newRouter(t)

	// Team A creates a sandbox.
	cw := do(r, "POST", "/sandboxes", apiKeyA, `{"name":"teamA-box"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", cw.Code, cw.Body.String())
	}
	sid := mustJSON(t, cw)["id"].(string)

	// Team B cannot delete it.
	dw := do(r, "DELETE", "/sandboxes/"+sid, apiKeyB, "")
	if dw.Code != http.StatusNotFound {
		t.Fatalf("expected 404 (team isolation), got %d: %s", dw.Code, dw.Body.String())
	}

	// Team A can.
	dw2 := do(r, "DELETE", "/sandboxes/"+sid, apiKeyA, "")
	if dw2.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", dw2.Code)
	}
}

func TestIntegration_ActivityLog_DeleteRecorded(t *testing.T) {
	ctx := context.Background()
	_, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"actlog-box"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d", cw.Code)
	}
	sid := mustJSON(t, cw)["id"].(string)
	sandboxID, _ := uuid.Parse(sid)

	dw := do(r, "DELETE", "/sandboxes/"+sid, apiKey, "")
	if dw.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", dw.Code)
	}

	time.Sleep(100 * time.Millisecond)
	activities, err := testQueries.ListActivityBySandbox(ctx, db.ListActivityBySandboxParams{
		SandboxID: pgtype.UUID{Bytes: sandboxID, Valid: true},
		Limit:     20,
	})
	if err != nil {
		t.Fatalf("list activities: %v", err)
	}

	var found bool
	for _, a := range activities {
		if a.Category == "sandbox" && a.Action == "deleted" {
			found = true
			if a.Status == nil || *a.Status != "success" {
				t.Errorf("activity status = %v, want success", a.Status)
			}
			if a.SandboxName == nil || *a.SandboxName != "actlog-box" {
				t.Errorf("activity sandbox_name = %v, want actlog-box", a.SandboxName)
			}
		}
	}
	if !found {
		t.Error("no 'sandbox/deleted' activity record after DELETE")
	}
}

func TestIntegration_ActivityLog_PauseRecorded(t *testing.T) {
	ctx := context.Background()
	_, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"pause-log-box"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d", cw.Code)
	}
	sid := mustJSON(t, cw)["id"].(string)
	sandboxID, _ := uuid.Parse(sid)

	pw := do(r, "POST", "/sandboxes/"+sid+"/pause", apiKey, "")
	if pw.Code != http.StatusNoContent {
		t.Fatalf("pause: %d %s", pw.Code, pw.Body.String())
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		activities, err := testQueries.ListActivityBySandbox(ctx, db.ListActivityBySandboxParams{
			SandboxID: pgtype.UUID{Bytes: sandboxID, Valid: true},
			Limit:     20,
		})
		if err != nil {
			t.Fatalf("list activities: %v", err)
		}

		for _, a := range activities {
			if a.Category == "sandbox" && a.Action == "paused" {
				return
			}
		}
		time.Sleep(25 * time.Millisecond)
	}

	t.Error("no 'sandbox/paused' activity record after pause")
}

func TestIntegration_ActivityLog_ActorAttributedToKeyCreator(t *testing.T) {
	ctx := context.Background()
	_, apiKey, profileID := seedTeamKeyAndProfile(t)
	r := newRouter(t)

	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"actor-box"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", cw.Code, cw.Body.String())
	}
	sid := mustJSON(t, cw)["id"].(string)
	sandboxID, _ := uuid.Parse(sid)

	time.Sleep(100 * time.Millisecond)
	activities, err := testQueries.ListActivityBySandbox(ctx, db.ListActivityBySandboxParams{
		SandboxID: pgtype.UUID{Bytes: sandboxID, Valid: true},
		Limit:     20,
	})
	if err != nil {
		t.Fatalf("list activities: %v", err)
	}

	var found bool
	for _, a := range activities {
		if a.Category == "sandbox" && a.Action == "started" {
			found = true
			if !a.ActorID.Valid {
				t.Errorf("actor_id = NULL, want %s", profileID)
			} else if uuid.UUID(a.ActorID.Bytes) != profileID {
				t.Errorf("actor_id = %s, want %s", uuid.UUID(a.ActorID.Bytes), profileID)
			}
		}
	}
	if !found {
		t.Error("no 'sandbox/started' activity record after create")
	}
}

func TestIntegration_ProtectedEndpointRejectsKeyWithoutCreator(t *testing.T) {
	_, apiKey := seedTeamAndKeyNoCreator(t)
	r := newRouter(t)

	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"null-actor-box"}`)
	if cw.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden for key without creator, got %d: %s", cw.Code, cw.Body.String())
	}
}

func TestIntegration_ConcurrentCreate(t *testing.T) {
	_, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	const n = 5
	type result struct {
		code int
		id   string
	}
	ch := make(chan result, n)
	var wg sync.WaitGroup

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			w := do(r, "POST", "/sandboxes", apiKey, fmt.Sprintf(`{"name":"concurrent-%d"}`, i))
			res := result{code: w.Code}
			if w.Code == http.StatusCreated {
				var b map[string]interface{}
				json.Unmarshal(w.Body.Bytes(), &b) //nolint:errcheck
				res.id, _ = b["id"].(string)
			}
			ch <- res
		}(i)
	}

	wg.Wait()
	close(ch)

	seen := map[string]bool{}
	for res := range ch {
		if res.code != http.StatusCreated {
			t.Errorf("concurrent create: expected 201, got %d", res.code)
		}
		if res.id != "" {
			if seen[res.id] {
				t.Errorf("duplicate sandbox ID: %s", res.id)
			}
			seen[res.id] = true
		}
	}
}

func TestIntegration_PatchSandbox_Network_Success(t *testing.T) {
	teamID, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"net-box"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", cw.Code, cw.Body.String())
	}
	sid := mustJSON(t, cw)["id"].(string)
	sandboxUUID, _ := uuid.Parse(sid)

	nw := do(r, "PATCH", "/sandboxes/"+sid, apiKey,
		`{"network":{"allow_out":["api.openai.com","8.8.8.8/32"],"deny_out":["0.0.0.0/0"]}}`)
	if nw.Code != http.StatusNoContent {
		t.Fatalf("patch network: expected 204, got %d: %s", nw.Code, nw.Body.String())
	}

	// Verify config persisted in DB.
	row, err := testQueries.GetSandboxNetworkConfig(context.Background(), db.GetSandboxNetworkConfigParams{
		ID:     sandboxUUID,
		TeamID: teamID,
	})
	if err != nil {
		t.Fatalf("get network config: %v", err)
	}
	if row == nil {
		t.Fatal("network_config is nil after patch")
	}
}

func TestIntegration_PatchSandbox_Network_NotActive(t *testing.T) {
	_, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"net-paused"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", cw.Code, cw.Body.String())
	}
	sid := mustJSON(t, cw)["id"].(string)
	// Pause it so it's in paused state.
	pw := do(r, "POST", "/sandboxes/"+sid+"/pause", apiKey, "")
	if pw.Code != http.StatusNoContent {
		t.Fatalf("pause: %d %s", pw.Code, pw.Body.String())
	}

	// Try to patch network on paused sandbox — should fail.
	nw := do(r, "PATCH", "/sandboxes/"+sid, apiKey,
		`{"network":{"deny_out":["0.0.0.0/0"]}}`)
	if nw.Code != http.StatusConflict {
		t.Fatalf("expected 409 for paused sandbox, got %d: %s", nw.Code, nw.Body.String())
	}
}

func TestIntegration_PatchSandbox_Network_InvalidDenyCIDR(t *testing.T) {
	_, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"net-invalid"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", cw.Code, cw.Body.String())
	}
	sid := mustJSON(t, cw)["id"].(string)
	// deny_out with a domain (not a CIDR) should fail validation.
	nw := do(r, "PATCH", "/sandboxes/"+sid, apiKey,
		`{"network":{"deny_out":["evil.com"]}}`)
	if nw.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for domain in deny_out, got %d: %s", nw.Code, nw.Body.String())
	}
}

func TestIntegration_PatchSandbox_NotFound(t *testing.T) {
	_, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	nw := do(r, "PATCH", "/sandboxes/00000000-0000-0000-0000-000000000000", apiKey,
		`{"network":{"deny_out":["0.0.0.0/0"]}}`)
	if nw.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", nw.Code, nw.Body.String())
	}
}

// Empty patch body — at least one top-level field must be present.
func TestIntegration_PatchSandbox_EmptyBody(t *testing.T) {
	_, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"net-empty"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", cw.Code, cw.Body.String())
	}
	sid := mustJSON(t, cw)["id"].(string)

	nw := do(r, "PATCH", "/sandboxes/"+sid, apiKey, `{}`)
	if nw.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty patch body, got %d: %s", nw.Code, nw.Body.String())
	}
}

// Unknown top-level fields are rejected by the strict JSON decoder so typos
// surface as 400s instead of silent no-ops.
func TestIntegration_PatchSandbox_UnknownField(t *testing.T) {
	_, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"net-unknown"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", cw.Code, cw.Body.String())
	}
	sid := mustJSON(t, cw)["id"].(string)

	nw := do(r, "PATCH", "/sandboxes/"+sid, apiKey, `{"netwrk":{"deny_out":["0.0.0.0/0"]}}`)
	if nw.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown field, got %d: %s", nw.Code, nw.Body.String())
	}
}

func TestIntegration_CreateSandbox_WithNetworkConfig(t *testing.T) {
	_, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	cw := do(r, "POST", "/sandboxes", apiKey,
		`{"name":"net-create","network":{"allow_out":["api.openai.com"],"deny_out":["0.0.0.0/0"]}}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create with network: %d %s", cw.Code, cw.Body.String())
	}
	body := mustJSON(t, cw)
	if body["status"] != "active" {
		t.Errorf("expected status=active, got %v", body["status"])
	}
}

func TestIntegration_SecurityHeaders(t *testing.T) {
	r := newRouter(t)

	w := do(r, "GET", "/health", "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("health: %d", w.Code)
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing X-Content-Type-Options: nosniff")
	}
	if w.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("missing X-Frame-Options: DENY")
	}
	if w.Header().Get("Strict-Transport-Security") == "" {
		t.Error("missing Strict-Transport-Security")
	}
}

func TestIntegration_CreateSandbox_WithMetadata(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	w := do(r, "POST", "/sandboxes", apiKey,
		`{"name":"tagged","metadata":{"env":"prod","owner":"agent-7"}}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	body := mustJSON(t, w)
	md, ok := body["metadata"].(map[string]interface{})
	if !ok {
		t.Fatalf("response metadata not an object: %v", body["metadata"])
	}
	if md["env"] != "prod" || md["owner"] != "agent-7" {
		t.Fatalf("response metadata = %v", md)
	}

	// DB row carries the same jsonb.
	sandboxID, _ := uuid.Parse(body["id"].(string))
	sb, err := testQueries.GetSandbox(ctx, db.GetSandboxParams{ID: sandboxID, TeamID: teamID})
	if err != nil {
		t.Fatalf("get sandbox: %v", err)
	}
	var roundTrip map[string]string
	if err := json.Unmarshal(sb.Metadata, &roundTrip); err != nil {
		t.Fatalf("decode persisted metadata: %v", err)
	}
	if roundTrip["env"] != "prod" || roundTrip["owner"] != "agent-7" {
		t.Fatalf("persisted metadata = %v", roundTrip)
	}
}

func TestIntegration_CreateSandbox_NoMetadataDefaultsEmptyObject(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	w := do(r, "POST", "/sandboxes", apiKey, `{"name":"plain"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}

	// Response must include metadata as an empty object, not null/missing.
	if !strings.Contains(w.Body.String(), `"metadata":{}`) {
		t.Errorf("response should include \"metadata\":{}, got %s", w.Body.String())
	}

	// DB row must be the empty jsonb object (NOT NULL constraint enforces this).
	sandboxID, _ := uuid.Parse(mustJSON(t, w)["id"].(string))
	sb, err := testQueries.GetSandbox(ctx, db.GetSandboxParams{ID: sandboxID, TeamID: teamID})
	if err != nil {
		t.Fatalf("get sandbox: %v", err)
	}
	if string(sb.Metadata) != "{}" {
		t.Errorf("persisted metadata = %q, want %q", string(sb.Metadata), "{}")
	}
}

func TestIntegration_CreateSandbox_MetadataAdversarial(t *testing.T) {
	_, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	// Build adversarial payloads that should each return 400.
	cases := []struct {
		name string
		body string
	}{
		{
			name: "reserved prefix",
			body: `{"name":"x","metadata":{"superserve.tier":"gold"}}`,
		},
		{
			name: "reserved underscore prefix",
			body: `{"name":"x","metadata":{"_superserve_internal":"x"}}`,
		},
		{
			name: "key too long",
			body: fmt.Sprintf(`{"name":"x","metadata":{%q:"v"}}`, strings.Repeat("k", 257)),
		},
		{
			name: "value too long",
			body: fmt.Sprintf(`{"name":"x","metadata":{"k":%q}}`, strings.Repeat("v", 2049)),
		},
		{
			name: "empty key",
			body: `{"name":"x","metadata":{"":"v"}}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := do(r, "POST", "/sandboxes", apiKey, tc.body)
			if w.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400; body: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestIntegration_CreateSandbox_MetadataTooManyKeys(t *testing.T) {
	_, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	// 65 keys exceeds the cap of 64.
	pairs := make([]string, 0, 65)
	for i := 0; i < 65; i++ {
		pairs = append(pairs, fmt.Sprintf("%q:%q", fmt.Sprintf("k%d", i), "v"))
	}
	body := fmt.Sprintf(`{"name":"x","metadata":{%s}}`, strings.Join(pairs, ","))

	w := do(r, "POST", "/sandboxes", apiKey, body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
}

func TestIntegration_CreateSandbox_MetadataTotalSizeExceeded(t *testing.T) {
	_, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	// 9 values × ~2 KB each = ~18 KB > 16 KB cap.
	bigVal := strings.Repeat("v", 2048)
	pairs := make([]string, 0, 9)
	for i := 0; i < 9; i++ {
		pairs = append(pairs, fmt.Sprintf("%q:%q", fmt.Sprintf("k%d", i), bigVal))
	}
	body := fmt.Sprintf(`{"name":"x","metadata":{%s}}`, strings.Join(pairs, ","))

	w := do(r, "POST", "/sandboxes", apiKey, body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
}

func TestIntegration_ListSandboxes_FilterByMetadata(t *testing.T) {
	_, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	// Create three sandboxes with overlapping but distinct tag sets.
	bodies := []string{
		`{"name":"a","metadata":{"env":"prod","owner":"alice"}}`,
		`{"name":"b","metadata":{"env":"prod","owner":"bob"}}`,
		`{"name":"c","metadata":{"env":"staging","owner":"alice"}}`,
	}
	for i, body := range bodies {
		cw := do(r, "POST", "/sandboxes", apiKey, body)
		if cw.Code != http.StatusCreated {
			t.Fatalf("create[%d]: %d %s", i, cw.Code, cw.Body.String())
		}
	}

	// Filter by env=prod → expect a, b.
	w := do(r, "GET", "/sandboxes?metadata.env=prod", apiKey, "")
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	var got []map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("parse: %v", err)
	}
	names := map[string]bool{}
	for _, item := range got {
		names[item["name"].(string)] = true
	}
	if !names["a"] || !names["b"] || names["c"] {
		t.Errorf("env=prod filter returned wrong set: %v", names)
	}

	// AND filter env=prod & owner=alice → expect only a.
	w = do(r, "GET", "/sandboxes?metadata.env=prod&metadata.owner=alice", apiKey, "")
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 1 || got[0]["name"] != "a" {
		t.Errorf("env=prod&owner=alice should return only [a], got %v", got)
	}

	// Non-matching value → empty list.
	w = do(r, "GET", "/sandboxes?metadata.env=nope", apiKey, "")
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("env=nope should return empty list, got %v", got)
	}
}

func TestIntegration_ListSandboxes_FilterIsolatedPerTeam(t *testing.T) {
	_, apiKeyA := seedTeamAndKey(t)
	_, apiKeyB := seedTeamAndKey(t)
	r := newRouter(t)

	// Team A creates a sandbox tagged env=prod.
	if cw := do(r, "POST", "/sandboxes", apiKeyA,
		`{"name":"a","metadata":{"env":"prod"}}`); cw.Code != http.StatusCreated {
		t.Fatalf("team A create: %d %s", cw.Code, cw.Body.String())
	}

	// Team B filters env=prod and must not see team A's sandbox.
	w := do(r, "GET", "/sandboxes?metadata.env=prod", apiKeyB, "")
	if w.Code != http.StatusOK {
		t.Fatalf("team B list: %d %s", w.Code, w.Body.String())
	}
	var got []map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("team B should see 0 sandboxes, got %d", len(got))
	}
}

func TestIntegration_ListSandboxes_FilterRejectsAdversarial(t *testing.T) {
	_, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	// Reserved prefix in filter is also rejected (uses same validateMetadata).
	w := do(r, "GET", "/sandboxes?metadata.superserve.tier=gold", apiKey, "")
	if w.Code != http.StatusBadRequest {
		t.Errorf("reserved prefix in filter: status = %d, want 400; body: %s", w.Code, w.Body.String())
	}

	// Empty filter key is rejected.
	w = do(r, "GET", "/sandboxes?metadata.=v", apiKey, "")
	if w.Code != http.StatusBadRequest {
		t.Errorf("empty filter key: status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
}

func TestIntegration_RateLimit_Headers(t *testing.T) {
	r := newRouter(t)

	w := do(r, "GET", "/health", "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("health: %d", w.Code)
	}
	if w.Header().Get("RateLimit-Limit") == "" {
		t.Error("missing RateLimit-Limit header")
	}
	if w.Header().Get("RateLimit-Remaining") == "" {
		t.Error("missing RateLimit-Remaining header")
	}
}

// TestIntegration_CreateTemplate_NameReusableAfterDelete verifies the partial
// unique index on (team_id, name) WHERE deleted_at IS NULL: once a template
// is soft-deleted its name can be reused for a fresh template.
func TestIntegration_CreateTemplate_NameReusableAfterDelete(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	const name = "reuse-me"

	// Insert a template directly and mark it soft-deleted, simulating the
	// state after DELETE /templates/{id}. We bypass POST /templates here
	// because that path queues a build, which would block deletion.
	old, err := testQueries.CreateTemplate(ctx, db.CreateTemplateParams{
		TeamID:    teamID,
		Name:      name,
		BuildSpec: []byte(`{"from":"debian:12-slim","steps":[]}`),
		Vcpu:      1,
		MemoryMib: 1024,
		DiskMib:   4096,
	})
	if err != nil {
		t.Fatalf("seed template: %v", err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE template SET deleted_at = now() WHERE id = $1`, old.ID); err != nil {
		t.Fatalf("soft-delete: %v", err)
	}

	// Same name on a fresh POST /templates must succeed.
	body := fmt.Sprintf(`{"name":%q,"build_spec":{"from":"debian:12-slim","steps":[]}}`, name)
	w := do(r, "POST", "/templates", apiKey, body)
	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", w.Code, w.Body.String())
	}
	resp := mustJSON(t, w)
	if resp["name"] != name {
		t.Errorf("name = %q, want %q", resp["name"], name)
	}

	newID, _ := uuid.Parse(resp["id"].(string))
	if newID == old.ID {
		t.Fatal("expected a fresh template id; got the soft-deleted row's id")
	}

	// Both rows exist in DB: the old one with deleted_at set, the new one without.
	var liveCount, deletedCount int
	if err := testPool.QueryRow(ctx,
		`SELECT
		   COUNT(*) FILTER (WHERE deleted_at IS NULL),
		   COUNT(*) FILTER (WHERE deleted_at IS NOT NULL)
		 FROM template WHERE team_id = $1 AND name = $2`,
		teamID, name,
	).Scan(&liveCount, &deletedCount); err != nil {
		t.Fatalf("count check: %v", err)
	}
	if liveCount != 1 || deletedCount != 1 {
		t.Errorf("DB state: live=%d deleted=%d, want 1/1", liveCount, deletedCount)
	}
}

// TestIntegration_CreateTemplate_NameCharSet rejects names that don't match
// the lowercase/`._/-` allowlist with a 400.
func TestIntegration_CreateTemplate_NameCharSet(t *testing.T) {
	_, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	cases := []struct {
		name    string
		ok      bool
		comment string
	}{
		{"foo", true, "lowercase ok"},
		{"my-python-env", true, "hyphens ok"},
		{"a/b/c", true, "slashes ok"},
		{"foo.bar", true, "dot ok"},
		{"f", true, "single char ok"},
		{"Foo", false, "capitals rejected"},
		{"foo bar", false, "space rejected"},
		{"-foo", false, "leading hyphen rejected"},
		{"foo-", false, "trailing hyphen rejected"},
		{"/foo", false, "leading slash rejected"},
		{"foo/", false, "trailing slash rejected"},
		{"foo!", false, "punctuation rejected"},
		{"", false, "empty rejected"},
	}
	for _, tc := range cases {
		body := fmt.Sprintf(`{"name":%q,"build_spec":{"from":"debian:12-slim","steps":[]}}`, tc.name)
		w := do(r, "POST", "/templates", apiKey, body)
		if tc.ok {
			if w.Code != http.StatusAccepted {
				t.Errorf("%s: expected 202, got %d (%s)", tc.comment, w.Code, w.Body.String())
			}
		} else {
			if w.Code != http.StatusBadRequest {
				t.Errorf("%s: name=%q expected 400, got %d", tc.comment, tc.name, w.Code)
			}
		}
	}
}

// TestIntegration_CreateTemplate_DuplicateLiveNameReturns409 is the negative
// case: a non-deleted template's name still blocks a duplicate.
func TestIntegration_CreateTemplate_DuplicateLiveNameReturns409(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	const name = "taken"
	if _, err := testQueries.CreateTemplate(ctx, db.CreateTemplateParams{
		TeamID:    teamID,
		Name:      name,
		BuildSpec: []byte(`{"from":"debian:12-slim","steps":[]}`),
		Vcpu:      1,
		MemoryMib: 1024,
		DiskMib:   4096,
	}); err != nil {
		t.Fatalf("seed template: %v", err)
	}

	body := fmt.Sprintf(`{"name":%q,"build_spec":{"from":"debian:12-slim","steps":[]}}`, name)
	w := do(r, "POST", "/templates", apiKey, body)
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
}
