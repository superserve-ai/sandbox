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
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
)

// ---------------------------------------------------------------------------
// Test infrastructure
// ---------------------------------------------------------------------------

var (
	testPool    *pgxpool.Pool
	testQueries *db.Queries
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

	if err := applyMigrations(ctx, testPool); err != nil {
		fmt.Fprintf(os.Stderr, "migration failed: %v\n", err)
		os.Exit(1)
	}

	testQueries = db.New(testPool)
	os.Exit(m.Run())
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

func (s *stubVMD) CreateInstance(_ context.Context, _ string, _, _, _ uint32, _ map[string]string) (string, uint32, uint32, error) {
	return "10.0.0.1", 1, 1024, nil
}
func (s *stubVMD) DestroyInstance(_ context.Context, _ string, _ bool) error { return nil }
func (s *stubVMD) PauseInstance(_ context.Context, _, _ string) (string, string, error) {
	return "/snapshots/disk.snap", "/snapshots/mem.snap", nil
}
func (s *stubVMD) ResumeInstance(_ context.Context, _, _, _ string) (string, error) {
	return "10.0.0.1", nil
}
func (s *stubVMD) ExecCommand(_ context.Context, _, _ string, _ []string, _ map[string]string, _ string, _ uint32) (string, string, int32, error) {
	return "hello\n", "", 0, nil
}
func (s *stubVMD) ExecCommandStream(_ context.Context, _, _ string, _ []string, _ map[string]string, _ string, _ uint32, onChunk func([]byte, []byte, int32, bool)) error {
	onChunk([]byte("hello\n"), nil, 0, false)
	onChunk(nil, nil, 0, true)
	return nil
}
func (s *stubVMD) UpdateSandboxNetwork(_ context.Context, _ string, _, _, _ []string) error {
	return nil
}

// seedTeamAndKey inserts a team + API key and returns (teamID, rawKey).
func seedTeamAndKey(t *testing.T) (uuid.UUID, string) {
	t.Helper()
	ctx := context.Background()

	team, err := testQueries.CreateTeam(ctx, "team-"+uuid.New().String()[:8])
	if err != nil {
		t.Fatalf("seedTeamAndKey: create team: %v", err)
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
		t.Fatalf("seedTeamAndKey: create api key: %v", err)
	}

	return team.ID, rawKey
}

// newRouter builds a router scoped to the current test. Using t.Context()
// ensures the rate limiter's cleanup goroutine exits when the test ends,
// preventing goroutine leaks across hundreds of test invocations.
func newRouter(t *testing.T) *gin.Engine {
	t.Helper()
	cfg := &config.Config{Port: "0", VMDAddress: "localhost:0"}
	h := api.NewHandlers(&stubVMD{}, testQueries, cfg)
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

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// POST /sandboxes
// ---------------------------------------------------------------------------

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
	if sb.MemoryMib != 512 {
		t.Errorf("memory_mib = %d, want 512", sb.MemoryMib)
	}
}

// ---------------------------------------------------------------------------
// GET /sandboxes and GET /sandboxes/:id
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// POST /sandboxes/:id/pause
// ---------------------------------------------------------------------------

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
	if pw.Code != http.StatusOK {
		t.Fatalf("pause: expected 200, got %d: %s", pw.Code, pw.Body.String())
	}
	pb := mustJSON(t, pw)
	if pb["status"] != "idle" {
		t.Errorf("pause status = %q, want idle", pb["status"])
	}
	snapshotIDStr, ok := pb["snapshot_id"].(string)
	if !ok || snapshotIDStr == "" {
		t.Fatal("pause response missing snapshot_id")
	}

	// DB: sandbox is idle, snapshot record exists and is linked.
	sandboxID, _ := uuid.Parse(sid)
	sb, err := testQueries.GetSandbox(ctx, db.GetSandboxParams{ID: sandboxID, TeamID: teamID})
	if err != nil {
		t.Fatalf("get sandbox: %v", err)
	}
	if sb.Status != db.SandboxStatusIdle {
		t.Errorf("DB status = %q, want idle", sb.Status)
	}
	if !sb.SnapshotID.Valid {
		t.Error("sandbox snapshot_id should be set after pause")
	}

	snapID, _ := uuid.Parse(snapshotIDStr)
	snap, err := testQueries.GetSnapshot(ctx, snapID)
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

func TestIntegration_PauseSandbox_AlreadyIdle(t *testing.T) {
	_, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"idle-box"}`)
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

// ---------------------------------------------------------------------------
// POST /sandboxes/:id/resume
// ---------------------------------------------------------------------------

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
	if pw.Code != http.StatusOK {
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
}

func TestIntegration_DeleteSandbox_NotFound(t *testing.T) {
	_, apiKey := seedTeamAndKey(t)
	w := do(newRouter(t), "DELETE", "/sandboxes/"+uuid.New().String(), apiKey, "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// POST /sandboxes/:id/exec
// ---------------------------------------------------------------------------

func TestIntegration_ExecSandbox_Success(t *testing.T) {
	ctx := context.Background()
	_, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"exec-box"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", cw.Code, cw.Body.String())
	}
	sid := mustJSON(t, cw)["id"].(string)
	ew := do(r, "POST", "/sandboxes/"+sid+"/exec", apiKey, `{"command":"echo hello","timeout_s":5}`)
	if ew.Code != http.StatusOK {
		t.Fatalf("exec: expected 200, got %d: %s", ew.Code, ew.Body.String())
	}
	eb := mustJSON(t, ew)
	if eb["stdout"] != "hello\n" {
		t.Errorf("stdout = %q, want hello\\n", eb["stdout"])
	}
	if int(eb["exit_code"].(float64)) != 0 {
		t.Errorf("exit_code = %v, want 0", eb["exit_code"])
	}

	// Activity logged asynchronously.
	time.Sleep(100 * time.Millisecond)
	sandboxID, _ := uuid.Parse(sid)
	activities, err := testQueries.ListActivityBySandbox(ctx, db.ListActivityBySandboxParams{
		SandboxID: sandboxID,
		Limit:     20,
	})
	if err != nil {
		t.Fatalf("list activities: %v", err)
	}
	var foundExec bool
	for _, a := range activities {
		if a.Category == "exec" && a.Action == "executed" {
			foundExec = true
		}
	}
	if !foundExec {
		t.Error("expected exec activity record after exec")
	}
}

func TestIntegration_ExecSandbox_AutoWakeIdleSandbox(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"wake-box"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d", cw.Code)
	}
	sid := mustJSON(t, cw)["id"].(string)

	pw := do(r, "POST", "/sandboxes/"+sid+"/pause", apiKey, "")
	if pw.Code != http.StatusOK {
		t.Fatalf("pause: %d %s", pw.Code, pw.Body.String())
	}

	// Exec on idle sandbox — AutoWake middleware should resume transparently.
	ew := do(r, "POST", "/sandboxes/"+sid+"/exec", apiKey, `{"command":"echo hello"}`)
	if ew.Code != http.StatusOK {
		t.Fatalf("exec on idle: expected 200, got %d: %s", ew.Code, ew.Body.String())
	}

	// DB: active after auto-wake.
	time.Sleep(50 * time.Millisecond)
	sandboxID, _ := uuid.Parse(sid)
	sb, err := testQueries.GetSandbox(ctx, db.GetSandboxParams{ID: sandboxID, TeamID: teamID})
	if err != nil {
		t.Fatalf("get sandbox: %v", err)
	}
	if sb.Status != db.SandboxStatusActive {
		t.Errorf("DB status = %q after auto-wake, want active", sb.Status)
	}
}

// ---------------------------------------------------------------------------
// Team isolation
// ---------------------------------------------------------------------------

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

func TestIntegration_TeamIsolation_Exec(t *testing.T) {
	_, apiKeyA := seedTeamAndKey(t)
	_, apiKeyB := seedTeamAndKey(t)
	r := newRouter(t)

	cw := do(r, "POST", "/sandboxes", apiKeyA, `{"name":"iso-exec"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d", cw.Code)
	}
	sid := mustJSON(t, cw)["id"].(string)

	ew := do(r, "POST", "/sandboxes/"+sid+"/exec", apiKeyB, `{"command":"id"}`)
	if ew.Code != http.StatusNotFound {
		t.Fatalf("expected 404 (team isolation on exec), got %d: %s", ew.Code, ew.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Activity logging
// ---------------------------------------------------------------------------

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
		SandboxID: sandboxID,
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
	if pw.Code != http.StatusOK {
		t.Fatalf("pause: %d %s", pw.Code, pw.Body.String())
	}

	time.Sleep(100 * time.Millisecond)
	activities, err := testQueries.ListActivityBySandbox(ctx, db.ListActivityBySandboxParams{
		SandboxID: sandboxID,
		Limit:     20,
	})
	if err != nil {
		t.Fatalf("list activities: %v", err)
	}

	var found bool
	for _, a := range activities {
		if a.Category == "sandbox" && a.Action == "paused" {
			found = true
		}
	}
	if !found {
		t.Error("no 'sandbox/paused' activity record after pause")
	}
}

// ---------------------------------------------------------------------------
// Concurrent sandbox creation via API
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// PATCH /sandboxes/:id
// ---------------------------------------------------------------------------

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

	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"net-idle"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", cw.Code, cw.Body.String())
	}
	sid := mustJSON(t, cw)["id"].(string)
	// Pause it so it's in idle state.
	pw := do(r, "POST", "/sandboxes/"+sid+"/pause", apiKey, "")
	if pw.Code != http.StatusOK {
		t.Fatalf("pause: %d %s", pw.Code, pw.Body.String())
	}

	// Try to patch network on idle sandbox — should fail.
	nw := do(r, "PATCH", "/sandboxes/"+sid, apiKey,
		`{"network":{"deny_out":["0.0.0.0/0"]}}`)
	if nw.Code != http.StatusConflict {
		t.Fatalf("expected 409 for idle sandbox, got %d: %s", nw.Code, nw.Body.String())
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

// ---------------------------------------------------------------------------
// POST /sandboxes with network config
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Security headers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Sandbox metadata
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

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
