//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"io"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	dbmigrate "github.com/superserve-ai/sandbox/db"
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

	// Run migrations.
	if err := dbmigrate.MigrateUp(ctx, testPool); err != nil {
		fmt.Fprintf(os.Stderr, "migration failed: %v\n", err)
		os.Exit(1)
	}

	testQueries = db.New(testPool)

	os.Exit(m.Run())
}

// seedTeamAndKey creates a team and API key, returns (teamID, rawAPIKey).
func seedTeamAndKey(t *testing.T, ctx context.Context) (uuid.UUID, string) {
	t.Helper()

	team, err := testQueries.CreateTeam(ctx, "test-team-"+uuid.New().String()[:8])
	if err != nil {
		t.Fatalf("create team: %v", err)
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
		t.Fatalf("create api key: %v", err)
	}

	return team.ID, rawKey
}

// stubVMD is a minimal VMDClient for integration tests that does not call a real VMD.
type stubVMD struct{}

func (s *stubVMD) CreateInstance(ctx context.Context, instanceID string, vcpu, memMiB, diskMiB uint32, metadata map[string]string) (string, error) {
	return "10.0.0.1", nil
}
func (s *stubVMD) DestroyInstance(ctx context.Context, instanceID string, force bool) error {
	return nil
}
func (s *stubVMD) PauseInstance(ctx context.Context, instanceID, snapshotDir string) (string, string, error) {
	return "/snap", "/mem", nil
}
func (s *stubVMD) ResumeInstance(ctx context.Context, instanceID, snapshotPath, memPath string) (string, error) {
	return "10.0.0.1", nil
}
func (s *stubVMD) ExecCommand(ctx context.Context, instanceID, command string, args []string, env map[string]string, workingDir string, timeoutS uint32) (string, string, int32, error) {
	return "ok\n", "", 0, nil
}
func (s *stubVMD) ExecCommandStream(ctx context.Context, instanceID, command string, args []string, env map[string]string, workingDir string, timeoutS uint32, onChunk func([]byte, []byte, int32, bool)) error {
	onChunk([]byte("ok\n"), nil, 0, true)
	return nil
}
func (s *stubVMD) UploadFile(ctx context.Context, instanceID, path string, content io.Reader) (int64, error) {
	return 0, nil
}
func (s *stubVMD) DownloadFile(ctx context.Context, instanceID, path string) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("")), nil
}

func setupIntegrationRouter(t *testing.T) *gin.Engine {
	t.Helper()
	cfg := &config.Config{Port: "0", VMDAddress: "localhost:0"}
	h := api.NewHandlers(&stubVMD{}, testQueries, cfg)
	return api.SetupRouter(h, testPool)
}

func doRequest(r *gin.Engine, method, path, apiKey string, body string) *httptest.ResponseRecorder {
	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	var req *http.Request
	if reader != nil {
		req, _ = http.NewRequest(method, path, reader)
	} else {
		req, _ = http.NewRequest(method, path, nil)
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func parseBody(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("parse JSON: %v\nbody: %s", err, w.Body.String())
	}
	return m
}

// ---------------------------------------------------------------------------
// Auth integration tests
// ---------------------------------------------------------------------------

func TestIntegration_AuthValidKey(t *testing.T) {
	ctx := context.Background()
	_, apiKey := seedTeamAndKey(t, ctx)

	r := setupIntegrationRouter(t)
	w := doRequest(r, "GET", "/health", "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("health check failed: %d", w.Code)
	}

	// Auth-protected endpoint with valid key.
	w = doRequest(r, "POST", "/instances", apiKey, `{"name":"int-test"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
}

func TestIntegration_AuthMissingKey(t *testing.T) {
	r := setupIntegrationRouter(t)
	w := doRequest(r, "POST", "/instances", "", `{"name":"no-auth"}`)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestIntegration_AuthInvalidKey(t *testing.T) {
	r := setupIntegrationRouter(t)
	w := doRequest(r, "POST", "/instances", "sk-fake-does-not-exist", `{"name":"bad-key"}`)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestIntegration_AuthRevokedKey(t *testing.T) {
	ctx := context.Background()
	_, apiKey := seedTeamAndKey(t, ctx)

	// Revoke the key.
	hash := sha256.Sum256([]byte(apiKey))
	keyHash := hex.EncodeToString(hash[:])
	keyRecord, err := testQueries.GetAPIKeyByHashV2(ctx, keyHash)
	if err != nil {
		t.Fatalf("get key: %v", err)
	}
	if err := testQueries.RevokeAPIKeyV2(ctx, keyRecord.ID); err != nil {
		t.Fatalf("revoke key: %v", err)
	}

	r := setupIntegrationRouter(t)
	w := doRequest(r, "POST", "/instances", apiKey, `{"name":"revoked"}`)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for revoked key, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Sandbox lifecycle: create → delete
// ---------------------------------------------------------------------------

func TestIntegration_SandboxLifecycle(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey := seedTeamAndKey(t, ctx)

	r := setupIntegrationRouter(t)

	// Create a sandbox in DB.
	sandbox, err := testQueries.CreateSandbox(ctx, db.CreateSandboxParams{
		TeamID:    teamID,
		Name:      "lifecycle-test",
		Status:    db.SandboxStatusActive,
		VcpuCount: 1,
		MemoryMib: 512,
	})
	if err != nil {
		t.Fatalf("create sandbox: %v", err)
	}

	// Delete it via API.
	w := doRequest(r, "DELETE", "/sandboxes/"+sandbox.ID.String(), apiKey, "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
	}

	// Verify soft-deleted.
	_, err = testQueries.GetSandbox(ctx, db.GetSandboxParams{
		ID:     sandbox.ID,
		TeamID: teamID,
	})
	if err == nil {
		t.Fatal("expected sandbox to be soft-deleted (not found)")
	}
}

// ---------------------------------------------------------------------------
// Team isolation
// ---------------------------------------------------------------------------

func TestIntegration_TeamIsolation(t *testing.T) {
	ctx := context.Background()
	teamA, apiKeyA := seedTeamAndKey(t, ctx)
	_, _ = seedTeamAndKey(t, ctx) // teamB (unused key)

	r := setupIntegrationRouter(t)

	// Create sandbox owned by teamA.
	sandbox, err := testQueries.CreateSandbox(ctx, db.CreateSandboxParams{
		TeamID:    teamA,
		Name:      "team-a-box",
		Status:    db.SandboxStatusActive,
		VcpuCount: 1,
		MemoryMib: 256,
	})
	if err != nil {
		t.Fatalf("create sandbox: %v", err)
	}

	// TeamB's key trying to delete teamA's sandbox.
	_, apiKeyB := seedTeamAndKey(t, ctx)
	w := doRequest(r, "DELETE", "/sandboxes/"+sandbox.ID.String(), apiKeyB, "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 (team isolation), got %d: %s", w.Code, w.Body.String())
	}

	// TeamA's key works.
	w = doRequest(r, "DELETE", "/sandboxes/"+sandbox.ID.String(), apiKeyA, "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Activity logging
// ---------------------------------------------------------------------------

func TestIntegration_ActivityLogOnDelete(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey := seedTeamAndKey(t, ctx)

	r := setupIntegrationRouter(t)

	sandbox, err := testQueries.CreateSandbox(ctx, db.CreateSandboxParams{
		TeamID:    teamID,
		Name:      "activity-test",
		Status:    db.SandboxStatusActive,
		VcpuCount: 1,
		MemoryMib: 256,
	})
	if err != nil {
		t.Fatalf("create sandbox: %v", err)
	}

	w := doRequest(r, "DELETE", "/sandboxes/"+sandbox.ID.String(), apiKey, "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}

	// Check activity was logged.
	activities, err := testQueries.ListActivityBySandbox(ctx, db.ListActivityBySandboxParams{
		SandboxID: sandbox.ID,
		Limit:     10,
	})
	if err != nil {
		t.Fatalf("list activities: %v", err)
	}
	if len(activities) == 0 {
		t.Fatal("expected at least one activity record after delete")
	}

	found := false
	for _, a := range activities {
		if a.Action == "deleted" && a.Category == "sandbox" {
			found = true
			if a.Status == nil || *a.Status != "success" {
				t.Errorf("expected status=success, got %v", a.Status)
			}
			if a.SandboxName == nil || *a.SandboxName != "activity-test" {
				t.Errorf("expected sandbox_name=activity-test, got %v", a.SandboxName)
			}
		}
	}
	if !found {
		t.Error("did not find 'deleted' activity record")
	}
}

// ---------------------------------------------------------------------------
// Delete non-existent sandbox
// ---------------------------------------------------------------------------

func TestIntegration_DeleteNonExistentSandbox(t *testing.T) {
	ctx := context.Background()
	_, apiKey := seedTeamAndKey(t, ctx)

	r := setupIntegrationRouter(t)
	w := doRequest(r, "DELETE", "/sandboxes/"+uuid.New().String(), apiKey, "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Snapshot visibility
// ---------------------------------------------------------------------------

func TestIntegration_SnapshotSavedFlag(t *testing.T) {
	ctx := context.Background()
	teamID, _ := seedTeamAndKey(t, ctx)

	// Create a sandbox to reference.
	sandbox, err := testQueries.CreateSandbox(ctx, db.CreateSandboxParams{
		TeamID:    teamID,
		Name:      "snap-test",
		Status:    db.SandboxStatusActive,
		VcpuCount: 1,
		MemoryMib: 256,
	})
	if err != nil {
		t.Fatalf("create sandbox: %v", err)
	}

	// Auto-snapshot (saved=false).
	autoSnap, err := testQueries.CreateSnapshot(ctx, db.CreateSnapshotParams{
		SandboxID: sandbox.ID,
		TeamID:    teamID,
		Path:      "/snap/auto",
		SizeBytes: 1024,
		Saved:     false,
		Trigger:   "auto-pause",
	})
	if err != nil {
		t.Fatalf("create auto snapshot: %v", err)
	}

	// Manual snapshot (saved=true).
	manualSnap, err := testQueries.CreateSnapshot(ctx, db.CreateSnapshotParams{
		SandboxID: sandbox.ID,
		TeamID:    teamID,
		Path:      "/snap/manual",
		SizeBytes: 2048,
		Saved:     true,
		Trigger:   "user",
	})
	if err != nil {
		t.Fatalf("create manual snapshot: %v", err)
	}

	// Verify auto-snapshot is not saved.
	got, err := testQueries.GetSnapshot(ctx, autoSnap.ID)
	if err != nil {
		t.Fatalf("get auto snapshot: %v", err)
	}
	if got.Saved {
		t.Error("auto-snapshot should not be saved")
	}

	// Verify manual snapshot is saved.
	got, err = testQueries.GetSnapshot(ctx, manualSnap.ID)
	if err != nil {
		t.Fatalf("get manual snapshot: %v", err)
	}
	if !got.Saved {
		t.Error("manual snapshot should be saved")
	}

	// Mark auto snapshot as saved.
	if err := testQueries.MarkSnapshotSaved(ctx, autoSnap.ID); err != nil {
		t.Fatalf("mark saved: %v", err)
	}
	got, err = testQueries.GetSnapshot(ctx, autoSnap.ID)
	if err != nil {
		t.Fatalf("get updated snapshot: %v", err)
	}
	if !got.Saved {
		t.Error("snapshot should now be saved after MarkSnapshotSaved")
	}
}

// ---------------------------------------------------------------------------
// Concurrent sandbox creation
// ---------------------------------------------------------------------------

func TestIntegration_ConcurrentSandboxCreation(t *testing.T) {
	ctx := context.Background()
	teamID, _ := seedTeamAndKey(t, ctx)

	const n = 10
	errs := make(chan error, n)

	for i := 0; i < n; i++ {
		go func(i int) {
			_, err := testQueries.CreateSandbox(ctx, db.CreateSandboxParams{
				TeamID:    teamID,
				Name:      fmt.Sprintf("concurrent-%d", i),
				Status:    db.SandboxStatusStarting,
				VcpuCount: 1,
				MemoryMib: 256,
			})
			errs <- err
		}(i)
	}

	for i := 0; i < n; i++ {
		if err := <-errs; err != nil {
			t.Errorf("concurrent create %d: %v", i, err)
		}
	}

	// All 10 should be listed.
	sandboxes, err := testQueries.ListSandboxesByTeam(ctx, teamID)
	if err != nil {
		t.Fatalf("list sandboxes: %v", err)
	}
	if len(sandboxes) < n {
		t.Errorf("expected at least %d sandboxes, got %d", n, len(sandboxes))
	}
}
