//go:build integration

// Package integration contains end-to-end tests that exercise the sandbox CRUD
// HTTP handlers against a real PostgreSQL database. All VMD calls use an
// in-process stub so no running VM daemon is required.
//
// Run with:
//
//	TEST_DATABASE_URL=postgres://... go test -tags integration ./internal/integration/ -v
//
// If TEST_DATABASE_URL (or DATABASE_URL) is not set, or the database is
// unreachable, the entire suite is skipped. The target database must have the
// schema already applied (run migrations before the test suite).
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
	"strings"
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
// Package-level test state
// ---------------------------------------------------------------------------

var (
	pool       *pgxpool.Pool
	router     *gin.Engine
	vmdStub    *stubVMD
	teamAID    uuid.UUID
	teamAKey   string // plaintext API key for team A
	teamBID    uuid.UUID
	teamBKey   string // plaintext API key for team B
)

// ---------------------------------------------------------------------------
// Stub VMD client (no real VM daemon needed)
// ---------------------------------------------------------------------------

type stubVMD struct {
	createFn   func(ctx context.Context, id string, vcpu, memMiB, diskMiB uint32, metadata map[string]string) (string, error)
	destroyFn  func(ctx context.Context, id string, force bool) error
	pauseFn    func(ctx context.Context, id, snapshotDir string) (string, string, error)
	resumeFn   func(ctx context.Context, id, snapshotPath, memPath string) (string, error)
	uploadFn   func(ctx context.Context, id, path string, content io.Reader) (int64, error)
	downloadFn func(ctx context.Context, id, path string) (io.ReadCloser, error)
}

func (s *stubVMD) CreateInstance(ctx context.Context, id string, vcpu, memMiB, diskMiB uint32, metadata map[string]string) (string, error) {
	if s.createFn != nil {
		return s.createFn(ctx, id, vcpu, memMiB, diskMiB, metadata)
	}
	return "10.0.0.1", nil
}
func (s *stubVMD) DestroyInstance(ctx context.Context, id string, force bool) error {
	if s.destroyFn != nil {
		return s.destroyFn(ctx, id, force)
	}
	return nil
}
func (s *stubVMD) PauseInstance(ctx context.Context, id, snapshotDir string) (string, string, error) {
	if s.pauseFn != nil {
		return s.pauseFn(ctx, id, snapshotDir)
	}
	return "/snapshots/" + id + "/vmstate.snap", "/snapshots/" + id + "/mem.snap", nil
}
func (s *stubVMD) ResumeInstance(ctx context.Context, id, snapshotPath, memPath string) (string, error) {
	if s.resumeFn != nil {
		return s.resumeFn(ctx, id, snapshotPath, memPath)
	}
	return "10.0.0.2", nil
}
func (s *stubVMD) ExecCommand(context.Context, string, string, []string, map[string]string, string, uint32) (string, string, int32, error) {
	return "", "", 0, nil
}
func (s *stubVMD) ExecCommandStream(context.Context, string, string, []string, map[string]string, string, uint32, func([]byte, []byte, int32, bool)) error {
	return nil
}
func (s *stubVMD) UploadFile(ctx context.Context, id, path string, content io.Reader) (int64, error) {
	if s.uploadFn != nil {
		return s.uploadFn(ctx, id, path, content)
	}
	_, err := io.Copy(io.Discard, content)
	return 42, err
}
func (s *stubVMD) DownloadFile(ctx context.Context, id, path string) (io.ReadCloser, error) {
	if s.downloadFn != nil {
		return s.downloadFn(ctx, id, path)
	}
	return io.NopCloser(strings.NewReader("hello-integration")), nil
}

// ---------------------------------------------------------------------------
// TestMain — suite setup & teardown
// ---------------------------------------------------------------------------

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)

	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		dbURL = os.Getenv("DATABASE_URL")
	}
	if dbURL == "" {
		fmt.Fprintln(os.Stderr, "integration: skipping — TEST_DATABASE_URL not set")
		os.Exit(0)
	}

	ctx := context.Background()
	var err error
	pool, err = pgxpool.New(ctx, dbURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration: skipping — cannot connect to DB: %v\n", err)
		os.Exit(0)
	}
	if err := pool.Ping(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "integration: skipping — DB not reachable: %v\n", err)
		os.Exit(0)
	}

	// Verify schema is migrated (sandbox table must exist).
	var exists bool
	err = pool.QueryRow(ctx,
		"SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'sandbox')",
	).Scan(&exists)
	if err != nil || !exists {
		fmt.Fprintln(os.Stderr, "integration: skipping — 'sandbox' table not found; run migrations first")
		os.Exit(0)
	}

	// Seed test teams and API keys.
	cleanup, seedErr := seedTestFixtures(ctx)
	if seedErr != nil {
		fmt.Fprintf(os.Stderr, "integration: seed failed: %v\n", seedErr)
		pool.Close()
		os.Exit(1)
	}

	// Build the HTTP router with a stub VMD and the real DB pool.
	vmdStub = &stubVMD{}
	queries := db.New(pool)
	cfg := &config.Config{}
	handlers := api.NewHandlers(vmdStub, queries, cfg)
	router = api.SetupRouter(handlers, pool)

	code := m.Run()

	cleanup()
	pool.Close()
	os.Exit(code)
}

// seedTestFixtures inserts the two test teams and their API keys. Returns a
// cleanup function that removes all inserted rows.
func seedTestFixtures(ctx context.Context) (func(), error) {
	suffix := uuid.New().String()[:8]

	// Team A
	if err := pool.QueryRow(ctx,
		"INSERT INTO team (name) VALUES ($1) RETURNING id",
		"test-team-a-"+suffix,
	).Scan(&teamAID); err != nil {
		return nil, fmt.Errorf("create team A: %w", err)
	}

	teamAKey = "test-key-a-" + uuid.New().String()
	if _, err := pool.Exec(ctx,
		"INSERT INTO api_key (team_id, key_hash, name) VALUES ($1, $2, $3)",
		teamAID, hashKey(teamAKey), "integration-test-a",
	); err != nil {
		return nil, fmt.Errorf("create api key A: %w", err)
	}

	// Team B
	if err := pool.QueryRow(ctx,
		"INSERT INTO team (name) VALUES ($1) RETURNING id",
		"test-team-b-"+suffix,
	).Scan(&teamBID); err != nil {
		return nil, fmt.Errorf("create team B: %w", err)
	}

	teamBKey = "test-key-b-" + uuid.New().String()
	if _, err := pool.Exec(ctx,
		"INSERT INTO api_key (team_id, key_hash, name) VALUES ($1, $2, $3)",
		teamBID, hashKey(teamBKey), "integration-test-b",
	); err != nil {
		return nil, fmt.Errorf("create api key B: %w", err)
	}

	cleanup := func() {
		ctx := context.Background()
		// Cascade: delete sandboxes (and their snapshots) first.
		pool.Exec(ctx, "DELETE FROM activity WHERE team_id IN ($1, $2)", teamAID, teamBID)
		pool.Exec(ctx, "DELETE FROM snapshot WHERE team_id IN ($1, $2)", teamAID, teamBID)
		// Remove snapshot_id FK before deleting sandboxes.
		pool.Exec(ctx, "UPDATE sandbox SET snapshot_id = NULL WHERE team_id IN ($1, $2)", teamAID, teamBID)
		pool.Exec(ctx, "DELETE FROM sandbox WHERE team_id IN ($1, $2)", teamAID, teamBID)
		pool.Exec(ctx, "DELETE FROM api_key WHERE team_id IN ($1, $2)", teamAID, teamBID)
		pool.Exec(ctx, "DELETE FROM team WHERE id IN ($1, $2)", teamAID, teamBID)
	}
	return cleanup, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func hashKey(plaintext string) string {
	h := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(h[:])
}

func doRequest(method, path, apiKey string, body interface{}) *httptest.ResponseRecorder {
	var bodyReader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, path, bodyReader)
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func parseJSON(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("response is not valid JSON: %v — body: %s", err, w.Body.String())
	}
	return result
}

// pollSandboxStatus queries the DB until the sandbox reaches the target status
// or the timeout expires.
func pollSandboxStatus(t *testing.T, sandboxID uuid.UUID, want db.SandboxStatus, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var status db.SandboxStatus
		err := pool.QueryRow(context.Background(),
			"SELECT status FROM sandbox WHERE id = $1", sandboxID,
		).Scan(&status)
		if err == nil && status == want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	var got db.SandboxStatus
	_ = pool.QueryRow(context.Background(),
		"SELECT status FROM sandbox WHERE id = $1", sandboxID,
	).Scan(&got)
	t.Fatalf("sandbox %s: status never reached %q (got %q) within %v", sandboxID, want, got, timeout)
}

// insertActiveSandbox seeds a sandbox row directly in the DB with status=active
// and returns its ID. This bypasses VMD so tests can exercise pause/resume/delete
// without a prior create call.
func insertActiveSandbox(t *testing.T, teamID uuid.UUID, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := pool.QueryRow(context.Background(),
		`INSERT INTO sandbox (team_id, name, status, vcpu_count, memory_mib)
		 VALUES ($1, $2, 'active', 2, 1024)
		 RETURNING id`,
		teamID, name,
	).Scan(&id)
	if err != nil {
		t.Fatalf("insertActiveSandbox: %v", err)
	}
	return id
}

// insertIdleSandbox seeds an idle sandbox with a snapshot row and returns both IDs.
func insertIdleSandbox(t *testing.T, teamID uuid.UUID, name string) (sandboxID, snapshotID uuid.UUID) {
	t.Helper()
	ctx := context.Background()

	// Create the sandbox first (idle status, no snapshot yet).
	err := pool.QueryRow(ctx,
		`INSERT INTO sandbox (team_id, name, status, vcpu_count, memory_mib)
		 VALUES ($1, $2, 'idle', 2, 1024)
		 RETURNING id`,
		teamID, name,
	).Scan(&sandboxID)
	if err != nil {
		t.Fatalf("insertIdleSandbox — sandbox: %v", err)
	}

	// Create snapshot row.
	triggerName := "pause"
	err = pool.QueryRow(ctx,
		`INSERT INTO snapshot (sandbox_id, team_id, path, size_bytes, saved, name, trigger)
		 VALUES ($1, $2, $3, 0, false, $4, $5)
		 RETURNING id`,
		sandboxID, teamID, "/snapshots/"+sandboxID.String()+"/vmstate.snap", &triggerName, triggerName,
	).Scan(&snapshotID)
	if err != nil {
		t.Fatalf("insertIdleSandbox — snapshot: %v", err)
	}

	// Link snapshot to sandbox.
	if _, err := pool.Exec(ctx,
		"UPDATE sandbox SET snapshot_id = $1 WHERE id = $2",
		snapshotID, sandboxID,
	); err != nil {
		t.Fatalf("insertIdleSandbox — link snapshot: %v", err)
	}

	return sandboxID, snapshotID
}

// cleanupSandbox removes a sandbox (and its snapshot) from the DB.
func cleanupSandbox(sandboxID uuid.UUID) {
	ctx := context.Background()
	pool.Exec(ctx, "DELETE FROM activity WHERE sandbox_id = $1", sandboxID)
	pool.Exec(ctx, "UPDATE sandbox SET snapshot_id = NULL WHERE id = $1", sandboxID)
	pool.Exec(ctx, "DELETE FROM snapshot WHERE sandbox_id = $1", sandboxID)
	pool.Exec(ctx, "DELETE FROM sandbox WHERE id = $1", sandboxID)
}

// ---------------------------------------------------------------------------
// Tests: POST /sandboxes — auth
// ---------------------------------------------------------------------------

func TestCreateSandbox_Auth(t *testing.T) {
	body := map[string]interface{}{
		"name":       "test-auth",
		"vcpu_count": 1,
		"memory_mib": 512,
	}

	t.Run("missing key returns 401", func(t *testing.T) {
		w := doRequest(http.MethodPost, "/sandboxes", "", body)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d — body: %s", w.Code, w.Body.String())
		}
	})

	t.Run("invalid key returns 401", func(t *testing.T) {
		w := doRequest(http.MethodPost, "/sandboxes", "not-a-real-key", body)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d — body: %s", w.Code, w.Body.String())
		}
	})
}

// ---------------------------------------------------------------------------
// Tests: POST /sandboxes — success
// ---------------------------------------------------------------------------

func TestCreateSandbox_Success(t *testing.T) {
	body := map[string]interface{}{
		"name":       "integration-create",
		"vcpu_count": 2,
		"memory_mib": 1024,
	}

	w := doRequest(http.MethodPost, "/sandboxes", teamAKey, body)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d — body: %s", w.Code, w.Body.String())
	}

	resp := parseJSON(t, w)

	// Validate response fields.
	sandboxIDStr, ok := resp["id"].(string)
	if !ok || sandboxIDStr == "" {
		t.Fatalf("response missing 'id' field: %v", resp)
	}
	sandboxID, err := uuid.Parse(sandboxIDStr)
	if err != nil {
		t.Fatalf("response 'id' is not a valid UUID: %s", sandboxIDStr)
	}
	if resp["name"] != "integration-create" {
		t.Errorf("expected name=%q, got %v", "integration-create", resp["name"])
	}
	if resp["status"] != "active" {
		t.Errorf("expected status=active, got %v", resp["status"])
	}
	if resp["vcpu_count"] == nil {
		t.Errorf("response missing vcpu_count")
	}
	if resp["memory_mib"] == nil {
		t.Errorf("response missing memory_mib")
	}
	if resp["ip_address"] == nil {
		t.Errorf("response missing ip_address")
	}

	t.Cleanup(func() { cleanupSandbox(sandboxID) })

	// Verify sandbox row in DB (async status update may still be in flight).
	var dbTeamID uuid.UUID
	var dbVcpu, dbMemory int32
	err = pool.QueryRow(context.Background(),
		"SELECT team_id, vcpu_count, memory_mib FROM sandbox WHERE id = $1",
		sandboxID,
	).Scan(&dbTeamID, &dbVcpu, &dbMemory)
	if err != nil {
		t.Fatalf("DB lookup failed: %v", err)
	}
	if dbTeamID != teamAID {
		t.Errorf("DB team_id=%v, want %v", dbTeamID, teamAID)
	}
	if dbVcpu != 2 {
		t.Errorf("DB vcpu_count=%d, want 2", dbVcpu)
	}
	if dbMemory != 1024 {
		t.Errorf("DB memory_mib=%d, want 1024", dbMemory)
	}

	// Wait for async status update to active.
	pollSandboxStatus(t, sandboxID, db.SandboxStatusActive, 2*time.Second)
}

// ---------------------------------------------------------------------------
// Tests: POST /sandboxes/{id}/pause
// ---------------------------------------------------------------------------

func TestPauseSandbox(t *testing.T) {
	// Seed an active sandbox directly in DB.
	sandboxID := insertActiveSandbox(t, teamAID, "integration-pause")
	t.Cleanup(func() { cleanupSandbox(sandboxID) })

	path := fmt.Sprintf("/sandboxes/%s/pause", sandboxID)
	w := doRequest(http.MethodPost, path, teamAKey, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}

	resp := parseJSON(t, w)
	if resp["status"] != "idle" {
		t.Errorf("expected status=idle, got %v", resp["status"])
	}
	snapshotIDStr, ok := resp["snapshot_id"].(string)
	if !ok || snapshotIDStr == "" {
		t.Fatalf("response missing snapshot_id: %v", resp)
	}
	snapshotID, err := uuid.Parse(snapshotIDStr)
	if err != nil {
		t.Fatalf("snapshot_id is not a valid UUID: %s", snapshotIDStr)
	}

	// Verify DB: sandbox is now idle.
	var dbStatus db.SandboxStatus
	var dbSnapshotID uuid.UUID
	err = pool.QueryRow(context.Background(),
		"SELECT status, snapshot_id FROM sandbox WHERE id = $1",
		sandboxID,
	).Scan(&dbStatus, &dbSnapshotID)
	if err != nil {
		t.Fatalf("DB sandbox lookup: %v", err)
	}
	if dbStatus != db.SandboxStatusIdle {
		t.Errorf("DB status=%q, want idle", dbStatus)
	}
	if dbSnapshotID != snapshotID {
		t.Errorf("DB snapshot_id=%v, want %v", dbSnapshotID, snapshotID)
	}

	// Verify snapshot row exists in DB.
	var snapPath string
	err = pool.QueryRow(context.Background(),
		"SELECT path FROM snapshot WHERE id = $1",
		snapshotID,
	).Scan(&snapPath)
	if err != nil {
		t.Fatalf("DB snapshot lookup: %v", err)
	}
	if snapPath == "" {
		t.Error("snapshot path is empty")
	}
}

func TestPauseSandbox_InvalidState(t *testing.T) {
	// Seed an idle sandbox (not active — can't be paused again).
	sandboxID, _ := insertIdleSandbox(t, teamAID, "integration-pause-conflict")
	t.Cleanup(func() { cleanupSandbox(sandboxID) })

	path := fmt.Sprintf("/sandboxes/%s/pause", sandboxID)
	w := doRequest(http.MethodPost, path, teamAKey, nil)
	if w.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d — body: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Tests: POST /sandboxes/{id}/resume
// ---------------------------------------------------------------------------

func TestResumeSandbox(t *testing.T) {
	sandboxID, _ := insertIdleSandbox(t, teamAID, "integration-resume")
	t.Cleanup(func() { cleanupSandbox(sandboxID) })

	path := fmt.Sprintf("/sandboxes/%s/resume", sandboxID)
	w := doRequest(http.MethodPost, path, teamAKey, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}

	resp := parseJSON(t, w)
	if resp["status"] != "active" {
		t.Errorf("expected status=active, got %v", resp["status"])
	}
	if resp["ip_address"] == nil {
		t.Errorf("response missing ip_address")
	}

	// Verify DB: sandbox is now active.
	var dbStatus db.SandboxStatus
	err := pool.QueryRow(context.Background(),
		"SELECT status FROM sandbox WHERE id = $1",
		sandboxID,
	).Scan(&dbStatus)
	if err != nil {
		t.Fatalf("DB lookup: %v", err)
	}
	if dbStatus != db.SandboxStatusActive {
		t.Errorf("DB status=%q, want active", dbStatus)
	}
}

// ---------------------------------------------------------------------------
// Tests: DELETE /sandboxes/{id}
// ---------------------------------------------------------------------------

func TestDeleteSandbox(t *testing.T) {
	sandboxID := insertActiveSandbox(t, teamAID, "integration-delete")
	// Cleanup is a no-op if the sandbox was already deleted by the handler.
	t.Cleanup(func() { cleanupSandbox(sandboxID) })

	path := fmt.Sprintf("/sandboxes/%s", sandboxID)
	w := doRequest(http.MethodDelete, path, teamAKey, nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d — body: %s", w.Code, w.Body.String())
	}

	// Verify DB: sandbox has destroyed_at set and status=deleted.
	var dbStatus db.SandboxStatus
	var destroyedAt *time.Time
	err := pool.QueryRow(context.Background(),
		"SELECT status, destroyed_at FROM sandbox WHERE id = $1",
		sandboxID,
	).Scan(&dbStatus, &destroyedAt)
	if err != nil {
		t.Fatalf("DB lookup: %v", err)
	}
	if dbStatus != db.SandboxStatusDeleted {
		t.Errorf("DB status=%q, want deleted", dbStatus)
	}
	if destroyedAt == nil {
		t.Error("DB destroyed_at is NULL, expected a timestamp")
	}

	// Second delete should return 404.
	w2 := doRequest(http.MethodDelete, path, teamAKey, nil)
	if w2.Code != http.StatusNotFound {
		t.Errorf("second delete: expected 404, got %d — body: %s", w2.Code, w2.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Tests: PUT/GET /sandboxes/{id}/files/*path  (via AutoWake middleware)
// ---------------------------------------------------------------------------

func TestSandboxFiles_UploadDownload(t *testing.T) {
	sandboxID := insertActiveSandbox(t, teamAID, "integration-files")
	t.Cleanup(func() { cleanupSandbox(sandboxID) })

	fileContent := "hello integration test"
	uploadBody := strings.NewReader(fileContent)

	uploadReq, _ := http.NewRequest(
		http.MethodPut,
		fmt.Sprintf("/sandboxes/%s/files/hello.txt", sandboxID),
		uploadBody,
	)
	uploadReq.Header.Set("X-API-Key", teamAKey)
	uploadW := httptest.NewRecorder()
	router.ServeHTTP(uploadW, uploadReq)

	if uploadW.Code != http.StatusOK {
		t.Fatalf("upload: expected 200, got %d — body: %s", uploadW.Code, uploadW.Body.String())
	}

	uploadResp := parseJSON(t, uploadW)
	if uploadResp["path"] != "/hello.txt" {
		t.Errorf("upload response path=%v, want /hello.txt", uploadResp["path"])
	}

	// Download the file.
	var downloadedContent []byte
	vmdStub.downloadFn = func(ctx context.Context, id, path string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(fileContent)), nil
	}
	defer func() { vmdStub.downloadFn = nil }()

	downloadReq, _ := http.NewRequest(
		http.MethodGet,
		fmt.Sprintf("/sandboxes/%s/files/hello.txt", sandboxID),
		nil,
	)
	downloadReq.Header.Set("X-API-Key", teamAKey)
	downloadW := httptest.NewRecorder()
	router.ServeHTTP(downloadW, downloadReq)

	if downloadW.Code != http.StatusOK {
		t.Fatalf("download: expected 200, got %d — body: %s", downloadW.Code, downloadW.Body.String())
	}
	downloadedContent = downloadW.Body.Bytes()
	if string(downloadedContent) != fileContent {
		t.Errorf("downloaded content=%q, want %q", downloadedContent, fileContent)
	}
}

func TestSandboxFiles_AutoWakeFromIdle(t *testing.T) {
	// Start with an idle sandbox — upload should auto-wake it.
	sandboxID, _ := insertIdleSandbox(t, teamAID, "integration-files-autowake")
	t.Cleanup(func() { cleanupSandbox(sandboxID) })

	req, _ := http.NewRequest(
		http.MethodPut,
		fmt.Sprintf("/sandboxes/%s/files/wake.txt", sandboxID),
		strings.NewReader("wake"),
	)
	req.Header.Set("X-API-Key", teamAKey)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 after auto-wake, got %d — body: %s", w.Code, w.Body.String())
	}

	// Verify sandbox was woken (status=active).
	var dbStatus db.SandboxStatus
	err := pool.QueryRow(context.Background(),
		"SELECT status FROM sandbox WHERE id = $1",
		sandboxID,
	).Scan(&dbStatus)
	if err != nil {
		t.Fatalf("DB lookup: %v", err)
	}
	if dbStatus != db.SandboxStatusActive {
		t.Errorf("DB status=%q after auto-wake, want active", dbStatus)
	}
}

// ---------------------------------------------------------------------------
// Tests: Cross-team isolation
// ---------------------------------------------------------------------------

func TestCrossTeamIsolation(t *testing.T) {
	// Sandbox belongs to team A.
	sandboxID := insertActiveSandbox(t, teamAID, "integration-isolation")
	t.Cleanup(func() { cleanupSandbox(sandboxID) })

	// Team B should get 404 for all sandbox operations.
	paths := []struct {
		method string
		path   string
		body   interface{}
	}{
		{http.MethodPost, fmt.Sprintf("/sandboxes/%s/pause", sandboxID), nil},
		{http.MethodPost, fmt.Sprintf("/sandboxes/%s/resume", sandboxID), nil},
		{http.MethodDelete, fmt.Sprintf("/sandboxes/%s", sandboxID), nil},
		{http.MethodPut, fmt.Sprintf("/sandboxes/%s/files/x.txt", sandboxID), nil},
		{http.MethodGet, fmt.Sprintf("/sandboxes/%s/files/x.txt", sandboxID), nil},
	}

	for _, tc := range paths {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			w := doRequest(tc.method, tc.path, teamBKey, tc.body)
			if w.Code != http.StatusNotFound {
				t.Errorf("team B: expected 404, got %d — body: %s", w.Code, w.Body.String())
			}
		})
	}
}
