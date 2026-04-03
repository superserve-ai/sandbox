package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/superserve-ai/sandbox/internal/db"
)

// ---------------------------------------------------------------------------
// Mock VMDClient
// ---------------------------------------------------------------------------

type stubVMD struct {
	createFn   func(ctx context.Context, id string, vcpu, memMiB, diskMiB uint32, metadata map[string]string) (string, error)
	destroyFn  func(ctx context.Context, id string, force bool) error
	pauseFn    func(ctx context.Context, id, snapshotDir string) (string, string, error)
	resumeFn   func(ctx context.Context, id, snapshotPath, memPath string) (string, error)
	execFn     func(ctx context.Context, id, command string, args []string, env map[string]string, workingDir string, timeoutS uint32) (string, string, int32, error)
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
	return "/snapshots/vmstate.snap", "/snapshots/mem.snap", nil
}
func (s *stubVMD) ResumeInstance(ctx context.Context, id, snapshotPath, memPath string) (string, error) {
	if s.resumeFn != nil {
		return s.resumeFn(ctx, id, snapshotPath, memPath)
	}
	return "10.0.0.1", nil
}
func (s *stubVMD) ExecCommand(ctx context.Context, id, command string, args []string, env map[string]string, workingDir string, timeoutS uint32) (string, string, int32, error) {
	if s.execFn != nil {
		return s.execFn(ctx, id, command, args, env, workingDir, timeoutS)
	}
	return "", "", 0, nil
}
func (s *stubVMD) ExecCommandStream(context.Context, string, string, []string, map[string]string, string, uint32, func([]byte, []byte, int32, bool)) error {
	return nil
}
func (s *stubVMD) UploadFile(ctx context.Context, id, path string, content io.Reader) (int64, error) {
	if s.uploadFn != nil {
		return s.uploadFn(ctx, id, path, content)
	}
	return 0, nil
}
func (s *stubVMD) DownloadFile(ctx context.Context, id, path string) (io.ReadCloser, error) {
	if s.downloadFn != nil {
		return s.downloadFn(ctx, id, path)
	}
	return io.NopCloser(strings.NewReader("file-content")), nil
}

// ---------------------------------------------------------------------------
// Mock DBTX — drives db.Queries without a real database
// ---------------------------------------------------------------------------

type mockRow struct {
	scanFn func(dest ...any) error
}

func (r *mockRow) Scan(dest ...any) error { return r.scanFn(dest...) }

type mockDBTX struct {
	queryRowFn func(ctx context.Context, sql string, args ...any) pgx.Row
	execFn     func(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

func (m *mockDBTX) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return m.queryRowFn(ctx, sql, args...)
}

func (m *mockDBTX) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return m.execFn(ctx, sql, args...)
}

func (m *mockDBTX) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, fmt.Errorf("Query not expected")
}

// ---------------------------------------------------------------------------
// Row helpers
// ---------------------------------------------------------------------------

// sandboxRow returns a mockRow that populates a Sandbox from GetSandbox's Scan
// call (14 destination pointers matching the column order).
func sandboxRow(s db.Sandbox) *mockRow {
	return &mockRow{scanFn: func(dest ...any) error {
		*dest[0].(*uuid.UUID) = s.ID
		*dest[1].(*uuid.UUID) = s.TeamID
		*dest[2].(*string) = s.Name
		*dest[3].(*db.SandboxStatus) = s.Status
		*dest[4].(*int32) = s.VcpuCount
		*dest[5].(*int32) = s.MemoryMib
		*dest[6].(**string) = s.HostID
		*dest[7].(**netip.Addr) = s.IpAddress
		*dest[8].(**int32) = s.Pid
		*dest[9].(*pgtype.UUID) = s.SnapshotID
		*dest[10].(*time.Time) = s.LastActivityAt
		*dest[11].(*time.Time) = s.CreatedAt
		*dest[12].(*time.Time) = s.UpdatedAt
		*dest[13].(*pgtype.Timestamptz) = s.DestroyedAt
		return nil
	}}
}

func notFoundRow() *mockRow {
	return &mockRow{scanFn: func(...any) error { return pgx.ErrNoRows }}
}

func errorRow(err error) *mockRow {
	return &mockRow{scanFn: func(...any) error { return err }}
}

// activityRow returns a mockRow for CreateActivity's Scan (12 fields).
func activityRow() *mockRow {
	return &mockRow{scanFn: func(dest ...any) error {
		*dest[0].(*uuid.UUID) = uuid.New()
		*dest[1].(*uuid.UUID) = uuid.Nil
		*dest[2].(*uuid.UUID) = uuid.Nil
		*dest[3].(*pgtype.UUID) = pgtype.UUID{}
		*dest[4].(*string) = "sandbox"
		*dest[5].(*string) = "deleted"
		*dest[6].(**string) = nil
		*dest[7].(**string) = nil
		*dest[8].(**int32) = nil
		*dest[9].(**string) = nil
		*dest[10].(*[]byte) = nil
		*dest[11].(*time.Time) = time.Now()
		return nil
	}}
}

// ---------------------------------------------------------------------------
// Router / request helpers
// ---------------------------------------------------------------------------

func setupTestRouter(h *Handlers, teamID string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		if teamID != "" {
			c.Set("team_id", teamID)
		}
		c.Next()
	})
	r.POST("/sandboxes", h.CreateSandbox)
	r.POST("/sandboxes/:sandbox_id/resume", h.ResumeSandbox)
	r.POST("/sandboxes/:sandbox_id/pause", h.PauseSandbox)
	r.DELETE("/sandboxes/:sandbox_id", h.DeleteSandbox)

	// Routes with auto-wake middleware.
	ops := r.Group("/sandboxes/:sandbox_id")
	ops.Use(h.AutoWake())
	{
		ops.POST("/exec", h.ExecSandbox)
		ops.POST("/exec/stream", h.ExecSandboxStream)
		ops.PUT("/files/*path", h.UploadSandboxFile)
		ops.GET("/files/*path", h.DownloadSandboxFile)
	}
	return r
}

func deleteRequest(sandboxID string) *http.Request {
	return httptest.NewRequest(http.MethodDelete, "/sandboxes/"+sandboxID, nil)
}

func sandboxExecReq(sandboxID, body string) *http.Request {
	return httptest.NewRequest(http.MethodPost, "/sandboxes/"+sandboxID+"/exec", strings.NewReader(body))
}

func parseJSON(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to parse response: %v\nbody: %s", err, w.Body.String())
	}
	return body
}

func errorCode(body map[string]any) string {
	errObj, _ := body["error"].(map[string]any)
	code, _ := errObj["code"].(string)
	return code
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestDeleteSandbox_Success(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Name: "test-sb", Status: db.SandboxStatusActive}

	var destroyCalled bool
	vmd := &stubVMD{destroyFn: func(_ context.Context, id string, force bool) error {
		destroyCalled = true
		if id != sandboxID.String() {
			t.Errorf("DestroyInstance id = %q, want %q", id, sandboxID)
		}
		if !force {
			t.Error("DestroyInstance force = false, want true")
		}
		return nil
	}}

	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if strings.Contains(sql, "FROM sandbox") {
				return sandboxRow(sb)
			}
			return activityRow()
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, deleteRequest(sandboxID.String()))

	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d; body: %s", w.Code, http.StatusNoContent, w.Body.String())
	}
	if !destroyCalled {
		t.Error("VMD.DestroyInstance was not called")
	}
}

func TestDeleteSandbox_InvalidUUID(t *testing.T) {
	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row { return notFoundRow() },
		execFn:     func(context.Context, string, ...any) (pgconn.CommandTag, error) { return pgconn.NewCommandTag(""), nil },
	}
	vmd := &stubVMD{destroyFn: func(context.Context, string, bool) error { return nil }}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, uuid.New().String()).ServeHTTP(w, deleteRequest("not-a-uuid"))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
	if c := errorCode(parseJSON(t, w)); c != "bad_request" {
		t.Errorf("error code = %q, want %q", c, "bad_request")
	}
}

func TestDeleteSandbox_MissingTeamID(t *testing.T) {
	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row { return notFoundRow() },
		execFn:     func(context.Context, string, ...any) (pgconn.CommandTag, error) { return pgconn.NewCommandTag(""), nil },
	}
	vmd := &stubVMD{destroyFn: func(context.Context, string, bool) error { return nil }}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	// Empty teamID — context won't have "team_id".
	setupTestRouter(h, "").ServeHTTP(w, deleteRequest(uuid.New().String()))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d; body: %s", w.Code, http.StatusUnauthorized, w.Body.String())
	}
}

func TestDeleteSandbox_NotFound(t *testing.T) {
	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row { return notFoundRow() },
		execFn:     func(context.Context, string, ...any) (pgconn.CommandTag, error) { return pgconn.NewCommandTag(""), nil },
	}
	vmd := &stubVMD{destroyFn: func(context.Context, string, bool) error { return nil }}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, uuid.New().String()).ServeHTTP(w, deleteRequest(uuid.New().String()))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
	if c := errorCode(parseJSON(t, w)); c != "not_found" {
		t.Errorf("error code = %q, want %q", c, "not_found")
	}
}

func TestDeleteSandbox_DBGetError(t *testing.T) {
	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row {
			return errorRow(fmt.Errorf("connection refused"))
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) { return pgconn.NewCommandTag(""), nil },
	}
	vmd := &stubVMD{destroyFn: func(context.Context, string, bool) error { return nil }}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, uuid.New().String()).ServeHTTP(w, deleteRequest(uuid.New().String()))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
}

func TestDeleteSandbox_VMDDestroyError(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Name: "sb", Status: db.SandboxStatusActive}

	vmd := &stubVMD{destroyFn: func(context.Context, string, bool) error {
		return fmt.Errorf("vmd unreachable")
	}}
	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row { return sandboxRow(sb) },
		execFn:     func(context.Context, string, ...any) (pgconn.CommandTag, error) { return pgconn.NewCommandTag(""), nil },
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, deleteRequest(sandboxID.String()))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
}

func TestDeleteSandbox_DBDestroyError(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Name: "sb", Status: db.SandboxStatusActive}

	vmd := &stubVMD{destroyFn: func(context.Context, string, bool) error { return nil }}
	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row { return sandboxRow(sb) },
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag(""), fmt.Errorf("db write failed")
		},
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, deleteRequest(sandboxID.String()))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
}

func TestDeleteSandbox_ActivityLogFailure_StillReturns204(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Name: "sb", Status: db.SandboxStatusActive}

	vmd := &stubVMD{destroyFn: func(context.Context, string, bool) error { return nil }}

	queryRowCall := 0
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			queryRowCall++
			if queryRowCall == 1 {
				return sandboxRow(sb) // GetSandbox
			}
			return errorRow(fmt.Errorf("activity table locked")) // CreateActivity
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("UPDATE 1"), nil // DestroySandbox
		},
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, deleteRequest(sandboxID.String()))

	// Activity logging failure is non-fatal — should still return 204.
	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d; body: %s", w.Code, http.StatusNoContent, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// ResumeSandbox tests
// ---------------------------------------------------------------------------

// snapshotRow returns a mockRow that populates a Snapshot from GetSnapshot's
// Scan call (9 destination pointers matching the column order).
func snapshotRow(s db.Snapshot) *mockRow {
	return &mockRow{scanFn: func(dest ...any) error {
		*dest[0].(*uuid.UUID) = s.ID
		*dest[1].(*uuid.UUID) = s.SandboxID
		*dest[2].(*uuid.UUID) = s.TeamID
		*dest[3].(*string) = s.Path
		*dest[4].(*int64) = s.SizeBytes
		*dest[5].(*bool) = s.Saved
		*dest[6].(**string) = s.Name
		*dest[7].(*string) = s.Trigger
		*dest[8].(*time.Time) = s.CreatedAt
		return nil
	}}
}

func resumeRequest(sandboxID string) *http.Request {
	return httptest.NewRequest(http.MethodPost, "/sandboxes/"+sandboxID+"/resume", nil)
}

func idleSandboxWithSnapshot(sandboxID, teamID, snapshotID uuid.UUID) db.Sandbox {
	return db.Sandbox{
		ID:         sandboxID,
		TeamID:     teamID,
		Name:       "test-sb",
		Status:     db.SandboxStatusIdle,
		SnapshotID: pgtype.UUID{Bytes: snapshotID, Valid: true},
	}
}

func TestResumeSandbox_Success(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	snapshotID := uuid.New()
	sb := idleSandboxWithSnapshot(sandboxID, teamID, snapshotID)
	snap := db.Snapshot{
		ID:        snapshotID,
		SandboxID: sandboxID,
		TeamID:    teamID,
		Path:      "/snapshots/test/vmstate.snap",
		SizeBytes: 1024,
		Saved:     true,
		Trigger:   "pause",
	}

	var resumeCalled bool
	vmd := &stubVMD{
		destroyFn: func(context.Context, string, bool) error { return nil },
		resumeFn: func(_ context.Context, id, snapPath, memPath string) (string, error) {
			resumeCalled = true
			if id != sandboxID.String() {
				t.Errorf("ResumeInstance id = %q, want %q", id, sandboxID)
			}
			if snapPath != "/snapshots/test/vmstate.snap" {
				t.Errorf("snapshotPath = %q, want %q", snapPath, "/snapshots/test/vmstate.snap")
			}
			if memPath != "/snapshots/test/mem.snap" {
				t.Errorf("memPath = %q, want %q", memPath, "/snapshots/test/mem.snap")
			}
			return "10.0.0.5", nil
		},
	}

	queryRowCall := 0
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			queryRowCall++
			switch {
			case strings.Contains(sql, "FROM sandbox"):
				return sandboxRow(sb)
			case strings.Contains(sql, "FROM snapshot"):
				return snapshotRow(snap)
			default:
				return activityRow() // CreateActivity
			}
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, resumeRequest(sandboxID.String()))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
	if !resumeCalled {
		t.Error("VMD.ResumeInstance was not called")
	}

	body := parseJSON(t, w)
	if body["status"] != "active" {
		t.Errorf("status = %q, want %q", body["status"], "active")
	}
	if body["ip_address"] != "10.0.0.5" {
		t.Errorf("ip_address = %q, want %q", body["ip_address"], "10.0.0.5")
	}
}

func TestResumeSandbox_InvalidUUID(t *testing.T) {
	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row { return notFoundRow() },
		execFn:     func(context.Context, string, ...any) (pgconn.CommandTag, error) { return pgconn.NewCommandTag(""), nil },
	}
	vmd := &stubVMD{destroyFn: func(context.Context, string, bool) error { return nil }}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, uuid.New().String()).ServeHTTP(w, resumeRequest("not-a-uuid"))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
	if c := errorCode(parseJSON(t, w)); c != "bad_request" {
		t.Errorf("error code = %q, want %q", c, "bad_request")
	}
}

func TestResumeSandbox_MissingTeamID(t *testing.T) {
	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row { return notFoundRow() },
		execFn:     func(context.Context, string, ...any) (pgconn.CommandTag, error) { return pgconn.NewCommandTag(""), nil },
	}
	vmd := &stubVMD{destroyFn: func(context.Context, string, bool) error { return nil }}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, "").ServeHTTP(w, resumeRequest(uuid.New().String()))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d; body: %s", w.Code, http.StatusUnauthorized, w.Body.String())
	}
}

func TestResumeSandbox_NotFound(t *testing.T) {
	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row { return notFoundRow() },
		execFn:     func(context.Context, string, ...any) (pgconn.CommandTag, error) { return pgconn.NewCommandTag(""), nil },
	}
	vmd := &stubVMD{destroyFn: func(context.Context, string, bool) error { return nil }}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, uuid.New().String()).ServeHTTP(w, resumeRequest(uuid.New().String()))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
	if c := errorCode(parseJSON(t, w)); c != "not_found" {
		t.Errorf("error code = %q, want %q", c, "not_found")
	}
}

func TestResumeSandbox_NotIdle(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Name: "sb", Status: db.SandboxStatusActive}

	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row { return sandboxRow(sb) },
		execFn:     func(context.Context, string, ...any) (pgconn.CommandTag, error) { return pgconn.NewCommandTag(""), nil },
	}
	vmd := &stubVMD{destroyFn: func(context.Context, string, bool) error { return nil }}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, resumeRequest(sandboxID.String()))

	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d", w.Code, http.StatusConflict)
	}
	if c := errorCode(parseJSON(t, w)); c != "conflict" {
		t.Errorf("error code = %q, want %q", c, "conflict")
	}
}

func TestResumeSandbox_NoSnapshotID(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	// Idle but no snapshot_id set.
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Name: "sb", Status: db.SandboxStatusIdle}

	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row { return sandboxRow(sb) },
		execFn:     func(context.Context, string, ...any) (pgconn.CommandTag, error) { return pgconn.NewCommandTag(""), nil },
	}
	vmd := &stubVMD{destroyFn: func(context.Context, string, bool) error { return nil }}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, resumeRequest(sandboxID.String()))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
}

func TestResumeSandbox_VMDError(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	snapshotID := uuid.New()
	sb := idleSandboxWithSnapshot(sandboxID, teamID, snapshotID)
	snap := db.Snapshot{
		ID: snapshotID, SandboxID: sandboxID, TeamID: teamID,
		Path: "/snapshots/test/vmstate.snap", Saved: true, Trigger: "pause",
	}

	vmd := &stubVMD{
		destroyFn: func(context.Context, string, bool) error { return nil },
		resumeFn: func(context.Context, string, string, string) (string, error) {
			return "", fmt.Errorf("vmd unreachable")
		},
	}

	queryRowCall := 0
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			queryRowCall++
			if strings.Contains(sql, "FROM sandbox") {
				return sandboxRow(sb)
			}
			return snapshotRow(snap)
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag(""), nil
		},
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, resumeRequest(sandboxID.String()))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
}

func TestResumeSandbox_ActivityLogFailure_StillReturns200(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	snapshotID := uuid.New()
	sb := idleSandboxWithSnapshot(sandboxID, teamID, snapshotID)
	snap := db.Snapshot{
		ID: snapshotID, SandboxID: sandboxID, TeamID: teamID,
		Path: "/snapshots/test/vmstate.snap", Saved: true, Trigger: "pause",
	}

	vmd := &stubVMD{
		destroyFn: func(context.Context, string, bool) error { return nil },
		resumeFn: func(context.Context, string, string, string) (string, error) {
			return "10.0.0.5", nil
		},
	}

	queryRowCall := 0
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			queryRowCall++
			switch {
			case strings.Contains(sql, "FROM sandbox"):
				return sandboxRow(sb)
			case strings.Contains(sql, "FROM snapshot"):
				return snapshotRow(snap)
			default:
				return errorRow(fmt.Errorf("activity table locked"))
			}
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, resumeRequest(sandboxID.String()))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// ExecSandbox tests
// ---------------------------------------------------------------------------

func TestExecSandbox_Success(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Name: "test-sb", Status: db.SandboxStatusActive}

	var execCalled bool
	vmd := &stubVMD{
		execFn: func(_ context.Context, id, command string, args []string, _ map[string]string, _ string, _ uint32) (string, string, int32, error) {
			execCalled = true
			if id != sandboxID.String() {
				t.Errorf("ExecCommand id = %q, want %q", id, sandboxID)
			}
			if command != "ls" {
				t.Errorf("ExecCommand command = %q, want %q", command, "ls")
			}
			return "file1\nfile2\n", "", 0, nil
		},
	}

	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if strings.Contains(sql, "FROM sandbox") {
				return sandboxRow(sb)
			}
			return activityRow()
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, sandboxExecReq(sandboxID.String(), `{"command":"ls","args":["-la"]}`))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
	if !execCalled {
		t.Error("VMD.ExecCommand was not called")
	}

	body := parseJSON(t, w)
	if body["stdout"] != "file1\nfile2\n" {
		t.Errorf("stdout = %q, want %q", body["stdout"], "file1\nfile2\n")
	}
	if body["exit_code"] != float64(0) {
		t.Errorf("exit_code = %v, want 0", body["exit_code"])
	}
}

func TestExecSandbox_InvalidUUID(t *testing.T) {
	vmd := &stubVMD{}
	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row { return notFoundRow() },
		execFn:     func(context.Context, string, ...any) (pgconn.CommandTag, error) { return pgconn.NewCommandTag(""), nil },
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, uuid.New().String()).ServeHTTP(w, sandboxExecReq("not-a-uuid", `{"command":"ls"}`))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestExecSandbox_NotFound(t *testing.T) {
	vmd := &stubVMD{}
	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row { return notFoundRow() },
		execFn:     func(context.Context, string, ...any) (pgconn.CommandTag, error) { return pgconn.NewCommandTag(""), nil },
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, uuid.New().String()).ServeHTTP(w, sandboxExecReq(uuid.New().String(), `{"command":"ls"}`))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestExecSandbox_MissingCommand(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Name: "sb", Status: db.SandboxStatusActive}

	vmd := &stubVMD{}
	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row { return sandboxRow(sb) },
		execFn:     func(context.Context, string, ...any) (pgconn.CommandTag, error) { return pgconn.NewCommandTag(""), nil },
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, sandboxExecReq(sandboxID.String(), `{}`))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d; body: %s", w.Code, http.StatusBadRequest, w.Body.String())
	}
}

func TestExecSandbox_InvalidState(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Name: "sb", Status: db.SandboxStatusStarting}

	vmd := &stubVMD{}
	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row { return sandboxRow(sb) },
		execFn:     func(context.Context, string, ...any) (pgconn.CommandTag, error) { return pgconn.NewCommandTag(""), nil },
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, sandboxExecReq(sandboxID.String(), `{"command":"ls"}`))

	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d; body: %s", w.Code, http.StatusConflict, w.Body.String())
	}
}

func TestExecSandbox_AutoWakeIdle(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Name: "idle-sb", Status: db.SandboxStatusIdle}

	var resumeCalled, execCalled bool
	vmd := &stubVMD{
		resumeFn: func(_ context.Context, id, _, _ string) (string, error) {
			resumeCalled = true
			if id != sandboxID.String() {
				t.Errorf("ResumeInstance id = %q, want %q", id, sandboxID)
			}
			return "10.0.0.1", nil
		},
		execFn: func(_ context.Context, id, command string, _ []string, _ map[string]string, _ string, _ uint32) (string, string, int32, error) {
			execCalled = true
			return "ok\n", "", 0, nil
		},
	}

	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if strings.Contains(sql, "FROM sandbox") {
				return sandboxRow(sb)
			}
			return activityRow()
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, sandboxExecReq(sandboxID.String(), `{"command":"echo","args":["hello"]}`))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
	if !resumeCalled {
		t.Error("VMD.ResumeInstance was not called for auto-wake")
	}
	if !execCalled {
		t.Error("VMD.ExecCommand was not called after auto-wake")
	}
}

func TestExecSandbox_VMDExecError(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Name: "sb", Status: db.SandboxStatusActive}

	vmd := &stubVMD{
		execFn: func(context.Context, string, string, []string, map[string]string, string, uint32) (string, string, int32, error) {
			return "", "", -1, fmt.Errorf("vmd unreachable")
		},
	}

	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row { return sandboxRow(sb) },
		execFn:     func(context.Context, string, ...any) (pgconn.CommandTag, error) { return pgconn.NewCommandTag(""), nil },
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, sandboxExecReq(sandboxID.String(), `{"command":"ls"}`))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
}

func TestExecSandbox_MissingTeamID(t *testing.T) {
	vmd := &stubVMD{}
	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row { return notFoundRow() },
		execFn:     func(context.Context, string, ...any) (pgconn.CommandTag, error) { return pgconn.NewCommandTag(""), nil },
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, "").ServeHTTP(w, sandboxExecReq(uuid.New().String(), `{"command":"ls"}`))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d; body: %s", w.Code, http.StatusUnauthorized, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// CreateSandbox tests
// ---------------------------------------------------------------------------

func createSandboxReq(body string) *http.Request {
	return httptest.NewRequest(http.MethodPost, "/sandboxes", strings.NewReader(body))
}

func TestCreateSandbox_Success(t *testing.T) {
	teamID := uuid.New()
	sandboxID := uuid.New()

	var createCalled bool
	vmd := &stubVMD{
		createFn: func(_ context.Context, id string, vcpu, memMiB, _ uint32, _ map[string]string) (string, error) {
			createCalled = true
			if vcpu != 2 {
				t.Errorf("vcpu = %d, want 2", vcpu)
			}
			if memMiB != 512 {
				t.Errorf("memMiB = %d, want 512", memMiB)
			}
			return "10.0.0.42", nil
		},
	}

	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if strings.Contains(sql, "INSERT INTO sandbox") {
				return sandboxRow(db.Sandbox{
					ID: sandboxID, TeamID: teamID, Name: "my-sandbox",
					Status: db.SandboxStatusStarting, VcpuCount: 2, MemoryMib: 512,
					CreatedAt: time.Now(),
				})
			}
			return activityRow()
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, createSandboxReq(`{"name":"my-sandbox","vcpu_count":2,"memory_mib":512}`))

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d; body: %s", w.Code, http.StatusCreated, w.Body.String())
	}
	if !createCalled {
		t.Error("VMD.CreateInstance was not called")
	}

	body := parseJSON(t, w)
	if body["name"] != "my-sandbox" {
		t.Errorf("name = %q, want %q", body["name"], "my-sandbox")
	}
	if body["status"] != "active" {
		t.Errorf("status = %q, want %q", body["status"], "active")
	}
	if body["ip_address"] != "10.0.0.42" {
		t.Errorf("ip_address = %q, want %q", body["ip_address"], "10.0.0.42")
	}
}

func TestCreateSandbox_InvalidBody(t *testing.T) {
	vmd := &stubVMD{}
	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row { return notFoundRow() },
		execFn:     func(context.Context, string, ...any) (pgconn.CommandTag, error) { return pgconn.NewCommandTag(""), nil },
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, uuid.New().String()).ServeHTTP(w, createSandboxReq(`{}`))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestCreateSandbox_MissingTeamID(t *testing.T) {
	vmd := &stubVMD{}
	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row { return notFoundRow() },
		execFn:     func(context.Context, string, ...any) (pgconn.CommandTag, error) { return pgconn.NewCommandTag(""), nil },
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, "").ServeHTTP(w, createSandboxReq(`{"name":"test","vcpu_count":1,"memory_mib":256}`))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestCreateSandbox_VMDError(t *testing.T) {
	teamID := uuid.New()
	sandboxID := uuid.New()

	vmd := &stubVMD{
		createFn: func(context.Context, string, uint32, uint32, uint32, map[string]string) (string, error) {
			return "", fmt.Errorf("vmd unreachable")
		},
	}

	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if strings.Contains(sql, "INSERT INTO sandbox") {
				return sandboxRow(db.Sandbox{
					ID: sandboxID, TeamID: teamID, Name: "sb",
					Status: db.SandboxStatusStarting, VcpuCount: 1, MemoryMib: 256,
				})
			}
			return activityRow()
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, createSandboxReq(`{"name":"sb","vcpu_count":1,"memory_mib":256}`))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
}

// ---------------------------------------------------------------------------
// PauseSandbox tests
// ---------------------------------------------------------------------------

func pauseRequest(sandboxID string) *http.Request {
	return httptest.NewRequest(http.MethodPost, "/sandboxes/"+sandboxID+"/pause", nil)
}

func TestPauseSandbox_Success(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Name: "test-sb", Status: db.SandboxStatusActive}

	var pauseCalled bool
	vmd := &stubVMD{
		pauseFn: func(_ context.Context, id, _ string) (string, string, error) {
			pauseCalled = true
			if id != sandboxID.String() {
				t.Errorf("PauseInstance id = %q, want %q", id, sandboxID)
			}
			return "/snapshots/vmstate.snap", "/snapshots/mem.snap", nil
		},
	}

	snapshotID := uuid.New()
	queryRowCall := 0
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			queryRowCall++
			if strings.Contains(sql, "FROM sandbox") {
				return sandboxRow(sb)
			}
			if strings.Contains(sql, "INSERT INTO snapshot") {
				return snapshotRow(db.Snapshot{
					ID: snapshotID, SandboxID: sandboxID, TeamID: teamID,
					Path: "/snapshots/vmstate.snap", Trigger: "pause",
				})
			}
			return activityRow()
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, pauseRequest(sandboxID.String()))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
	if !pauseCalled {
		t.Error("VMD.PauseInstance was not called")
	}

	body := parseJSON(t, w)
	if body["status"] != "idle" {
		t.Errorf("status = %q, want %q", body["status"], "idle")
	}
	if body["snapshot_id"] != snapshotID.String() {
		t.Errorf("snapshot_id = %q, want %q", body["snapshot_id"], snapshotID)
	}
}

func TestPauseSandbox_NotActive(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Name: "sb", Status: db.SandboxStatusIdle}

	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row { return sandboxRow(sb) },
		execFn:     func(context.Context, string, ...any) (pgconn.CommandTag, error) { return pgconn.NewCommandTag(""), nil },
	}
	vmd := &stubVMD{}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, pauseRequest(sandboxID.String()))

	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d", w.Code, http.StatusConflict)
	}
}

func TestPauseSandbox_NotFound(t *testing.T) {
	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row { return notFoundRow() },
		execFn:     func(context.Context, string, ...any) (pgconn.CommandTag, error) { return pgconn.NewCommandTag(""), nil },
	}
	vmd := &stubVMD{}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, uuid.New().String()).ServeHTTP(w, pauseRequest(uuid.New().String()))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestPauseSandbox_VMDError(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Name: "sb", Status: db.SandboxStatusActive}

	vmd := &stubVMD{
		pauseFn: func(context.Context, string, string) (string, string, error) {
			return "", "", fmt.Errorf("vmd unreachable")
		},
	}

	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row { return sandboxRow(sb) },
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, pauseRequest(sandboxID.String()))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
}

func TestPauseSandbox_MissingTeamID(t *testing.T) {
	vmd := &stubVMD{}
	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row { return notFoundRow() },
		execFn:     func(context.Context, string, ...any) (pgconn.CommandTag, error) { return pgconn.NewCommandTag(""), nil },
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, "").ServeHTTP(w, pauseRequest(uuid.New().String()))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

// ---------------------------------------------------------------------------
// Sandbox file operation tests
// ---------------------------------------------------------------------------

func uploadFileReq(sandboxID, filePath string) *http.Request {
	return httptest.NewRequest(http.MethodPut, "/sandboxes/"+sandboxID+"/files/"+filePath, strings.NewReader("file-content"))
}

func downloadFileReq(sandboxID, filePath string) *http.Request {
	return httptest.NewRequest(http.MethodGet, "/sandboxes/"+sandboxID+"/files/"+filePath, nil)
}

func TestUploadSandboxFile_Success(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Name: "sb", Status: db.SandboxStatusActive}

	var uploadCalled bool
	vmd := &stubVMD{
		uploadFn: func(_ context.Context, id, path string, content io.Reader) (int64, error) {
			uploadCalled = true
			if id != sandboxID.String() {
				t.Errorf("UploadFile id = %q, want %q", id, sandboxID)
			}
			if path != "/app/main.go" {
				t.Errorf("UploadFile path = %q, want %q", path, "/app/main.go")
			}
			data, _ := io.ReadAll(content)
			return int64(len(data)), nil
		},
	}

	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if strings.Contains(sql, "FROM sandbox") {
				return sandboxRow(sb)
			}
			return activityRow()
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, uploadFileReq(sandboxID.String(), "app/main.go"))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
	if !uploadCalled {
		t.Error("VMD.UploadFile was not called")
	}
}

func TestDownloadSandboxFile_Success(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Name: "sb", Status: db.SandboxStatusActive}

	var downloadCalled bool
	vmd := &stubVMD{
		downloadFn: func(_ context.Context, id, path string) (io.ReadCloser, error) {
			downloadCalled = true
			if id != sandboxID.String() {
				t.Errorf("DownloadFile id = %q, want %q", id, sandboxID)
			}
			return io.NopCloser(strings.NewReader("hello world")), nil
		},
	}

	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if strings.Contains(sql, "FROM sandbox") {
				return sandboxRow(sb)
			}
			return activityRow()
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, downloadFileReq(sandboxID.String(), "app/main.go"))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
	if !downloadCalled {
		t.Error("VMD.DownloadFile was not called")
	}
	if w.Body.String() != "hello world" {
		t.Errorf("body = %q, want %q", w.Body.String(), "hello world")
	}
}

func TestUploadSandboxFile_PathTraversal(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Name: "sb", Status: db.SandboxStatusActive}

	vmd := &stubVMD{}
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if strings.Contains(sql, "FROM sandbox") {
				return sandboxRow(sb)
			}
			return activityRow()
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, uploadFileReq(sandboxID.String(), "../etc/passwd"))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d; body: %s", w.Code, http.StatusBadRequest, w.Body.String())
	}
}

func TestDownloadSandboxFile_NotFound(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Name: "sb", Status: db.SandboxStatusActive}

	vmd := &stubVMD{
		downloadFn: func(context.Context, string, string) (io.ReadCloser, error) {
			return nil, fmt.Errorf("404 not found")
		},
	}

	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if strings.Contains(sql, "FROM sandbox") {
				return sandboxRow(sb)
			}
			return activityRow()
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, downloadFileReq(sandboxID.String(), "missing.txt"))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}
