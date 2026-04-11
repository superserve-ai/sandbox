package api

import (
	"context"
	"encoding/json"
	"fmt"
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
	createFn  func(ctx context.Context, id string, vcpu, memMiB, diskMiB uint32, metadata map[string]string) (string, error)
	destroyFn func(ctx context.Context, id string, force bool) error
	pauseFn   func(ctx context.Context, id, snapshotDir string) (string, string, error)
	resumeFn  func(ctx context.Context, id, snapshotPath, memPath string) (string, error)
	restoreFn func(ctx context.Context, id, snapshotPath, memPath string) (string, error)
	execFn    func(ctx context.Context, id, command string, args []string, env map[string]string, workingDir string, timeoutS uint32) (string, string, int32, error)
}

func (s *stubVMD) CreateInstance(ctx context.Context, id string, vcpu, memMiB, diskMiB uint32, metadata map[string]string, envVars map[string]string) (string, uint32, uint32, error) {
	if s.createFn != nil {
		ip, err := s.createFn(ctx, id, vcpu, memMiB, diskMiB, metadata)
		return ip, 1, 1024, err
	}
	return "10.0.0.1", 1, 1024, nil
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
func (s *stubVMD) ResumeInstance(ctx context.Context, id, snapshotPath, memPath string, envVars map[string]string) (string, uint32, uint32, error) {
	if s.resumeFn != nil {
		ip, err := s.resumeFn(ctx, id, snapshotPath, memPath)
		return ip, 1, 1024, err
	}
	return "10.0.0.1", 1, 1024, nil
}
func (s *stubVMD) RestoreSnapshot(ctx context.Context, id, snapshotPath, memPath string) (string, uint32, uint32, error) {
	if s.restoreFn != nil {
		ip, err := s.restoreFn(ctx, id, snapshotPath, memPath)
		return ip, 1, 1024, err
	}
	return "10.0.0.1", 1, 1024, nil
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
func (s *stubVMD) UpdateSandboxNetwork(_ context.Context, _ string, _, _, _ []string) error {
	return nil
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
// call (17 destination pointers matching the column order in sqlc-generated
// queries: ID, TeamID, Name, Status, VcpuCount, MemoryMib, HostID, IpAddress,
// Pid, SnapshotID, LastActivityAt, CreatedAt, UpdatedAt, DestroyedAt,
// NetworkConfig, TimeoutSeconds, Metadata).
func sandboxRow(s db.Sandbox) *mockRow {
	return &mockRow{scanFn: func(dest ...any) error {
		*dest[0].(*uuid.UUID) = s.ID
		*dest[1].(*uuid.UUID) = s.TeamID
		*dest[2].(*string) = s.Name
		*dest[3].(*db.SandboxStatus) = s.Status
		*dest[4].(*int32) = s.VcpuCount
		*dest[5].(*int32) = s.MemoryMib
		*dest[6].(*string) = s.HostID
		*dest[7].(**netip.Addr) = s.IpAddress
		*dest[8].(**int32) = s.Pid
		*dest[9].(*pgtype.UUID) = s.SnapshotID
		*dest[10].(*time.Time) = s.LastActivityAt
		*dest[11].(*time.Time) = s.CreatedAt
		*dest[12].(*time.Time) = s.UpdatedAt
		*dest[13].(*pgtype.Timestamptz) = s.DestroyedAt
		*dest[14].(*[]byte) = s.NetworkConfig
		*dest[15].(**int32) = s.TimeoutSeconds
		*dest[16].(*[]byte) = s.Metadata
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

// finalizePauseRow mocks the single-uuid RETURNING clause of FinalizePause.
func finalizePauseRow(snapshotID uuid.UUID) *mockRow {
	return &mockRow{scanFn: func(dest ...any) error {
		*dest[0].(*uuid.UUID) = snapshotID
		return nil
	}}
}

// boolRow mocks a single-bool scan (e.g. SandboxExists).
func boolRow(value bool) *mockRow {
	return &mockRow{scanFn: func(dest ...any) error {
		*dest[0].(*bool) = value
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

	vmd := &stubVMD{
		createFn: func(_ context.Context, id string, _, _, _ uint32, _ map[string]string) (string, error) {
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
	setupTestRouter(h, teamID.String()).ServeHTTP(w, createSandboxReq(`{"name":"my-sandbox"}`))

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d; body: %s", w.Code, http.StatusCreated, w.Body.String())
	}

	// Creation is synchronous — sandbox is active on return.
	body := parseJSON(t, w)
	if body["name"] != "my-sandbox" {
		t.Errorf("name = %q, want %q", body["name"], "my-sandbox")
	}
	if body["status"] != "active" {
		t.Errorf("status = %q, want active", body["status"])
	}
	// Resources should reflect what VMD reported, not the initial INSERT placeholders.
	if v := body["vcpu_count"].(float64); v == 0 {
		t.Error("vcpu_count is 0 — VMD's reported value was not propagated to the response")
	}
	if v := body["memory_mib"].(float64); v == 0 {
		t.Error("memory_mib is 0 — VMD's reported value was not propagated to the response")
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
	setupTestRouter(h, "").ServeHTTP(w, createSandboxReq(`{"name":"test"}`))

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
		execFn: func(_ context.Context, _ string, _ ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, createSandboxReq(`{"name":"sb"}`))

	// Creation is synchronous — VMD error returns 500.
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
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
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "'pausing'"):
				// BeginPause: atomic transition active → pausing, returns *
				return sandboxRow(sb)
			case strings.Contains(sql, "INSERT INTO snapshot"):
				// FinalizePause: CTE insert + update, returns snapshot_id
				return finalizePauseRow(snapshotID)
			case strings.Contains(sql, "FROM sandbox"):
				// Generic GetSandbox (fallback from BeginPause)
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

	// BeginPause's WHERE status = 'active' clause excludes an idle
	// sandbox → 0 rows. The handler falls back to SandboxExists to
	// disambiguate 404 vs 409; since the row exists (just in the wrong
	// state), we return 409 Conflict.
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if strings.Contains(sql, "'pausing'") {
				return notFoundRow() // BeginPause: no active row matched
			}
			if strings.Contains(sql, "EXISTS") {
				return boolRow(true) // fallback: row exists, but not active
			}
			return notFoundRow()
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) { return pgconn.NewCommandTag(""), nil },
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
	// BeginPause returns 0 rows (sandbox doesn't exist), and the
	// SandboxExists fallback also returns false → 404.
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if strings.Contains(sql, "'pausing'") {
				return notFoundRow()
			}
			if strings.Contains(sql, "EXISTS") {
				return boolRow(false)
			}
			return notFoundRow()
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) { return pgconn.NewCommandTag(""), nil },
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


func TestParseSandboxID_Valid(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "sandbox_id", Value: uuid.New().String()}}
	if _, err := parseSandboxID(c); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestParseSandboxID_Invalid(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "sandbox_id", Value: "bad"}}
	if _, err := parseSandboxID(c); err == nil {
		t.Fatal("expected error for invalid UUID")
	}
}

func TestTeamIDFromContext_Valid(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	teamID := uuid.New().String()
	c.Set("team_id", teamID)
	got, err := teamIDFromContext(c)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if got.String() != teamID {
		t.Errorf("expected %s, got %s", teamID, got.String())
	}
}

func TestTeamIDFromContext_Missing(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	if _, err := teamIDFromContext(c); err == nil {
		t.Fatal("expected error for missing team_id")
	}
}

func TestTeamIDFromContext_InvalidUUID(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set("team_id", "not-a-uuid")
	if _, err := teamIDFromContext(c); err == nil {
		t.Fatal("expected error for invalid team_id UUID")
	}
}

// ---------------------------------------------------------------------------
// validateMetadata tests
// ---------------------------------------------------------------------------

func TestValidateMetadata(t *testing.T) {
	tests := []struct {
		name    string
		md      map[string]string
		wantErr bool
		errSub  string // substring expected in the error message
	}{
		{name: "nil ok", md: nil},
		{name: "empty ok", md: map[string]string{}},
		{name: "happy path", md: map[string]string{"env": "prod", "owner": "agent-7"}},
		{
			name:    "too many keys",
			md:      makeMetadata(metadataMaxKeys+1, "k", "v"),
			wantErr: true,
			errSub:  "max is 64",
		},
		{
			name:    "key too long",
			md:      map[string]string{strings.Repeat("k", metadataMaxKeyLen+1): "v"},
			wantErr: true,
			errSub:  "max is 256",
		},
		{
			name:    "value too long",
			md:      map[string]string{"k": strings.Repeat("v", metadataMaxValueLen+1)},
			wantErr: true,
			errSub:  "max is 2048",
		},
		{
			name:    "empty key",
			md:      map[string]string{"": "v"},
			wantErr: true,
			errSub:  "cannot be empty",
		},
		{
			name:    "reserved prefix lower",
			md:      map[string]string{"superserve.tier": "gold"},
			wantErr: true,
			errSub:  "reserved prefix",
		},
		{
			name:    "reserved prefix upper",
			md:      map[string]string{"SUPERSERVE.tier": "gold"},
			wantErr: true,
			errSub:  "reserved prefix",
		},
		{
			name:    "reserved underscore",
			md:      map[string]string{"_superserve_internal": "x"},
			wantErr: true,
			errSub:  "reserved prefix",
		},
		{
			name:    "total bytes exceeded",
			md:      map[string]string{"a": strings.Repeat("v", metadataMaxValueLen), "b": strings.Repeat("v", metadataMaxValueLen), "c": strings.Repeat("v", metadataMaxValueLen), "d": strings.Repeat("v", metadataMaxValueLen), "e": strings.Repeat("v", metadataMaxValueLen), "f": strings.Repeat("v", metadataMaxValueLen), "g": strings.Repeat("v", metadataMaxValueLen), "h": strings.Repeat("v", metadataMaxValueLen), "i": strings.Repeat("v", metadataMaxValueLen)},
			wantErr: true,
			errSub:  "16384 bytes total",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateMetadata(tc.md)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.errSub)
				}
				if tc.errSub != "" && !strings.Contains(err.Error(), tc.errSub) {
					t.Fatalf("error %q does not contain %q", err.Error(), tc.errSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// makeMetadata builds a metadata map with n entries — used to exercise the
// max-keys check without typing out 65 literals.
func makeMetadata(n int, keyPrefix, val string) map[string]string {
	out := make(map[string]string, n)
	for i := 0; i < n; i++ {
		out[fmt.Sprintf("%s%d", keyPrefix, i)] = val
	}
	return out
}

// ---------------------------------------------------------------------------
// parseMetadataFilter tests
// ---------------------------------------------------------------------------

func TestParseMetadataFilter(t *testing.T) {
	t.Run("no filters", func(t *testing.T) {
		got, err := parseMetadataFilter(map[string][]string{"page": {"1"}})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("expected empty filter, got %v", got)
		}
	})

	t.Run("multiple filters", func(t *testing.T) {
		got, err := parseMetadataFilter(map[string][]string{
			"metadata.env":   {"prod"},
			"metadata.owner": {"agent-7"},
			"page":           {"1"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got["env"] != "prod" || got["owner"] != "agent-7" {
			t.Fatalf("got %v, want env=prod owner=agent-7", got)
		}
	})

	t.Run("empty key after prefix rejected", func(t *testing.T) {
		_, err := parseMetadataFilter(map[string][]string{"metadata.": {"x"}})
		if err == nil {
			t.Fatal("expected error for empty filter key")
		}
	})

	t.Run("repeated value rejected", func(t *testing.T) {
		_, err := parseMetadataFilter(map[string][]string{"metadata.k": {"a", "b"}})
		if err == nil {
			t.Fatal("expected error for repeated filter value")
		}
	})

	t.Run("filter values inherit metadata limits", func(t *testing.T) {
		_, err := parseMetadataFilter(map[string][]string{
			"metadata.k": {strings.Repeat("v", metadataMaxValueLen+1)},
		})
		if err == nil {
			t.Fatal("expected error for oversized filter value")
		}
	})
}

// ---------------------------------------------------------------------------
// CreateSandbox metadata tests
// ---------------------------------------------------------------------------

func TestCreateSandbox_WithMetadata(t *testing.T) {
	teamID := uuid.New()
	sandboxID := uuid.New()

	var capturedMetadata []byte
	vmd := &stubVMD{
		createFn: func(context.Context, string, uint32, uint32, uint32, map[string]string) (string, error) {
			return "10.0.0.42", nil
		},
	}
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			if strings.Contains(sql, "INSERT INTO sandbox") {
				// Positional args (0-indexed): id, team_id, name, status,
				// vcpu, mem, host_id, ip, pid, snapshot_id, timeout, metadata.
				if b, ok := args[11].([]byte); ok {
					capturedMetadata = b
				}
				// Echo metadata back through the row so the response carries it.
				return sandboxRow(db.Sandbox{
					ID: sandboxID, TeamID: teamID, Name: "tagged",
					Status: db.SandboxStatusStarting, VcpuCount: 1, MemoryMib: 512,
					CreatedAt: time.Now(),
					Metadata:  capturedMetadata,
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
	body := `{"name":"tagged","metadata":{"env":"prod","owner":"agent-7"}}`
	setupTestRouter(h, teamID.String()).ServeHTTP(w, createSandboxReq(body))

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", w.Code, w.Body.String())
	}
	if string(capturedMetadata) == "" {
		t.Fatal("metadata was not passed to CreateSandbox params")
	}
	// Verify the captured jsonb decodes back to our map.
	var roundTrip map[string]string
	if err := json.Unmarshal(capturedMetadata, &roundTrip); err != nil {
		t.Fatalf("decode captured metadata: %v", err)
	}
	if roundTrip["env"] != "prod" || roundTrip["owner"] != "agent-7" {
		t.Fatalf("round-trip metadata = %v, want env=prod owner=agent-7", roundTrip)
	}

	// Response should echo metadata.
	resp := parseJSON(t, w)
	mdResp, _ := resp["metadata"].(map[string]any)
	if mdResp["env"] != "prod" || mdResp["owner"] != "agent-7" {
		t.Fatalf("response metadata = %v, want env=prod owner=agent-7", mdResp)
	}
}

func TestCreateSandbox_EmptyMetadataIsObjectNotNull(t *testing.T) {
	teamID := uuid.New()
	sandboxID := uuid.New()

	var capturedMetadata []byte
	vmd := &stubVMD{
		createFn: func(context.Context, string, uint32, uint32, uint32, map[string]string) (string, error) {
			return "10.0.0.42", nil
		},
	}
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			if strings.Contains(sql, "INSERT INTO sandbox") {
				// Positional args (0-indexed): id, team_id, name, status,
				// vcpu, mem, host_id, ip, pid, snapshot_id, timeout, metadata.
				if b, ok := args[11].([]byte); ok {
					capturedMetadata = b
				}
				return sandboxRow(db.Sandbox{
					ID: sandboxID, TeamID: teamID, Name: "no-md",
					Status: db.SandboxStatusStarting, VcpuCount: 1, MemoryMib: 512,
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
	setupTestRouter(h, teamID.String()).ServeHTTP(w, createSandboxReq(`{"name":"no-md"}`))

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", w.Code, w.Body.String())
	}
	if string(capturedMetadata) != "{}" {
		t.Fatalf("metadata sent to DB = %q, want %q", string(capturedMetadata), "{}")
	}

	// Response should serialize metadata as `{}`, not `null`.
	if !strings.Contains(w.Body.String(), `"metadata":{}`) {
		t.Fatalf("response body should contain \"metadata\":{}, got %s", w.Body.String())
	}
}

func TestCreateSandbox_MetadataValidationRejected(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{name: "reserved prefix", body: `{"name":"x","metadata":{"superserve.tier":"gold"}}`},
		{name: "key too long", body: fmt.Sprintf(`{"name":"x","metadata":{%q:"v"}}`, strings.Repeat("k", metadataMaxKeyLen+1))},
		{name: "value too long", body: fmt.Sprintf(`{"name":"x","metadata":{"k":%q}}`, strings.Repeat("v", metadataMaxValueLen+1))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vmd := &stubVMD{}
			mock := &mockDBTX{
				queryRowFn: func(context.Context, string, ...any) pgx.Row {
					t.Fatal("DB should not be called when validation fails")
					return notFoundRow()
				},
				execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
					t.Fatal("DB should not be called when validation fails")
					return pgconn.NewCommandTag(""), nil
				},
			}
			h := &Handlers{VMD: vmd, DB: db.New(mock)}
			w := httptest.NewRecorder()
			setupTestRouter(h, uuid.New().String()).ServeHTTP(w, createSandboxReq(tc.body))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
			}
		})
	}
}
