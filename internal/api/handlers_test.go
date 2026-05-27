package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

// ---------------------------------------------------------------------------
// Mock VMDClient
// ---------------------------------------------------------------------------

type stubVMD struct {
	destroyFn        func(ctx context.Context, id string, force bool) error
	pauseFn          func(ctx context.Context, id, snapshotDir string) (string, string, error)
	resumeFn         func(ctx context.Context, id, snapshotPath, memPath string) (string, error)
	restoreFn        func(ctx context.Context, id, snapshotPath, memPath string) (string, error)
	deleteSnapshotFn func(ctx context.Context, id, snapshotPath, memPath string) error
	updateNetworkFn  func(ctx context.Context, id string, allowedCIDRs, deniedCIDRs, allowedDomains []string) error
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
func (s *stubVMD) RestoreSnapshot(ctx context.Context, id, snapshotPath, memPath, _, _ string, _ map[string]string) (string, uint32, uint32, error) {
	if s.restoreFn != nil {
		ip, err := s.restoreFn(ctx, id, snapshotPath, memPath)
		return ip, 1, 1024, err
	}
	return "10.0.0.1", 1, 1024, nil
}
func (s *stubVMD) DeleteSnapshot(ctx context.Context, id, snapshotPath, memPath string) error {
	if s.deleteSnapshotFn != nil {
		return s.deleteSnapshotFn(ctx, id, snapshotPath, memPath)
	}
	return nil
}
func (s *stubVMD) DeleteTemplateArtifacts(_ context.Context, _ string) error { return nil }
func (s *stubVMD) DeleteBuildArtifacts(_ context.Context, _, _ string) error { return nil }
func (s *stubVMD) ListBuildArtifacts(_ context.Context) ([]vmdclient.BuildArtifactEntry, error) {
	return nil, nil
}
func (s *stubVMD) UpdateSandboxNetwork(ctx context.Context, id string, allowed, denied, domains []string) error {
	if s.updateNetworkFn != nil {
		return s.updateNetworkFn(ctx, id, allowed, denied, domains)
	}
	return nil
}

// Template build methods — no-op stubs. Handler tests don't exercise
// the build pipeline; supervisor integration tests are the right place
// for that. Kept minimal so adding real behavior per test is easy.

func (s *stubVMD) BuildTemplate(_ context.Context, _ vmdclient.BuildTemplateInput) (string, error) {
	return "", nil
}
func (s *stubVMD) GetBuildStatus(_ context.Context, _ string) (vmdclient.BuildStatusResult, error) {
	return vmdclient.BuildStatusResult{}, nil
}
func (s *stubVMD) CancelBuild(_ context.Context, _ string) error { return nil }
func (s *stubVMD) StreamBuildLogs(_ context.Context, _ string, _ func(vmdclient.BuildLogEvent) error) error {
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
// call (16 destination pointers matching the column order in sqlc-generated
// queries: ID, TeamID, Name, Status, VcpuCount, MemoryMib, HostID, IpAddress,
// Pid, SnapshotID, CreatedAt, UpdatedAt, DestroyedAt, NetworkConfig,
// TimeoutSeconds, Metadata).
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
		*dest[10].(*time.Time) = s.CreatedAt
		*dest[11].(*time.Time) = s.UpdatedAt
		*dest[12].(*pgtype.Timestamptz) = s.DestroyedAt
		*dest[13].(*[]byte) = s.NetworkConfig
		*dest[14].(**int32) = s.TimeoutSeconds
		*dest[15].(*[]byte) = s.Metadata
		return nil
	}}
}

// templateRow returns a mockRow that populates a Template from a Scan call
// matching the 17-column order in sqlc-generated template queries.
func templateRow(t db.Template) *mockRow {
	return &mockRow{scanFn: func(dest ...any) error {
		*dest[0].(*uuid.UUID) = t.ID
		*dest[1].(*uuid.UUID) = t.TeamID
		*dest[2].(*string) = t.Name
		*dest[3].(*db.TemplateStatus) = t.Status
		*dest[4].(*[]byte) = t.BuildSpec
		*dest[5].(*int32) = t.Vcpu
		*dest[6].(*int32) = t.MemoryMib
		*dest[7].(*int32) = t.DiskMib
		*dest[8].(**string) = t.RootfsPath
		*dest[9].(**string) = t.SnapshotPath
		*dest[10].(**string) = t.MemPath
		*dest[11].(**int64) = t.SizeBytes
		*dest[12].(**string) = t.ErrorMessage
		*dest[13].(*time.Time) = t.CreatedAt
		*dest[14].(*time.Time) = t.UpdatedAt
		*dest[15].(*pgtype.Timestamptz) = t.BuiltAt
		*dest[16].(*pgtype.Timestamptz) = t.DeletedAt
		return nil
	}}
}

// defaultReadyTemplate returns a Template row suitable for tests that don't
// set from_template explicitly — since the handler now defaults it to
// "superserve/base", creates route through a template lookup even with no body field.
func defaultReadyTemplate() db.Template {
	snap := "/snap/vmstate.snap"
	mem := "/snap/mem.snap"
	return db.Template{
		ID:           uuid.New(),
		Name:         "superserve/base",
		Status:       db.TemplateStatusReady,
		Vcpu:         1,
		MemoryMib:    1024,
		DiskMib:      4096,
		SnapshotPath: &snap,
		MemPath:      &mem,
	}
}

func notFoundRow() *mockRow {
	return &mockRow{scanFn: func(...any) error { return pgx.ErrNoRows }}
}

func errorRow(err error) *mockRow {
	return &mockRow{scanFn: func(...any) error { return err }}
}

// activityRow returns a mockRow for CreateActivity's Scan (14 fields).
func activityRow() *mockRow {
	return &mockRow{scanFn: func(dest ...any) error {
		*dest[0].(*uuid.UUID) = uuid.New()
		*dest[1].(*pgtype.UUID) = pgtype.UUID{}
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
		*dest[12].(*pgtype.UUID) = pgtype.UUID{}
		*dest[13].(*string) = "sandbox"
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
	r.POST("/sandboxes/:sandbox_id/activate", h.ActivateSandbox)
	r.POST("/sandboxes/:sandbox_id/pause", h.PauseSandbox)
	r.DELETE("/sandboxes/:sandbox_id", h.DeleteSandbox)
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
		*dest[5].(*string) = s.Trigger
		*dest[6].(*time.Time) = s.CreatedAt
		*dest[7].(**string) = s.MemPath
		return nil
	}}
}

// finalizePauseRow mocks the single-column RETURNING of FinalizePause.
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

func activateRequest(sandboxID string) *http.Request {
	return httptest.NewRequest(http.MethodPost, "/sandboxes/"+sandboxID+"/activate", nil)
}

func pausedSandboxWithSnapshot(sandboxID, teamID, snapshotID uuid.UUID) db.Sandbox {
	return db.Sandbox{
		ID:         sandboxID,
		TeamID:     teamID,
		Name:       "test-sb",
		Status:     db.SandboxStatusPaused,
		SnapshotID: pgtype.UUID{Bytes: snapshotID, Valid: true},
	}
}

func TestResumeSandbox_Success(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	snapshotID := uuid.New()
	sb := pausedSandboxWithSnapshot(sandboxID, teamID, snapshotID)
	snap := db.Snapshot{
		ID:        snapshotID,
		SandboxID: sandboxID,
		TeamID:    teamID,
		Path:      "/snapshots/test/vmstate.snap",
		SizeBytes: 1024,
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

	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "'resuming'"):
				return sandboxRow(sb) // BeginResume RETURNING *
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

	// Resume returns the minimal {id, status, access_token} shape, not the
	// full sandbox response.
	body := parseJSON(t, w)
	if body["status"] != "active" {
		t.Errorf("status = %q, want %q", body["status"], "active")
	}
	if body["id"] != sandboxID.String() {
		t.Errorf("id = %q, want %q", body["id"], sandboxID)
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

func TestResumeSandbox_NotPaused(t *testing.T) {
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
	// Paused but no snapshot_id set.
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Name: "sb", Status: db.SandboxStatusPaused}

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
	sb := pausedSandboxWithSnapshot(sandboxID, teamID, snapshotID)
	snap := db.Snapshot{
		ID: snapshotID, SandboxID: sandboxID, TeamID: teamID,
		Path: "/snapshots/test/vmstate.snap", Trigger: "pause",
	}

	vmd := &stubVMD{
		destroyFn: func(context.Context, string, bool) error { return nil },
		resumeFn: func(context.Context, string, string, string) (string, error) {
			return "", fmt.Errorf("vmd unreachable")
		},
	}

	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "'resuming'"):
				return sandboxRow(sb)
			case strings.Contains(sql, "FROM sandbox"):
				return sandboxRow(sb)
			default:
				return snapshotRow(snap)
			}
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

// Network-reapply failure after VMD resume must destroy the VM, revert DB to
// paused, and never flip status to active.
func TestResumeSandbox_NetworkReapplyFailure_DestroysAndReverts(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	snapshotID := uuid.New()
	sb := pausedSandboxWithSnapshot(sandboxID, teamID, snapshotID)
	sb.NetworkConfig = []byte(`{"egress":{"allowed_cidrs":["10.0.0.0/8"]}}`)
	snap := db.Snapshot{
		ID: snapshotID, SandboxID: sandboxID, TeamID: teamID,
		Path: "/snapshots/test/vmstate.snap", Trigger: "pause",
	}

	var destroyCalled, updateNetworkCalled int32
	vmd := &stubVMD{
		resumeFn: func(context.Context, string, string, string) (string, error) {
			return "10.0.0.5", nil
		},
		destroyFn: func(context.Context, string, bool) error {
			atomic.AddInt32(&destroyCalled, 1)
			return nil
		},
		updateNetworkFn: func(context.Context, string, []string, []string, []string) error {
			atomic.AddInt32(&updateNetworkCalled, 1)
			return fmt.Errorf("nftables push failed")
		},
	}

	var activateCalled, revertCalled int32
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "'resuming'"):
				return sandboxRow(sb)
			case strings.Contains(sql, "FROM sandbox"):
				return sandboxRow(sb)
			case strings.Contains(sql, "FROM snapshot"):
				return snapshotRow(snap)
			}
			return activityRow()
		},
		execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			if strings.Contains(sql, "'active'") {
				atomic.AddInt32(&activateCalled, 1)
			}
			if strings.Contains(sql, "SET status = 'paused'") {
				atomic.AddInt32(&revertCalled, 1)
			}
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, resumeRequest(sandboxID.String()))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
	if got := atomic.LoadInt32(&updateNetworkCalled); got != 1 {
		t.Errorf("reapplyNetworkConfig calls = %d, want 1", got)
	}
	if got := atomic.LoadInt32(&destroyCalled); got != 1 {
		t.Errorf("DestroyInstance calls = %d, want 1 (on failure)", got)
	}
	if got := atomic.LoadInt32(&activateCalled); got != 0 {
		t.Errorf("ActivateSandbox calls = %d, want 0 (network failed before commit)", got)
	}
	if got := atomic.LoadInt32(&revertCalled); got != 1 {
		t.Errorf("RevertResumeToPaused calls = %d, want 1", got)
	}
}

// DB activate failure after network reapply must also destroy the VM + revert.
func TestResumeSandbox_ActivateFailure_DestroysAndReverts(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	snapshotID := uuid.New()
	sb := pausedSandboxWithSnapshot(sandboxID, teamID, snapshotID)
	snap := db.Snapshot{
		ID: snapshotID, SandboxID: sandboxID, TeamID: teamID,
		Path: "/snapshots/test/vmstate.snap", Trigger: "pause",
	}

	var destroyCalled int32
	vmd := &stubVMD{
		resumeFn: func(context.Context, string, string, string) (string, error) {
			return "10.0.0.5", nil
		},
		destroyFn: func(context.Context, string, bool) error {
			atomic.AddInt32(&destroyCalled, 1)
			return nil
		},
	}

	var revertCalled int32
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "'resuming'"):
				return sandboxRow(sb)
			case strings.Contains(sql, "FROM sandbox"):
				return sandboxRow(sb)
			case strings.Contains(sql, "FROM snapshot"):
				return snapshotRow(snap)
			}
			return activityRow()
		},
		execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			if strings.Contains(sql, "'active'") {
				return pgconn.CommandTag{}, fmt.Errorf("db connection lost")
			}
			if strings.Contains(sql, "SET status = 'paused'") {
				atomic.AddInt32(&revertCalled, 1)
			}
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, resumeRequest(sandboxID.String()))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
	if got := atomic.LoadInt32(&destroyCalled); got != 1 {
		t.Errorf("DestroyInstance calls = %d, want 1", got)
	}
	if got := atomic.LoadInt32(&revertCalled); got != 1 {
		t.Errorf("RevertResumeToPaused calls = %d, want 1", got)
	}
}

// ---------------------------------------------------------------------------
// ActivateSandbox tests — idempotent "make this sandbox usable" endpoint.
// Reuses loadActiveOrResumeSandbox under the hood; the tests focus on the
// edge case ResumeSandbox doesn't cover (already-active sandbox returns 200
// with a token, no VMD call).
// ---------------------------------------------------------------------------

func TestActivateSandbox_AlreadyActive_200WithSandboxResponse(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	sb := db.Sandbox{
		ID: sandboxID, TeamID: teamID, Name: "sb", Status: db.SandboxStatusActive,
		VcpuCount: 2, MemoryMib: 1024,
	}

	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row { return sandboxRow(sb) },
	}
	vmd := &stubVMD{}

	h := &Handlers{
		VMD:    vmd,
		DB:     db.New(mock),
		Config: &config.Config{SandboxAccessTokenSeed: []byte("test-seed-for-hmac-32-bytes-min!!")},
	}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, activateRequest(sandboxID.String()))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
	body := parseJSON(t, w)
	if body["status"] != "active" {
		t.Errorf("status = %q, want active", body["status"])
	}
	if body["id"] != sandboxID.String() {
		t.Errorf("id = %q, want %q", body["id"], sandboxID)
	}
	if _, ok := body["access_token"].(string); !ok {
		t.Error("expected access_token in response when SandboxAccessTokenSeed is set")
	}
	if body["vcpu_count"].(float64) != 2 {
		t.Errorf("vcpu_count = %v, want 2", body["vcpu_count"])
	}
}

func TestActivateSandbox_PausedResumesAndReturns200(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	snapshotID := uuid.New()
	sb := pausedSandboxWithSnapshot(sandboxID, teamID, snapshotID)
	snap := db.Snapshot{
		ID: snapshotID, SandboxID: sandboxID, TeamID: teamID,
		Path: "/snapshots/test/vmstate.snap", SizeBytes: 1024, Trigger: "pause",
	}

	var resumeCalled bool
	vmd := &stubVMD{
		destroyFn: func(context.Context, string, bool) error { return nil },
		resumeFn: func(_ context.Context, id, _, _ string) (string, error) {
			resumeCalled = true
			return "10.0.0.5", nil
		},
	}
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "'resuming'"):
				return sandboxRow(sb)
			case strings.Contains(sql, "FROM sandbox"):
				return sandboxRow(sb)
			case strings.Contains(sql, "FROM snapshot"):
				return snapshotRow(snap)
			default:
				return activityRow()
			}
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}

	h := &Handlers{
		VMD:    vmd,
		DB:     db.New(mock),
		Config: &config.Config{SandboxAccessTokenSeed: []byte("test-seed-for-hmac-32-bytes-min!!")},
	}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, activateRequest(sandboxID.String()))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
	if !resumeCalled {
		t.Error("VMD.ResumeInstance was not called for paused sandbox")
	}
	body := parseJSON(t, w)
	if body["status"] != "active" {
		t.Errorf("status = %q, want active", body["status"])
	}
	if _, ok := body["access_token"].(string); !ok {
		t.Error("expected access_token in response")
	}
}

func TestActivateSandbox_NotFound(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()

	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row { return notFoundRow() },
	}
	h := &Handlers{VMD: &stubVMD{}, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, activateRequest(sandboxID.String()))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestActivateSandbox_NonResumableStates_409(t *testing.T) {
	cases := []db.SandboxStatus{
		db.SandboxStatusFailed,
		db.SandboxStatusPausing,
		db.SandboxStatusResuming,
		db.SandboxStatusStarting,
	}
	for _, status := range cases {
		t.Run(string(status), func(t *testing.T) {
			sandboxID := uuid.New()
			teamID := uuid.New()
			sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Status: status}

			mock := &mockDBTX{
				queryRowFn: func(context.Context, string, ...any) pgx.Row { return sandboxRow(sb) },
			}
			h := &Handlers{VMD: &stubVMD{}, DB: db.New(mock)}
			w := httptest.NewRecorder()
			setupTestRouter(h, teamID.String()).ServeHTTP(w, activateRequest(sandboxID.String()))

			if w.Code != http.StatusConflict {
				t.Errorf("status = %d, want %d", w.Code, http.StatusConflict)
			}
		})
	}
}

func TestActivateSandbox_InvalidUUID(t *testing.T) {
	teamID := uuid.New()
	h := &Handlers{VMD: &stubVMD{}, DB: db.New(&mockDBTX{})}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, activateRequest("not-a-uuid"))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

