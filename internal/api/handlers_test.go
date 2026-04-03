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
	destroyFn func(ctx context.Context, id string, force bool) error
}

func (s *stubVMD) CreateInstance(context.Context, string, uint32, uint32, uint32, map[string]string) (string, error) {
	return "", nil
}
func (s *stubVMD) DestroyInstance(ctx context.Context, id string, force bool) error {
	return s.destroyFn(ctx, id, force)
}
func (s *stubVMD) PauseInstance(context.Context, string, string) (string, string, error) {
	return "", "", nil
}
func (s *stubVMD) ResumeInstance(context.Context, string, string, string) (string, error) {
	return "", nil
}
func (s *stubVMD) ExecCommand(context.Context, string, string, []string, map[string]string, string, uint32) (string, string, int32, error) {
	return "", "", 0, nil
}
func (s *stubVMD) ExecCommandStream(context.Context, string, string, []string, map[string]string, string, uint32, func([]byte, []byte, int32, bool)) error {
	return nil
}
func (s *stubVMD) UploadFile(context.Context, string, string, io.Reader) (int64, error) {
	return 0, nil
}
func (s *stubVMD) DownloadFile(context.Context, string, string) (io.ReadCloser, error) {
	return nil, nil
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
	r.DELETE("/sandboxes/:sandbox_id", h.DeleteSandbox)
	return r
}

func deleteRequest(sandboxID string) *http.Request {
	return httptest.NewRequest(http.MethodDelete, "/sandboxes/"+sandboxID, nil)
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
