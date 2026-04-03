package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/superserve-ai/sandbox/internal/db"
)

// ---------------------------------------------------------------------------
// Mock VMDClient
// ---------------------------------------------------------------------------

type mockVMD struct {
	createInstanceFn    func(ctx context.Context, instanceID string, vcpu, memMiB, diskMiB uint32, metadata map[string]string) (string, error)
	destroyInstanceFn   func(ctx context.Context, instanceID string, force bool) error
	pauseInstanceFn     func(ctx context.Context, instanceID, snapshotDir string) (string, string, error)
	resumeInstanceFn    func(ctx context.Context, instanceID, snapshotPath, memPath string) (string, error)
	execCommandFn       func(ctx context.Context, instanceID, command string, args []string, env map[string]string, workingDir string, timeoutS uint32) (string, string, int32, error)
	execCommandStreamFn func(ctx context.Context, instanceID, command string, args []string, env map[string]string, workingDir string, timeoutS uint32, onChunk func([]byte, []byte, int32, bool)) error
	uploadFileFn        func(ctx context.Context, instanceID, path string, content io.Reader) (int64, error)
	downloadFileFn      func(ctx context.Context, instanceID, path string) (io.ReadCloser, error)
}

func (m *mockVMD) CreateInstance(ctx context.Context, instanceID string, vcpu, memMiB, diskMiB uint32, metadata map[string]string) (string, error) {
	if m.createInstanceFn != nil {
		return m.createInstanceFn(ctx, instanceID, vcpu, memMiB, diskMiB, metadata)
	}
	return "10.0.0.1", nil
}

func (m *mockVMD) DestroyInstance(ctx context.Context, instanceID string, force bool) error {
	if m.destroyInstanceFn != nil {
		return m.destroyInstanceFn(ctx, instanceID, force)
	}
	return nil
}

func (m *mockVMD) PauseInstance(ctx context.Context, instanceID, snapshotDir string) (string, string, error) {
	if m.pauseInstanceFn != nil {
		return m.pauseInstanceFn(ctx, instanceID, snapshotDir)
	}
	return "/snap/path", "/mem/path", nil
}

func (m *mockVMD) ResumeInstance(ctx context.Context, instanceID, snapshotPath, memPath string) (string, error) {
	if m.resumeInstanceFn != nil {
		return m.resumeInstanceFn(ctx, instanceID, snapshotPath, memPath)
	}
	return "10.0.0.1", nil
}

func (m *mockVMD) ExecCommand(ctx context.Context, instanceID, command string, args []string, env map[string]string, workingDir string, timeoutS uint32) (string, string, int32, error) {
	if m.execCommandFn != nil {
		return m.execCommandFn(ctx, instanceID, command, args, env, workingDir, timeoutS)
	}
	return "hello\n", "", 0, nil
}

func (m *mockVMD) ExecCommandStream(ctx context.Context, instanceID, command string, args []string, env map[string]string, workingDir string, timeoutS uint32, onChunk func([]byte, []byte, int32, bool)) error {
	if m.execCommandStreamFn != nil {
		return m.execCommandStreamFn(ctx, instanceID, command, args, env, workingDir, timeoutS, onChunk)
	}
	onChunk([]byte("hello\n"), nil, 0, true)
	return nil
}

func (m *mockVMD) UploadFile(ctx context.Context, instanceID, path string, content io.Reader) (int64, error) {
	if m.uploadFileFn != nil {
		return m.uploadFileFn(ctx, instanceID, path, content)
	}
	return 42, nil
}

func (m *mockVMD) DownloadFile(ctx context.Context, instanceID, path string) (io.ReadCloser, error) {
	if m.downloadFileFn != nil {
		return m.downloadFileFn(ctx, instanceID, path)
	}
	return io.NopCloser(strings.NewReader("file-content")), nil
}

// ---------------------------------------------------------------------------
// Mock DB (implements the subset of db.Queries used by handlers)
// ---------------------------------------------------------------------------

type mockDBTX struct {
	execFn     func(ctx context.Context, sql string, args ...interface{}) (mockCommandTag, error)
	queryFn    func(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error)
	queryRowFn func(ctx context.Context, sql string, args ...interface{}) pgx.Row
}

type mockCommandTag struct{}

func (t mockCommandTag) RowsAffected() int64 { return 1 }
func (t mockCommandTag) String() string       { return "OK" }

// mockRow implements pgx.Row for returning sandbox data or errors.
type mockRow struct {
	sandbox *db.Sandbox
	err     error
}

func (r *mockRow) Scan(dest ...interface{}) error {
	if r.err != nil {
		return r.err
	}
	if r.sandbox == nil {
		return pgx.ErrNoRows
	}
	s := r.sandbox
	// GetSandbox scans: id, team_id, name, status, vcpu_count, memory_mib,
	// host_id, ip_address, pid, snapshot_id, last_activity_at, created_at, updated_at, destroyed_at
	if len(dest) >= 14 {
		*dest[0].(*uuid.UUID) = s.ID
		*dest[1].(*uuid.UUID) = s.TeamID
		*dest[2].(*string) = s.Name
		*dest[3].(*db.SandboxStatus) = s.Status
		*dest[4].(*int32) = s.VcpuCount
		*dest[5].(*int32) = s.MemoryMib
	}
	return nil
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func init() {
	gin.SetMode(gin.TestMode)
}

// setupTestRouter creates a Gin engine with the handler under test.
// It skips the real auth middleware and injects team_id directly.
func setupTestRouter(h *Handlers, teamID string) *gin.Engine {
	r := gin.New()
	// Inject team_id as auth middleware would.
	r.Use(func(c *gin.Context) {
		if teamID != "" {
			c.Set("team_id", teamID)
		}
		c.Next()
	})

	r.GET("/health", h.Health)
	r.POST("/instances", h.CreateInstance)
	r.GET("/instances/:instance_id", h.GetInstance)
	r.GET("/instances", h.ListInstances)
	r.DELETE("/instances/:instance_id", h.DeleteInstance)
	r.POST("/instances/:instance_id/pause", h.PauseInstance)
	r.POST("/instances/:instance_id/resume", h.ResumeInstance)
	r.POST("/instances/:instance_id/exec", h.ExecCommand)
	r.POST("/instances/:instance_id/exec/stream", h.ExecCommandStream)
	r.PUT("/instances/:instance_id/files/*path", h.UploadFile)
	r.GET("/instances/:instance_id/files/*path", h.DownloadFile)
	r.DELETE("/sandboxes/:sandbox_id", h.DeleteSandbox)
	return r
}

func newTestHandlers(vmd VMDClient) *Handlers {
	return &Handlers{VMD: vmd}
}

func jsonBody(v interface{}) *bytes.Buffer {
	b, _ := json.Marshal(v)
	return bytes.NewBuffer(b)
}

func parseJSON(t *testing.T, body *bytes.Buffer) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal(body.Bytes(), &m); err != nil {
		t.Fatalf("failed to parse JSON response: %v\nbody: %s", err, body.String())
	}
	return m
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

func TestHealth(t *testing.T) {
	h := newTestHandlers(&mockVMD{})
	r := setupTestRouter(h, "")

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/health", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := parseJSON(t, w.Body)
	if body["status"] != "ok" {
		t.Errorf("expected status=ok, got %v", body["status"])
	}
	if body["version"] != "0.1.0" {
		t.Errorf("expected version=0.1.0, got %v", body["version"])
	}
}

// ---------------------------------------------------------------------------
// CreateInstance
// ---------------------------------------------------------------------------

func TestCreateInstance_Success(t *testing.T) {
	vmd := &mockVMD{}
	h := newTestHandlers(vmd)
	r := setupTestRouter(h, uuid.New().String())

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/instances", jsonBody(map[string]string{"name": "test-box"}))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	body := parseJSON(t, w.Body)
	if body["name"] != "test-box" {
		t.Errorf("expected name=test-box, got %v", body["name"])
	}
	if body["status"] != "RUNNING" {
		t.Errorf("expected status=RUNNING, got %v", body["status"])
	}
	if body["id"] == nil || body["id"] == "" {
		t.Errorf("expected non-empty id")
	}
}

func TestCreateInstance_BadRequest_MissingName(t *testing.T) {
	h := newTestHandlers(&mockVMD{})
	r := setupTestRouter(h, uuid.New().String())

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/instances", jsonBody(map[string]string{}))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCreateInstance_BadRequest_EmptyBody(t *testing.T) {
	h := newTestHandlers(&mockVMD{})
	r := setupTestRouter(h, uuid.New().String())

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/instances", nil)
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCreateInstance_VMDFailure(t *testing.T) {
	vmd := &mockVMD{
		createInstanceFn: func(ctx context.Context, instanceID string, vcpu, memMiB, diskMiB uint32, metadata map[string]string) (string, error) {
			return "", errors.New("vmd unavailable")
		},
	}
	h := newTestHandlers(vmd)
	r := setupTestRouter(h, uuid.New().String())

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/instances", jsonBody(map[string]string{"name": "fail-box"}))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// DeleteInstance
// ---------------------------------------------------------------------------

func TestDeleteInstance_Success(t *testing.T) {
	vmd := &mockVMD{}
	h := newTestHandlers(vmd)
	r := setupTestRouter(h, uuid.New().String())

	id := uuid.New().String()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("DELETE", "/instances/"+id, nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDeleteInstance_InvalidUUID(t *testing.T) {
	h := newTestHandlers(&mockVMD{})
	r := setupTestRouter(h, uuid.New().String())

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("DELETE", "/instances/not-a-uuid", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestDeleteInstance_VMDFailure(t *testing.T) {
	vmd := &mockVMD{
		destroyInstanceFn: func(ctx context.Context, instanceID string, force bool) error {
			return errors.New("destroy failed")
		},
	}
	h := newTestHandlers(vmd)
	r := setupTestRouter(h, uuid.New().String())

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("DELETE", "/instances/"+uuid.New().String(), nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// PauseInstance
// ---------------------------------------------------------------------------

func TestPauseInstance_Success(t *testing.T) {
	vmd := &mockVMD{}
	h := newTestHandlers(vmd)
	r := setupTestRouter(h, uuid.New().String())

	id := uuid.New().String()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/instances/"+id+"/pause", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := parseJSON(t, w.Body)
	if body["status"] != "PAUSED" {
		t.Errorf("expected status=PAUSED, got %v", body["status"])
	}
}

func TestPauseInstance_InvalidUUID(t *testing.T) {
	h := newTestHandlers(&mockVMD{})
	r := setupTestRouter(h, uuid.New().String())

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/instances/bad/pause", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestPauseInstance_VMDFailure(t *testing.T) {
	vmd := &mockVMD{
		pauseInstanceFn: func(ctx context.Context, instanceID, snapshotDir string) (string, string, error) {
			return "", "", errors.New("pause failed")
		},
	}
	h := newTestHandlers(vmd)
	r := setupTestRouter(h, uuid.New().String())

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/instances/"+uuid.New().String()+"/pause", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// ResumeInstance
// ---------------------------------------------------------------------------

func TestResumeInstance_Success(t *testing.T) {
	vmd := &mockVMD{
		resumeInstanceFn: func(ctx context.Context, instanceID, snapshotPath, memPath string) (string, error) {
			return "10.0.0.42", nil
		},
	}
	h := newTestHandlers(vmd)
	r := setupTestRouter(h, uuid.New().String())

	id := uuid.New().String()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/instances/"+id+"/resume", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := parseJSON(t, w.Body)
	if body["status"] != "RUNNING" {
		t.Errorf("expected status=RUNNING, got %v", body["status"])
	}
	if body["ip_address"] != "10.0.0.42" {
		t.Errorf("expected ip_address=10.0.0.42, got %v", body["ip_address"])
	}
}

func TestResumeInstance_VMDFailure(t *testing.T) {
	vmd := &mockVMD{
		resumeInstanceFn: func(ctx context.Context, instanceID, snapshotPath, memPath string) (string, error) {
			return "", errors.New("resume failed")
		},
	}
	h := newTestHandlers(vmd)
	r := setupTestRouter(h, uuid.New().String())

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/instances/"+uuid.New().String()+"/resume", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// ExecCommand
// ---------------------------------------------------------------------------

func TestExecCommand_Success(t *testing.T) {
	vmd := &mockVMD{
		execCommandFn: func(ctx context.Context, instanceID, command string, args []string, env map[string]string, workingDir string, timeoutS uint32) (string, string, int32, error) {
			return "hello world\n", "", 0, nil
		},
	}
	h := newTestHandlers(vmd)
	r := setupTestRouter(h, uuid.New().String())

	id := uuid.New().String()
	w := httptest.NewRecorder()
	body := jsonBody(map[string]interface{}{"command": "echo", "args": []string{"hello", "world"}})
	req, _ := http.NewRequest("POST", "/instances/"+id+"/exec", body)
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	resp := parseJSON(t, w.Body)
	if resp["stdout"] != "hello world\n" {
		t.Errorf("unexpected stdout: %v", resp["stdout"])
	}
	if resp["exit_code"] != float64(0) {
		t.Errorf("expected exit_code=0, got %v", resp["exit_code"])
	}
}

func TestExecCommand_BadRequest_MissingCommand(t *testing.T) {
	h := newTestHandlers(&mockVMD{})
	r := setupTestRouter(h, uuid.New().String())

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/instances/"+uuid.New().String()+"/exec",
		jsonBody(map[string]interface{}{}))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestExecCommand_DefaultTimeout(t *testing.T) {
	var capturedTimeout uint32
	vmd := &mockVMD{
		execCommandFn: func(ctx context.Context, instanceID, command string, args []string, env map[string]string, workingDir string, timeoutS uint32) (string, string, int32, error) {
			capturedTimeout = timeoutS
			return "", "", 0, nil
		},
	}
	h := newTestHandlers(vmd)
	r := setupTestRouter(h, uuid.New().String())

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/instances/"+uuid.New().String()+"/exec",
		jsonBody(map[string]interface{}{"command": "ls"}))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if capturedTimeout != 30 {
		t.Errorf("expected default timeout=30, got %d", capturedTimeout)
	}
}

func TestExecCommand_VMDFailure(t *testing.T) {
	vmd := &mockVMD{
		execCommandFn: func(ctx context.Context, instanceID, command string, args []string, env map[string]string, workingDir string, timeoutS uint32) (string, string, int32, error) {
			return "", "", 0, errors.New("exec failed")
		},
	}
	h := newTestHandlers(vmd)
	r := setupTestRouter(h, uuid.New().String())

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/instances/"+uuid.New().String()+"/exec",
		jsonBody(map[string]interface{}{"command": "fail"}))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

func TestExecCommand_NonZeroExit(t *testing.T) {
	vmd := &mockVMD{
		execCommandFn: func(ctx context.Context, instanceID, command string, args []string, env map[string]string, workingDir string, timeoutS uint32) (string, string, int32, error) {
			return "", "not found\n", 127, nil
		},
	}
	h := newTestHandlers(vmd)
	r := setupTestRouter(h, uuid.New().String())

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/instances/"+uuid.New().String()+"/exec",
		jsonBody(map[string]interface{}{"command": "missing"}))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	resp := parseJSON(t, w.Body)
	if resp["exit_code"] != float64(127) {
		t.Errorf("expected exit_code=127, got %v", resp["exit_code"])
	}
	if resp["stderr"] != "not found\n" {
		t.Errorf("unexpected stderr: %v", resp["stderr"])
	}
}

// ---------------------------------------------------------------------------
// UploadFile
// ---------------------------------------------------------------------------

func TestUploadFile_Success(t *testing.T) {
	vmd := &mockVMD{
		uploadFileFn: func(ctx context.Context, instanceID, path string, content io.Reader) (int64, error) {
			data, _ := io.ReadAll(content)
			return int64(len(data)), nil
		},
	}
	h := newTestHandlers(vmd)
	r := setupTestRouter(h, uuid.New().String())

	id := uuid.New().String()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "/instances/"+id+"/files/home/user/test.txt",
		strings.NewReader("file content here"))
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	resp := parseJSON(t, w.Body)
	if resp["path"] != "/home/user/test.txt" {
		t.Errorf("unexpected path: %v", resp["path"])
	}
}

func TestUploadFile_PathTraversal(t *testing.T) {
	h := newTestHandlers(&mockVMD{})
	r := setupTestRouter(h, uuid.New().String())

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "/instances/"+uuid.New().String()+"/files/../etc/passwd",
		strings.NewReader("bad"))
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUploadFile_VMDFailure(t *testing.T) {
	vmd := &mockVMD{
		uploadFileFn: func(ctx context.Context, instanceID, path string, content io.Reader) (int64, error) {
			return 0, errors.New("upload failed")
		},
	}
	h := newTestHandlers(vmd)
	r := setupTestRouter(h, uuid.New().String())

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "/instances/"+uuid.New().String()+"/files/test.txt",
		strings.NewReader("data"))
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// DownloadFile
// ---------------------------------------------------------------------------

func TestDownloadFile_Success(t *testing.T) {
	vmd := &mockVMD{
		downloadFileFn: func(ctx context.Context, instanceID, path string) (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader("downloaded-content")), nil
		},
	}
	h := newTestHandlers(vmd)
	r := setupTestRouter(h, uuid.New().String())

	id := uuid.New().String()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/instances/"+id+"/files/data.txt", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w.Body.String() != "downloaded-content" {
		t.Errorf("unexpected body: %s", w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("expected Content-Type=application/octet-stream, got %s", ct)
	}
}

func TestDownloadFile_NotFound(t *testing.T) {
	vmd := &mockVMD{
		downloadFileFn: func(ctx context.Context, instanceID, path string) (io.ReadCloser, error) {
			return nil, errors.New("404 not found")
		},
	}
	h := newTestHandlers(vmd)
	r := setupTestRouter(h, uuid.New().String())

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/instances/"+uuid.New().String()+"/files/missing.txt", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestDownloadFile_PathTraversal(t *testing.T) {
	h := newTestHandlers(&mockVMD{})
	r := setupTestRouter(h, uuid.New().String())

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/instances/"+uuid.New().String()+"/files/../../../etc/shadow", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// ExecCommandStream
// ---------------------------------------------------------------------------

func TestExecCommandStream_Success(t *testing.T) {
	vmd := &mockVMD{
		execCommandStreamFn: func(ctx context.Context, instanceID, command string, args []string, env map[string]string, workingDir string, timeoutS uint32, onChunk func([]byte, []byte, int32, bool)) error {
			onChunk([]byte("line1\n"), nil, 0, false)
			onChunk(nil, []byte("warn\n"), 0, false)
			onChunk(nil, nil, 0, true)
			return nil
		},
	}
	h := newTestHandlers(vmd)
	r := setupTestRouter(h, uuid.New().String())

	id := uuid.New().String()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/instances/"+id+"/exec/stream",
		jsonBody(map[string]interface{}{"command": "echo"}))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("expected Content-Type=text/event-stream, got %s", ct)
	}
	body := w.Body.String()
	if !strings.Contains(body, "data: ") {
		t.Errorf("expected SSE data lines, got: %s", body)
	}
	if !strings.Contains(body, "line1") {
		t.Errorf("expected stdout chunk in SSE stream")
	}
}

func TestExecCommandStream_BadRequest(t *testing.T) {
	h := newTestHandlers(&mockVMD{})
	r := setupTestRouter(h, uuid.New().String())

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/instances/"+uuid.New().String()+"/exec/stream",
		jsonBody(map[string]interface{}{}))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// GetInstance / ListInstances (TODO stubs)
// ---------------------------------------------------------------------------

func TestGetInstance_NotImplemented(t *testing.T) {
	h := newTestHandlers(&mockVMD{})
	r := setupTestRouter(h, uuid.New().String())

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/instances/"+uuid.New().String(), nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d", w.Code)
	}
}

func TestListInstances_NotImplemented(t *testing.T) {
	h := newTestHandlers(&mockVMD{})
	r := setupTestRouter(h, uuid.New().String())

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/instances", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// DeleteSandbox (requires DB)
// ---------------------------------------------------------------------------

func TestDeleteSandbox_InvalidUUID(t *testing.T) {
	h := newTestHandlers(&mockVMD{})
	r := setupTestRouter(h, uuid.New().String())

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("DELETE", "/sandboxes/not-a-uuid", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestDeleteSandbox_MissingTeamID(t *testing.T) {
	h := newTestHandlers(&mockVMD{})
	// No team_id set
	r := setupTestRouter(h, "")

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("DELETE", "/sandboxes/"+uuid.New().String(), nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// cleanFilePath
// ---------------------------------------------------------------------------

func TestCleanFilePath(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"simple file", "/test.txt", "/test.txt", false},
		{"nested path", "/home/user/data.csv", "/home/user/data.csv", false},
		{"strips leading slash", "test.txt", "/test.txt", false},
		{"empty path", "/", "", true},
		{"traversal blocked", "/../etc/passwd", "", true},
		{"double dot in middle", "/foo/../bar", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := cleanFilePath(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("cleanFilePath(%q): err=%v, wantErr=%v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("cleanFilePath(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// parseInstanceID / parseSandboxID
// ---------------------------------------------------------------------------

func TestParseInstanceID_Valid(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "instance_id", Value: uuid.New().String()}}

	_, err := parseInstanceID(c)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestParseInstanceID_Invalid(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "instance_id", Value: "bad"}}

	_, err := parseInstanceID(c)
	if err == nil {
		t.Fatal("expected error for invalid UUID")
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestParseSandboxID_Valid(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "sandbox_id", Value: uuid.New().String()}}

	_, err := parseSandboxID(c)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestParseSandboxID_Invalid(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "sandbox_id", Value: "bad"}}

	_, err := parseSandboxID(c)
	if err == nil {
		t.Fatal("expected error for invalid UUID")
	}
}

// ---------------------------------------------------------------------------
// teamIDFromContext
// ---------------------------------------------------------------------------

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

	_, err := teamIDFromContext(c)
	if err == nil {
		t.Fatal("expected error for missing team_id")
	}
}

func TestTeamIDFromContext_InvalidUUID(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set("team_id", "not-a-uuid")

	_, err := teamIDFromContext(c)
	if err == nil {
		t.Fatal("expected error for invalid team_id UUID")
	}
}
