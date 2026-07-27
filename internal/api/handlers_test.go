package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/preview"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

type stubVMD struct {
	destroyFn        func(ctx context.Context, id string, force bool) error
	pauseFn          func(ctx context.Context, id, snapshotDir string) (string, string, error)
	resumeFn         func(ctx context.Context, id, snapshotPath, memPath string) (string, error)
	restoreFn        func(ctx context.Context, id, snapshotPath, memPath string) (string, error)
	restorePolicyFn  func(access string, ports map[int32]vmdclient.PortPolicy, revision int64)
	deleteSnapshotFn func(ctx context.Context, id, snapshotPath, memPath string) error
	deleteSnapsFn    func(ctx context.Context, id string) error
	updateNetworkFn  func(ctx context.Context, id string, allowedCIDRs, deniedCIDRs, allowedDomains []string) error
	updatePreviewFn  func(ctx context.Context, id, access string, ports map[int32]vmdclient.PortPolicy, revision int64) error
	injectEnvFn      func(ctx context.Context, id string, envVars map[string]string, secretsJWT string) error
	listDirFn        func(ctx context.Context, id, path string) ([]vmdclient.DirEntry, error)
}

type stubScheduler struct {
	hostID   string
	err      error
	required []string
}

func (s *stubScheduler) SelectHost(_ context.Context, required []string) (string, error) {
	s.required = append([]string(nil), required...)
	return s.hostID, s.err
}

func (s *stubScheduler) Invalidate() {}

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
func (s *stubVMD) ResumeInstance(ctx context.Context, id, snapshotPath, memPath string) (string, uint32, uint32, error) {
	if s.resumeFn != nil {
		ip, err := s.resumeFn(ctx, id, snapshotPath, memPath)
		return ip, 1, 1024, err
	}
	return "10.0.0.1", 1, 1024, nil
}
func (s *stubVMD) RestoreSnapshot(ctx context.Context, id, snapshotPath, memPath, _, _, _, _, previewAccess string, previewPorts map[int32]vmdclient.PortPolicy, previewPolicyRevision int64, _ map[string]string) (string, uint32, uint32, error) {
	if s.restorePolicyFn != nil {
		s.restorePolicyFn(previewAccess, previewPorts, previewPolicyRevision)
	}
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
func (s *stubVMD) DeleteSandboxSnapshots(ctx context.Context, id string) error {
	if s.deleteSnapsFn != nil {
		return s.deleteSnapsFn(ctx, id)
	}
	return nil
}
func (s *stubVMD) DeleteTemplateArtifacts(_ context.Context, _ string) error { return nil }
func (s *stubVMD) DeleteBuildArtifacts(_ context.Context, _, _ string) error { return nil }
func (s *stubVMD) ListBuildArtifacts(_ context.Context) ([]vmdclient.BuildArtifactEntry, error) {
	return nil, nil
}
func (s *stubVMD) ListDir(ctx context.Context, id, path string) ([]vmdclient.DirEntry, error) {
	if s.listDirFn != nil {
		return s.listDirFn(ctx, id, path)
	}
	return nil, nil
}
func (s *stubVMD) UpdateSandboxNetwork(ctx context.Context, id string, allowed, denied, domains []string) error {
	if s.updateNetworkFn != nil {
		return s.updateNetworkFn(ctx, id, allowed, denied, domains)
	}
	return nil
}
func (s *stubVMD) UpdateSandboxPreviewPolicy(ctx context.Context, id, access string, ports map[int32]vmdclient.PortPolicy, revision int64) error {
	if s.updatePreviewFn != nil {
		return s.updatePreviewFn(ctx, id, access, ports, revision)
	}
	return nil
}
func (s *stubVMD) InvalidateSecret(_ context.Context, _ string) error       { return nil }
func (s *stubVMD) RevokeSandbox(_ context.Context, _ string) error          { return nil }
func (s *stubVMD) InvalidateSandboxRules(_ context.Context, _ string) error { return nil }
func (s *stubVMD) InjectSandboxEnv(ctx context.Context, id string, envVars map[string]string, secretsJWT string) error {
	if s.injectEnvFn != nil {
		return s.injectEnvFn(ctx, id, envVars, secretsJWT)
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

type mockRow struct {
	scanFn func(dest ...any) error
}

func (r *mockRow) Scan(dest ...any) error { return r.scanFn(dest...) }

type mockDBTX struct {
	queryRowFn func(ctx context.Context, sql string, args ...any) pgx.Row
	execFn     func(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	// queryFn is optional; nil falls back to an empty rows iterator.
	queryFn func(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

func (m *mockDBTX) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return m.queryRowFn(ctx, sql, args...)
}

func (m *mockDBTX) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return m.execFn(ctx, sql, args...)
}

func (m *mockDBTX) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	if m.queryFn != nil {
		return m.queryFn(ctx, sql, args...)
	}
	return emptyRows{}, nil
}

// emptyRows is a no-row pgx.Rows implementation.
type emptyRows struct{}

func (emptyRows) Close()                                       {}
func (emptyRows) Err() error                                   { return nil }
func (emptyRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (emptyRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (emptyRows) Next() bool                                   { return false }
func (emptyRows) Scan(...any) error                            { return fmt.Errorf("emptyRows.Scan") }
func (emptyRows) Values() ([]any, error)                       { return nil, nil }
func (emptyRows) RawValues() [][]byte                          { return nil }
func (emptyRows) Conn() *pgx.Conn                              { return nil }

// sandboxRow returns a mockRow that populates a Sandbox from GetSandbox's Scan
// call, with destination pointers matching the sandbox column order in
// sqlc-generated queries (see db.Sandbox field order in internal/db/models.go).
func sandboxRow(s db.Sandbox) *mockRow {
	return &mockRow{scanFn: func(dest ...any) error {
		// Side-table policy reads intentionally share sandbox ownership scope.
		// Many lifecycle mocks route any `FROM sandbox` query here; model an
		// older control-plane row (no policy relation) for those reads.
		if len(dest) == 3 {
			access, accessOK := dest[0].(*string)
			wireAccess, wireAccessOK := dest[1].(*string)
			revision, revisionOK := dest[2].(*int64)
			if accessOK && wireAccessOK && revisionOK {
				*access = "legacy_public"
				*wireAccess = "legacy_public"
				*revision = 0
				return nil
			}
		}
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
		*dest[16].(*pgtype.UUID) = s.TemplateID
		*dest[17].(**string) = s.SnapshotPath
		*dest[18].(**string) = s.MemPath
		*dest[19].(**string) = s.BasePath
		*dest[20].(**string) = s.DeltaPath
		*dest[21].(*int32) = s.DiskMib
		*dest[22].(**int32) = s.AutoDeleteSeconds
		*dest[23].(*pgtype.Timestamptz) = s.AutoDeleteAt
		return nil
	}}
}

func hostRow(h db.Host) *mockRow {
	return &mockRow{scanFn: func(dest ...any) error {
		*dest[0].(*string) = h.ID
		*dest[1].(*string) = h.VmdAddr
		*dest[2].(*string) = h.ProxyAddr
		*dest[3].(*string) = h.Region
		*dest[4].(*string) = h.Status
		*dest[5].(*int32) = h.CapacityMemoryMib
		*dest[6].(*int32) = h.CapacityVcpus
		*dest[7].(*pgtype.Timestamptz) = h.LastHeartbeatAt
		*dest[8].(*time.Time) = h.CreatedAt
		*dest[9].(*time.Time) = h.UpdatedAt
		return nil
	}}
}

func previewCapableHostRow() *mockRow {
	return &mockRow{scanFn: func(dest ...any) error {
		*dest[0].(*bool) = true
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

// idRow returns a mockRow that scans a single uuid — for queries like
// DestroySandbox that RETURN the claimed id.
func idRow(id uuid.UUID) *mockRow {
	return &mockRow{scanFn: func(dest ...any) error {
		*dest[0].(*uuid.UUID) = id
		return nil
	}}
}

func errorRow(err error) *mockRow {
	return &mockRow{scanFn: func(...any) error { return err }}
}

// uuidRow returns a mockRow for a query that RETURNs a single uuid (e.g.
// FinalizePause's snapshot_id).
func uuidRow(id uuid.UUID) *mockRow {
	return &mockRow{scanFn: func(dest ...any) error {
		*dest[0].(*uuid.UUID) = id
		return nil
	}}
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
	r.GET("/sandboxes/:sandbox_id/files", h.ListSandboxFiles)
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
			switch {
			case strings.Contains(sql, "FROM destroyed"):
				return idRow(sandboxID) // DestroySandbox claim
			case strings.Contains(sql, "FROM sandbox"):
				return sandboxRow(sb)
			default:
				return activityRow()
			}
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

// TestDeleteSandbox_RevocationAtomicWithClaim verifies the revocation is written
// in the same statement that commits the soft-delete, leaving no crash window in
// which a deleted sandbox lacks a revocation row.
func TestDeleteSandbox_RevocationAtomicWithClaim(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Name: "sb", Status: db.SandboxStatusActive, HostID: "host-1"}

	var claimHasRevocation, claimHasExpiry, separateRevokeExec bool
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "FROM destroyed"):
				if strings.Contains(sql, "sandbox_revocation") {
					claimHasRevocation = true
				}
				for _, a := range args {
					if ts, ok := a.(time.Time); ok && !ts.IsZero() {
						claimHasExpiry = true
					}
				}
				return idRow(sandboxID)
			case strings.Contains(sql, "FROM sandbox"):
				return sandboxRow(sb)
			default:
				return activityRow()
			}
		},
		execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			if strings.Contains(sql, "INSERT INTO sandbox_revocation") {
				separateRevokeExec = true
			}
			return pgconn.NewCommandTag("OK"), nil
		},
	}

	h := &Handlers{VMD: &stubVMD{destroyFn: func(context.Context, string, bool) error { return nil }}, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, deleteRequest(sandboxID.String()))

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusNoContent, w.Body.String())
	}
	if !claimHasRevocation {
		t.Error("DestroySandbox claim does not write the revocation row")
	}
	if !claimHasExpiry {
		t.Error("DestroySandbox not called with a revocation expiry")
	}
	if separateRevokeExec {
		t.Error("revocation must be atomic with the claim, not a separate insert")
	}
}

// A failed sandbox can still hold a VM, rundir, and snapshot dir, so deleting it
// must attempt VM teardown and the path-based snapshot sweep.
func TestDeleteSandbox_Failed_StillCleansUp(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Name: "test-sb", Status: db.SandboxStatusFailed}

	var destroyCalled, snapDirCleaned bool
	vmd := &stubVMD{
		destroyFn:     func(context.Context, string, bool) error { destroyCalled = true; return nil },
		deleteSnapsFn: func(context.Context, string) error { snapDirCleaned = true; return nil },
	}
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "FROM destroyed"):
				return idRow(sandboxID)
			case strings.Contains(sql, "FROM sandbox"):
				return sandboxRow(sb)
			default:
				return activityRow()
			}
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("OK"), nil
		},
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, deleteRequest(sandboxID.String()))

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusNoContent, w.Body.String())
	}
	if !destroyCalled {
		t.Error("teardown must be attempted for a failed sandbox (may still hold resources)")
	}
	if !snapDirCleaned {
		t.Error("DeleteSandboxSnapshots must run on delete to reclaim the snapshot dir")
	}
}

// A failed sandbox must stay deletable even when VM teardown fails (best-effort);
// the vm reconciler backstops the miss.
func TestDeleteSandbox_FailedSandbox_DestroyError_StillDeletes(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Name: "test-sb", Status: db.SandboxStatusFailed}

	vmd := &stubVMD{destroyFn: func(context.Context, string, bool) error {
		return fmt.Errorf("vmd unreachable")
	}}
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "FROM destroyed"):
				return idRow(sandboxID)
			case strings.Contains(sql, "FROM sandbox"):
				return sandboxRow(sb)
			default:
				return activityRow()
			}
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("OK"), nil
		},
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, deleteRequest(sandboxID.String()))

	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d (teardown is best-effort); body: %s", w.Code, http.StatusNoContent, w.Body.String())
	}
}

// If the host vmd predates DeleteSandboxSnapshots (codes.Unimplemented), snapshot
// cleanup must fall back to the per-file DeleteSnapshot path during the upgrade window.
func TestDeleteSandbox_SnapshotCleanup_FallsBackOnUnimplemented(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	snapID := uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Name: "sb", Status: db.SandboxStatusActive}

	var perFileCalled bool
	vmd := &stubVMD{
		destroyFn:        func(context.Context, string, bool) error { return nil },
		deleteSnapsFn:    func(context.Context, string) error { return status.Error(codes.Unimplemented, "old vmd") },
		deleteSnapshotFn: func(context.Context, string, string, string) error { perFileCalled = true; return nil },
	}
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "FROM destroyed"):
				return idRow(sandboxID)
			case strings.Contains(sql, "FROM sandbox"):
				return sandboxRow(sb)
			default:
				return activityRow()
			}
		},
		queryFn: func(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
			if strings.Contains(sql, "FROM snapshot") {
				return &scanRows{rows: []func(...any) error{func(dest ...any) error {
					*dest[0].(*uuid.UUID) = snapID
					*dest[1].(*uuid.UUID) = sandboxID
					*dest[2].(*uuid.UUID) = teamID
					*dest[3].(*string) = "/snapshots/x/vmstate.snap"
					*dest[4].(*int64) = 0
					*dest[5].(*string) = "pause"
					*dest[6].(*time.Time) = time.Unix(0, 0)
					mp := "/snapshots/x/mem.snap"
					*dest[7].(**string) = &mp
					return nil
				}}}, nil
			}
			return &scanRows{}, nil
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("OK"), nil
		},
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, deleteRequest(sandboxID.String()))

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body: %s", w.Code, w.Body.String())
	}
	if !perFileCalled {
		t.Error("on Unimplemented, cleanup must fall back to per-file DeleteSnapshot")
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

// Teardown is best-effort AFTER the DB claim commits the delete, so a vmd
// failure no longer fails the request — the reconciler reclaims the VM.
func TestDeleteSandbox_TeardownError_StillCommits(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Name: "sb", Status: db.SandboxStatusActive}

	vmd := &stubVMD{destroyFn: func(context.Context, string, bool) error {
		return fmt.Errorf("vmd unreachable")
	}}
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "FROM destroyed"):
				return idRow(sandboxID)
			case strings.Contains(sql, "FROM sandbox"):
				return sandboxRow(sb)
			default:
				return activityRow()
			}
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) { return pgconn.NewCommandTag(""), nil },
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, deleteRequest(sandboxID.String()))

	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d (teardown is best-effort after the claim); body: %s", w.Code, http.StatusNoContent, w.Body.String())
	}
}

func TestDeleteSandbox_DBDestroyError(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Name: "sb", Status: db.SandboxStatusActive}

	vmd := &stubVMD{destroyFn: func(context.Context, string, bool) error { return nil }}
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if strings.Contains(sql, "FROM destroyed") {
				return errorRow(fmt.Errorf("db write failed")) // DestroySandbox claim errors
			}
			return sandboxRow(sb)
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) { return pgconn.NewCommandTag(""), nil },
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

	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "FROM destroyed"):
				return idRow(sandboxID) // DestroySandbox claim
			case strings.Contains(sql, "FROM sandbox"):
				return sandboxRow(sb) // GetSandbox
			default:
				return errorRow(fmt.Errorf("activity table locked")) // CreateActivity
			}
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("UPDATE 1"), nil
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

// A sandbox mid-transition (resuming/pausing/starting) can't be claimed: the
// guarded soft-delete matches 0 rows, so delete defers with 409 rather than
// tearing down a VM a concurrent resume is bringing up.
func TestDeleteSandbox_Resuming_Returns409(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Name: "sb", Status: db.SandboxStatusResuming}

	var destroyCalled bool
	vmd := &stubVMD{destroyFn: func(context.Context, string, bool) error { destroyCalled = true; return nil }}
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if strings.Contains(sql, "FROM destroyed") {
				return notFoundRow() // claim rejected: not a quiescent state
			}
			return sandboxRow(sb) // GetSandbox (top + re-read) → resuming
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) { return pgconn.NewCommandTag(""), nil },
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, deleteRequest(sandboxID.String()))

	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409 (delete must defer while resuming); body: %s", w.Code, w.Body.String())
	}
	if destroyCalled {
		t.Error("must NOT tear down a sandbox it couldn't claim")
	}
}

// If the row is soft-deleted concurrently between the existence read and the
// claim, the delete is idempotent (the goal is already met) → 204.
func TestDeleteSandbox_ConcurrentlyDeleted_Idempotent(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Name: "sb", Status: db.SandboxStatusActive}

	vmd := &stubVMD{destroyFn: func(context.Context, string, bool) error { return nil }}
	getCalls := 0
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if strings.Contains(sql, "FROM destroyed") {
				return notFoundRow() // claim lost: already deleted concurrently
			}
			getCalls++
			if getCalls == 1 {
				return sandboxRow(sb) // first read: alive
			}
			return notFoundRow() // re-read: gone
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) { return pgconn.NewCommandTag(""), nil },
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, deleteRequest(sandboxID.String()))

	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204 (already-deleted is idempotent); body: %s", w.Code, w.Body.String())
	}
}

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

func TestResumeSandbox_LegacyPolicyToleratesOldVMD(t *testing.T) {
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

	var resumeCalled, updateCalled bool
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
		updatePreviewFn: func(_ context.Context, _ string, access string, _ map[int32]vmdclient.PortPolicy, revision int64) error {
			updateCalled = true
			if access != preview.AccessLegacyPublic || revision != 0 {
				t.Errorf("legacy reconciliation = (%q, %d), want (legacy_public, 0)", access, revision)
			}
			return status.Error(codes.Unimplemented, "old vmd")
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
	if !updateCalled {
		t.Error("resume did not attempt final policy reconciliation")
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

func TestResumeSandbox_NotFoundRestoreReceivesPolicyAndReconcilesLatest(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	snapshotID := uuid.New()
	sb := pausedSandboxWithSnapshot(sandboxID, teamID, snapshotID)
	sb.HostID = "host-a"
	snap := db.Snapshot{
		ID: snapshotID, SandboxID: sandboxID, TeamID: teamID,
		Path: "/snapshots/test/vmstate.snap", Trigger: "pause",
	}

	var policyReads int
	var restored, reconciled previewPolicySnapshot
	vmd := &stubVMD{
		resumeFn: func(context.Context, string, string, string) (string, error) {
			return "", status.Error(codes.NotFound, "vm absent after vmd restart")
		},
		restorePolicyFn: func(access string, ports map[int32]vmdclient.PortPolicy, revision int64) {
			restored = previewPolicySnapshot{Access: access, Ports: ports, Revision: revision}
		},
		updatePreviewFn: func(_ context.Context, _ string, access string, ports map[int32]vmdclient.PortPolicy, revision int64) error {
			reconciled = previewPolicySnapshot{Access: access, Ports: ports, Revision: revision}
			return nil
		},
	}

	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "-- name: GetSandbox :one"):
				return sandboxRow(sb)
			case strings.Contains(sql, "-- name: GetSandboxPreviewPolicy :one"):
				policyReads++
				if policyReads == 1 {
					return previewPolicyRow(preview.AccessPublic, 7)
				}
				return previewPolicyRow(preview.AccessPublic, 8)
			case strings.Contains(sql, "-- name: HostHasCapability :one"):
				return scalarBoolRow(true)
			case strings.Contains(sql, "-- name: BeginResume :one"):
				return sandboxRow(sb)
			case strings.Contains(sql, "-- name: GetSnapshot :one"):
				return snapshotRow(snap)
			default:
				return activityRow()
			}
		},
		queryFn: func(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
			switch {
			case strings.Contains(sql, "-- name: ListPublishedPorts :many"):
				if policyReads == 1 {
					return previewPortRows(3000), nil
				}
				return previewPortRows(8080), nil
			case strings.Contains(sql, "-- name: ListSandboxSecretBindingMeta :many"):
				return emptyRows{}, nil
			default:
				return nil, fmt.Errorf("unexpected Query: %s", sql)
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
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	h.WaitAsyncBookkeeping()

	if restored.Access != preview.AccessPublic || restored.Revision != 7 {
		t.Fatalf("restore policy = (%q, %d), want (public, 7)", restored.Access, restored.Revision)
	}
	if _, ok := restored.Ports[3000]; !ok || len(restored.Ports) != 1 {
		t.Fatalf("restore ports = %#v, want {3000}", restored.Ports)
	}
	if reconciled.Access != preview.AccessPublic || reconciled.Revision != 8 {
		t.Fatalf("reconciled policy = (%q, %d), want (public, 8)", reconciled.Access, reconciled.Revision)
	}
	if _, ok := reconciled.Ports[8080]; !ok || len(reconciled.Ports) != 1 {
		t.Fatalf("reconciled ports = %#v, want {8080}", reconciled.Ports)
	}
}

func TestResumeSandbox_ReappliesSecretBindings(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	snapshotID := uuid.New()
	secretID := uuid.New()
	sb := pausedSandboxWithSnapshot(sandboxID, teamID, snapshotID)
	snap := db.Snapshot{ID: snapshotID, SandboxID: sandboxID, TeamID: teamID, Path: "/snapshots/test/vmstate.snap", Trigger: "pause"}

	var injectedJWT string
	var injectCalled bool
	vmd := &stubVMD{
		resumeFn: func(_ context.Context, _, _, _ string) (string, error) { return "10.0.0.5", nil },
		injectEnvFn: func(_ context.Context, _ string, _ map[string]string, jwt string) error {
			injectCalled, injectedJWT = true, jwt
			return nil
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
		queryFn: func(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
			if strings.Contains(sql, "ListSandboxSecretBindingMeta") {
				return &scanRows{rows: []func(...any) error{bindingMetaRow(secretID, "ANTHROPIC_API_KEY", "bearer", "ssrv_proxy_x")}}, nil
			}
			return &scanRows{}, nil
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock), Signer: newTestSigner(t, "v1")}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, resumeRequest(sandboxID.String()))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if !injectCalled {
		t.Fatal("resume must re-apply the binding set when the sandbox has bindings")
	}
	if injectedJWT == "" {
		t.Error("re-applied JWT should be signed for a non-empty binding set")
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
// A resume that gets the VM up but then fails to reapply egress rules must
// re-pause the VM (preserving the overlay), never destroy it.
func TestResumeSandbox_NetworkReapplyFailure_PausesNotDestroys(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	snapshotID := uuid.New()
	sb := pausedSandboxWithSnapshot(sandboxID, teamID, snapshotID)
	sb.NetworkConfig = []byte(`{"egress":{"allowed_cidrs":["10.0.0.0/8"]}}`)
	snap := db.Snapshot{
		ID: snapshotID, SandboxID: sandboxID, TeamID: teamID,
		Path: "/snapshots/test/vmstate.snap", Trigger: "pause",
	}

	var destroyCalled, pauseCalled, updateNetworkCalled, finalizeCalled, activateCalled int32
	vmd := &stubVMD{
		resumeFn: func(context.Context, string, string, string) (string, error) {
			return "10.0.0.5", nil
		},
		destroyFn: func(context.Context, string, bool) error {
			atomic.AddInt32(&destroyCalled, 1)
			return nil
		},
		pauseFn: func(context.Context, string, string) (string, string, error) {
			atomic.AddInt32(&pauseCalled, 1)
			return "/snapshots/test/vmstate.snap", "/snapshots/test/mem.snap", nil
		},
		updateNetworkFn: func(context.Context, string, []string, []string, []string) error {
			atomic.AddInt32(&updateNetworkCalled, 1)
			return fmt.Errorf("nftables push failed")
		},
	}

	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "INSERT INTO snapshot"): // FinalizePause
				atomic.AddInt32(&finalizeCalled, 1)
				return uuidRow(snapshotID)
			case strings.Contains(sql, "'resuming'"):
				return sandboxRow(sb)
			case strings.Contains(sql, "FROM snapshot"):
				return snapshotRow(snap)
			case strings.Contains(sql, "FROM sandbox"):
				return sandboxRow(sb)
			}
			return activityRow()
		},
		execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			if strings.Contains(sql, "'active'") {
				atomic.AddInt32(&activateCalled, 1)
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
	// Must never destroy a resumed VM — that deletes the overlay.
	if got := atomic.LoadInt32(&destroyCalled); got != 0 {
		t.Errorf("DestroyInstance calls = %d, want 0 (must not destroy a resumed VM)", got)
	}
	if got := atomic.LoadInt32(&pauseCalled); got != 1 {
		t.Errorf("PauseInstance calls = %d, want 1 (re-pause preserves overlay)", got)
	}
	if got := atomic.LoadInt32(&finalizeCalled); got != 1 {
		t.Errorf("FinalizePause calls = %d, want 1 (revert to paused)", got)
	}
	if got := atomic.LoadInt32(&activateCalled); got != 0 {
		t.Errorf("ActivateSandbox calls = %d, want 0 (network failed before commit)", got)
	}
}

// ActivateSandbox is fire-and-forget: the client gets a success response
// once the VM is up, and a DB activate failure re-pauses in the background
// (preserving the overlay), never destroys — the path that previously
// bricked a sandbox.
func TestResumeSandbox_ActivateFailure_PausesNotDestroys(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	snapshotID := uuid.New()
	sb := pausedSandboxWithSnapshot(sandboxID, teamID, snapshotID)
	snap := db.Snapshot{
		ID: snapshotID, SandboxID: sandboxID, TeamID: teamID,
		Path: "/snapshots/test/vmstate.snap", Trigger: "pause",
	}

	var destroyCalled, pauseCalled, finalizeCalled int32
	vmd := &stubVMD{
		resumeFn: func(context.Context, string, string, string) (string, error) {
			return "10.0.0.5", nil
		},
		destroyFn: func(context.Context, string, bool) error {
			atomic.AddInt32(&destroyCalled, 1)
			return nil
		},
		pauseFn: func(context.Context, string, string) (string, string, error) {
			atomic.AddInt32(&pauseCalled, 1)
			return "/snapshots/test/vmstate.snap", "/snapshots/test/mem.snap", nil
		},
	}

	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "INSERT INTO snapshot"): // FinalizePause
				atomic.AddInt32(&finalizeCalled, 1)
				return uuidRow(snapshotID)
			case strings.Contains(sql, "'resuming'"):
				return sandboxRow(sb)
			case strings.Contains(sql, "FROM snapshot"):
				return snapshotRow(snap)
			case strings.Contains(sql, "FROM sandbox"):
				return sandboxRow(sb)
			}
			return activityRow()
		},
		execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			if strings.Contains(sql, "'active'") {
				return pgconn.CommandTag{}, fmt.Errorf("db connection lost")
			}
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, resumeRequest(sandboxID.String()))

	// The activate write is fire-and-forget — the VM is up, so the client
	// sees success; the failure is compensated in the background.
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
	h.WaitAsyncBookkeeping()
	if got := atomic.LoadInt32(&destroyCalled); got != 0 {
		t.Errorf("DestroyInstance calls = %d, want 0 (must not destroy a resumed VM)", got)
	}
	if got := atomic.LoadInt32(&pauseCalled); got != 1 {
		t.Errorf("PauseInstance calls = %d, want 1 (re-pause preserves overlay)", got)
	}
	if got := atomic.LoadInt32(&finalizeCalled); got != 1 {
		t.Errorf("FinalizePause calls = %d, want 1 (revert to paused)", got)
	}
}

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
	// starting/resuming rows are polled for the settle window before the
	// 409; shrink it so the persistent-transitional cases stay fast.
	prev := activateSettleWindow
	activateSettleWindow = 100 * time.Millisecond
	defer func() { activateSettleWindow = prev }()

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

// The owner's follow-up right after create/resume may read the row before the
// fire-and-forget activate write lands. The settle window must absorb that:
// a 'starting' row that flips to 'active' mid-poll returns 200, not 409.
func TestActivateSandbox_SettlesStartingToActive(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()

	var reads int32
	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row {
			status := db.SandboxStatusStarting
			if atomic.AddInt32(&reads, 1) > 1 {
				status = db.SandboxStatusActive // async activate landed
			}
			return sandboxRow(db.Sandbox{ID: sandboxID, TeamID: teamID, Name: "sb", Status: status, VcpuCount: 1, MemoryMib: 512})
		},
	}
	h := &Handlers{VMD: &stubVMD{}, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, activateRequest(sandboxID.String()))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (settle window must absorb the async activate); body: %s", w.Code, w.Body.String())
	}
	if got := atomic.LoadInt32(&reads); got < 2 {
		t.Errorf("GetSandbox reads = %d, want >= 2 (must have polled)", got)
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

func TestResumeSandbox_ActivityLogFailure_StillReturns200(t *testing.T) {
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

func createSandboxReq(body string) *http.Request {
	return httptest.NewRequest(http.MethodPost, "/sandboxes", strings.NewReader(body))
}

func TestCreateSandbox_Success(t *testing.T) {
	teamID := uuid.New()
	sandboxID := uuid.New()

	// Even though the request omits from_template, the handler defaults it
	// to "superserve/base" and routes through RestoreSnapshot. The stub returns
	// VMD-reported resources (1 vcpu, 1024 MiB — stubVMD's defaults).
	var restoredAccess string
	var restoredPorts map[int32]vmdclient.PortPolicy
	var restoredRevision int64
	var attested bool
	var insertedSandboxID, policySandboxID uuid.UUID
	var insertedPolicyAccess string
	scheduler := &stubScheduler{hostID: "public-host"}
	var policyInsertedAtomically bool
	vmd := &stubVMD{
		restorePolicyFn: func(access string, ports map[int32]vmdclient.PortPolicy, revision int64) {
			restoredAccess, restoredPorts, restoredRevision = access, ports, revision
		},
		updatePreviewFn: func(_ context.Context, _ string, access string, ports map[int32]vmdclient.PortPolicy, revision int64) error {
			attested = true
			if access != preview.AccessPublic || ports != nil || revision != 0 {
				t.Errorf("live policy attestation = (%q, %#v, %d), want (public, nil, 0)", access, ports, revision)
			}
			return nil
		},
	}

	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			if strings.Contains(sql, "-- name: HostHasCapability :one") {
				return previewCapableHostRow()
			}
			if strings.Contains(sql, "INSERT INTO sandbox") {
				insertedSandboxID = args[0].(uuid.UUID)
				if strings.Contains(sql, "INSERT INTO sandbox_preview_policy") {
					policyInsertedAtomically = true
					policySandboxID = insertedSandboxID
					if access, ok := args[len(args)-1].(string); ok {
						insertedPolicyAccess = access
					}
				}
				return sandboxRow(db.Sandbox{
					ID: sandboxID, TeamID: teamID, Name: "my-sandbox",
					Status: db.SandboxStatusStarting, VcpuCount: 2, MemoryMib: 512,
					CreatedAt: time.Now(),
				})
			}
			if strings.Contains(sql, "FROM template") {
				return templateRow(defaultReadyTemplate())
			}
			return activityRow()
		},
		execFn: func(_ context.Context, _ string, _ ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock), Scheduler: scheduler}
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
	if body["preview_access"] != "public" {
		t.Errorf("preview_access = %q, want public", body["preview_access"])
	}
	if restoredAccess != "public" || restoredPorts != nil || restoredRevision != 0 {
		t.Errorf("restored preview policy = (%q, %#v, %d), want (public, nil, 0)", restoredAccess, restoredPorts, restoredRevision)
	}
	if !attested {
		t.Error("create did not attest the live VMD after restore")
	}
	if insertedSandboxID == uuid.Nil || !policyInsertedAtomically || policySandboxID != insertedSandboxID || insertedPolicyAccess != preview.AccessPublic {
		t.Errorf("inserted policy = (sandbox=%s access=%q), want sandbox=%s access=%q", policySandboxID, insertedPolicyAccess, insertedSandboxID, preview.AccessPublic)
	}
	if !reflect.DeepEqual(scheduler.required, []string{preview.HostCapabilityPorts}) {
		t.Errorf("scheduler requirements = %#v, want preview ports", scheduler.required)
	}
	// Resources should reflect what VMD reported, not the initial INSERT placeholders.
	if v := body["vcpu_count"].(float64); v == 0 {
		t.Error("vcpu_count is 0 — VMD's reported value was not propagated to the response")
	}
	if v := body["memory_mib"].(float64); v == 0 {
		t.Error("memory_mib is 0 — VMD's reported value was not propagated to the response")
	}
}

func TestCreateSandbox_PrivateUsesAccessCapablePlacementAndAttestation(t *testing.T) {
	teamID := uuid.New()
	sandboxID := uuid.New()
	scheduler := &stubScheduler{hostID: "private-host"}
	var restored, attested bool
	var policyAccess string
	var checkedCapabilities []string

	vmd := &stubVMD{
		restorePolicyFn: func(access string, ports map[int32]vmdclient.PortPolicy, revision int64) {
			restored = true
			if access != preview.AccessPrivate || ports != nil || revision != 0 {
				t.Errorf("restore policy = (%q, %#v, %d), want (private, nil, 0)", access, ports, revision)
			}
		},
		updatePreviewFn: func(_ context.Context, _ string, access string, ports map[int32]vmdclient.PortPolicy, revision int64) error {
			attested = true
			if access != preview.AccessPrivate || ports != nil || revision != 0 {
				t.Errorf("attested policy = (%q, %#v, %d), want (private, nil, 0)", access, ports, revision)
			}
			return nil
		},
	}
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "-- name: HostHasCapability :one"):
				checkedCapabilities = append(checkedCapabilities, args[1].(string))
				return previewCapableHostRow()
			case strings.Contains(sql, "INSERT INTO sandbox"):
				if strings.Contains(sql, "INSERT INTO sandbox_preview_policy") {
					if access, ok := args[len(args)-1].(string); ok {
						policyAccess = access
					}
				}
				return sandboxRow(db.Sandbox{
					ID: sandboxID, TeamID: teamID, Name: "private-sandbox",
					Status: db.SandboxStatusStarting, VcpuCount: 1, MemoryMib: 1024,
					CreatedAt: time.Now(), HostID: "private-host",
				})
			case strings.Contains(sql, "FROM template"):
				return templateRow(defaultReadyTemplate())
			default:
				return activityRow()
			}
		},
		execFn: func(_ context.Context, _ string, _ ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock), Scheduler: scheduler}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, createSandboxReq(`{"name":"private-sandbox","preview_access":"private"}`))

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", w.Code, w.Body.String())
	}
	if got := parseJSON(t, w)["preview_access"]; got != preview.AccessPrivate {
		t.Fatalf("preview_access = %#v, want private", got)
	}
	wantCaps := []string{preview.HostCapabilityPorts, preview.HostCapabilityPortAccess}
	if !reflect.DeepEqual(scheduler.required, wantCaps) {
		t.Fatalf("scheduler requirements = %#v, want %#v", scheduler.required, wantCaps)
	}
	if !reflect.DeepEqual(checkedCapabilities, wantCaps) {
		t.Fatalf("post-selection checks = %#v, want %#v", checkedCapabilities, wantCaps)
	}
	if policyAccess != preview.AccessPrivate || !restored || !attested {
		t.Fatalf("private create policy = %q restored=%v attested=%v", policyAccess, restored, attested)
	}
}

func TestCreateSandbox_RechecksCapabilitiesAfterSchedulerSelection(t *testing.T) {
	teamID := uuid.New()
	scheduler := &stubScheduler{hostID: "rolled-back-host"}
	var inserted, restored bool
	var checks int
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "FROM template"):
				return templateRow(defaultReadyTemplate())
			case strings.Contains(sql, "-- name: HostHasCapability :one"):
				checks++
				capability := args[1].(string)
				return scalarBoolRow(capability == preview.HostCapabilityPorts)
			case strings.Contains(sql, "INSERT INTO sandbox"):
				inserted = true
				return errorRow(fmt.Errorf("insert must not run after capability rollback"))
			default:
				return errorRow(fmt.Errorf("unexpected query: %s", sql))
			}
		},
		execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			inserted = true
			return pgconn.CommandTag{}, fmt.Errorf("unexpected exec: %s", sql)
		},
	}
	vmd := &stubVMD{restoreFn: func(context.Context, string, string, string) (string, error) {
		restored = true
		return "", nil
	}}

	h := &Handlers{VMD: vmd, DB: db.New(mock), Scheduler: scheduler}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, createSandboxReq(`{"name":"private-sandbox","preview_access":"private"}`))

	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body: %s", w.Code, w.Body.String())
	}
	if checks != 2 || inserted || restored {
		t.Fatalf("post-selection result: checks=%d inserted=%v restored=%v", checks, inserted, restored)
	}
}

func TestCreateSandbox_PreviewAttestationFailureFailsClosed(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "old vmd unimplemented", err: status.Error(codes.Unimplemented, "unknown method UpdateSandboxPreviewPolicy")},
		{name: "policy update failed", err: status.Error(codes.Internal, "policy persistence failed")},
		{name: "revision zero policy mismatch", err: status.Error(codes.FailedPrecondition, "revision zero conflicts with stored policy")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			teamID := uuid.New()
			sandboxID := uuid.New()
			var destroyed, injected bool
			vmd := &stubVMD{
				updatePreviewFn: func(context.Context, string, string, map[int32]vmdclient.PortPolicy, int64) error {
					return tt.err
				},
				destroyFn: func(context.Context, string, bool) error {
					destroyed = true
					return nil
				},
				injectEnvFn: func(context.Context, string, map[string]string, string) error {
					injected = true
					return nil
				},
			}
			mock := &mockDBTX{
				queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
					switch {
					case strings.Contains(sql, "-- name: HostHasCapability :one"):
						return previewCapableHostRow()
					case strings.Contains(sql, "INSERT INTO sandbox"):
						return sandboxRow(db.Sandbox{
							ID: sandboxID, TeamID: teamID, Name: "sb",
							Status: db.SandboxStatusStarting, VcpuCount: 1, MemoryMib: 256,
						})
					case strings.Contains(sql, "FROM template"):
						return templateRow(defaultReadyTemplate())
					default:
						return activityRow()
					}
				},
				execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
					return pgconn.NewCommandTag("UPDATE 1"), nil
				},
			}

			h := &Handlers{VMD: vmd, DB: db.New(mock)}
			w := httptest.NewRecorder()
			setupTestRouter(h, teamID.String()).ServeHTTP(w, createSandboxReq(`{"name":"sb"}`))

			if w.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500; body: %s", w.Code, w.Body.String())
			}
			if !destroyed {
				t.Fatal("VM was not destroyed after preview attestation failure")
			}
			if injected {
				t.Fatal("env injection ran before preview attestation succeeded")
			}
		})
	}
}

func TestCreateSandbox_InjectEnvUnimplementedTolerated(t *testing.T) {
	teamID := uuid.New()
	sandboxID := uuid.New()

	// A vmd that predates InjectSandboxEnv returns Unimplemented. With no
	// secrets bound, the env vars were already applied during RestoreSnapshot,
	// so creation should still succeed. Env vars in the request keep this on
	// the synchronous path — the branch this tolerance lives on.
	vmd := &stubVMD{
		injectEnvFn: func(context.Context, string, map[string]string, string) error {
			return status.Error(codes.Unimplemented, "unknown method InjectSandboxEnv")
		},
	}

	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if strings.Contains(sql, "-- name: HostHasCapability :one") {
				return previewCapableHostRow()
			}
			if strings.Contains(sql, "INSERT INTO sandbox") {
				return sandboxRow(db.Sandbox{
					ID: sandboxID, TeamID: teamID, Name: "sb",
					Status: db.SandboxStatusStarting, VcpuCount: 1, MemoryMib: 256,
					CreatedAt: time.Now(),
				})
			}
			if strings.Contains(sql, "FROM template") {
				return templateRow(defaultReadyTemplate())
			}
			return activityRow()
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, createSandboxReq(`{"name":"sb","env_vars":{"FOO":"bar"}}`))

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", w.Code, w.Body.String())
	}
	if body := parseJSON(t, w); body["status"] != "active" {
		t.Errorf("status = %q, want active", body["status"])
	}
	h.WaitAsyncBookkeeping()
}

func TestCreateSandbox_InjectEnvErrorFails(t *testing.T) {
	teamID := uuid.New()
	sandboxID := uuid.New()

	// A real injection failure (not Unimplemented) on a create that ships env
	// vars has no fallback: the VM is torn down and the request fails. Env
	// vars in the request keep this on the synchronous path — a hostname-only
	// create handles the same failure asynchronously (test below).
	var destroyed bool
	vmd := &stubVMD{
		injectEnvFn: func(context.Context, string, map[string]string, string) error {
			return status.Error(codes.Internal, "post-init failed")
		},
		destroyFn: func(context.Context, string, bool) error {
			destroyed = true
			return nil
		},
	}

	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if strings.Contains(sql, "-- name: HostHasCapability :one") {
				return previewCapableHostRow()
			}
			if strings.Contains(sql, "INSERT INTO sandbox") {
				return sandboxRow(db.Sandbox{
					ID: sandboxID, TeamID: teamID, Name: "sb",
					Status: db.SandboxStatusStarting, VcpuCount: 1, MemoryMib: 256,
				})
			}
			if strings.Contains(sql, "FROM template") {
				return templateRow(defaultReadyTemplate())
			}
			return activityRow()
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, createSandboxReq(`{"name":"sb","env_vars":{"FOO":"bar"}}`))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
	if !destroyed {
		t.Error("VM was not torn down after injection failure")
	}
}

// hostnameStampEnv builds the shared fixture for the async-stamp tests: a
// hostname-only create whose stamp is held open on a channel, with counters
// on the stamp, ActivateSandbox, and DestroyInstance.
type hostnameStampEnv struct {
	h             *Handlers
	teamID        uuid.UUID
	injectRelease chan struct{}
	releaseOnce   sync.Once
	stamped       atomic.Bool
	activated     atomic.Bool
	destroyed     atomic.Bool
}

func (e *hostnameStampEnv) release() { e.releaseOnce.Do(func() { close(e.injectRelease) }) }

func newHostnameStampEnv(t *testing.T, stampErr error) *hostnameStampEnv {
	t.Helper()
	e := &hostnameStampEnv{teamID: uuid.New(), injectRelease: make(chan struct{})}
	sandboxID := uuid.New()
	vmd := &stubVMD{
		injectEnvFn: func(_ context.Context, _ string, envVars map[string]string, jwt string) error {
			<-e.injectRelease // hold the stamp until the test releases it
			if len(envVars) != 0 || jwt != "" {
				t.Errorf("hostname-only path must ship no env/jwt, got env=%v jwt=%q", envVars, jwt)
			}
			e.stamped.Store(true)
			return stampErr
		},
		destroyFn: func(context.Context, string, bool) error {
			e.destroyed.Store(true)
			return nil
		},
	}
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if strings.Contains(sql, "-- name: HostHasCapability :one") {
				return previewCapableHostRow()
			}
			if strings.Contains(sql, "INSERT INTO sandbox") {
				return sandboxRow(db.Sandbox{
					ID: sandboxID, TeamID: e.teamID, Name: "sb",
					Status: db.SandboxStatusStarting, VcpuCount: 1, MemoryMib: 256,
					CreatedAt: time.Now(),
				})
			}
			if strings.Contains(sql, "FROM template") {
				return templateRow(defaultReadyTemplate())
			}
			return activityRow()
		},
		execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			if strings.Contains(sql, "sandbox_active_interval") {
				e.activated.Store(true)
			}
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}
	e.h = &Handlers{VMD: vmd, DB: db.New(mock)}
	// An assertion failure before release must not strand the goroutine —
	// a late-resumed stamp calling t.Errorf after completion panics the
	// test binary.
	t.Cleanup(func() {
		e.release()
		e.h.WaitAsyncBookkeeping()
	})
	return e
}

// A hostname-only create must not pay for the guest round trip: the response
// returns while the stamp is still in flight, and the stamp runs strictly
// before the row is activated so pause/destroy (status-gated on 'active')
// can never precede it.
func TestCreateSandbox_HostnameStampAsyncBeforeActivation(t *testing.T) {
	e := newHostnameStampEnv(t, nil)
	w := httptest.NewRecorder()
	setupTestRouter(e.h, e.teamID.String()).ServeHTTP(w, createSandboxReq(`{"name":"sb"}`))

	// The response must not have waited for the (still-held) stamp — and
	// activation must not have happened while the stamp is unfinished.
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", w.Code, w.Body.String())
	}
	if e.activated.Load() {
		t.Fatal("row activated before the hostname stamp completed")
	}
	e.release()
	e.h.WaitAsyncBookkeeping()
	if !e.stamped.Load() {
		t.Fatal("hostname stamp was never attempted")
	}
	if !e.activated.Load() {
		t.Fatal("row was not activated after the stamp completed")
	}
	if e.destroyed.Load() {
		t.Error("successful stamp must not destroy the sandbox")
	}
}

// A real guest failure during the stamp means the sandbox's boxd is not
// answering — the row must go failed, not active: never a live-looking
// sandbox with a dead guest.
func TestCreateSandbox_HostnameStampFailureFailsRow(t *testing.T) {
	e := newHostnameStampEnv(t, status.Error(codes.Internal, "post-init failed"))
	w := httptest.NewRecorder()
	setupTestRouter(e.h, e.teamID.String()).ServeHTTP(w, createSandboxReq(`{"name":"sb"}`))

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", w.Code, w.Body.String())
	}
	e.release()
	e.h.WaitAsyncBookkeeping()
	if e.activated.Load() {
		t.Error("failed stamp must not activate the row")
	}
	if !e.destroyed.Load() {
		t.Error("failed stamp must tear the VM down (failSandboxAfterBoot)")
	}
}

// NotFound before activation means the VM vanished abnormally (destroy is
// status-gated on 'active', so no user path removes it this early) — the row
// must go failed, never active-without-a-VM, and never resurrect a
// concurrently-failed row through ActivateSandbox's unguarded UPDATE.
func TestCreateSandbox_HostnameStampNotFoundFailsRow(t *testing.T) {
	e := newHostnameStampEnv(t, status.Error(codes.NotFound, "vm not found"))
	w := httptest.NewRecorder()
	setupTestRouter(e.h, e.teamID.String()).ServeHTTP(w, createSandboxReq(`{"name":"sb"}`))

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", w.Code, w.Body.String())
	}
	e.release()
	e.h.WaitAsyncBookkeeping()
	if e.activated.Load() {
		t.Error("a vanished VM must not produce an active row")
	}
	if !e.destroyed.Load() {
		t.Error("NotFound must take the failure path (failSandboxAfterBoot)")
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

func TestCreateSandbox_QuotaExceeded(t *testing.T) {
	teamID := uuid.New()
	vmd := &stubVMD{}

	// SS001 is what the sandbox_quota_on_insert trigger raises on over-quota.
	var destroyCalled bool
	vmd.destroyFn = func(_ context.Context, _ string, _ bool) error {
		destroyCalled = true
		return nil
	}

	quotaErr := &pgconn.PgError{Code: "SS001", Message: "sandbox quota exceeded"}

	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if strings.Contains(sql, "-- name: HostHasCapability :one") {
				return previewCapableHostRow()
			}
			if strings.Contains(sql, "INSERT INTO sandbox") {
				return errorRow(quotaErr)
			}
			if strings.Contains(sql, "FROM template") {
				return templateRow(defaultReadyTemplate())
			}
			// GetTeam lookup in respondQuotaExceeded falls back to the
			// code default when this errs.
			return notFoundRow()
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, createSandboxReq(`{"name":"x"}`))

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusTooManyRequests, w.Body.String())
	}
	body := parseJSON(t, w)
	errObj, _ := body["error"].(map[string]any)
	if errObj["code"] != "too_many_sandboxes" {
		t.Errorf("error code = %v, want too_many_sandboxes", errObj["code"])
	}
	if !destroyCalled {
		t.Error("orphan VM was not destroyed after quota rejection")
	}
}

func TestCreateSandbox_VMDError(t *testing.T) {
	teamID := uuid.New()
	sandboxID := uuid.New()

	// With the superserve/base default, CreateSandbox routes through
	// RestoreSnapshot. Fail it to exercise the VMD-error branch.
	vmd := &stubVMD{
		restoreFn: func(context.Context, string, string, string) (string, error) {
			return "", fmt.Errorf("vmd unreachable")
		},
	}

	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if strings.Contains(sql, "-- name: HostHasCapability :one") {
				return previewCapableHostRow()
			}
			if strings.Contains(sql, "INSERT INTO sandbox") {
				return sandboxRow(db.Sandbox{
					ID: sandboxID, TeamID: teamID, Name: "sb",
					Status: db.SandboxStatusStarting, VcpuCount: 1, MemoryMib: 256,
				})
			}
			if strings.Contains(sql, "FROM template") {
				return templateRow(defaultReadyTemplate())
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
			case strings.Contains(sql, "upserted AS"):
				// FinalizePause: CTE upsert + update, returns snapshot_id
				return finalizePauseRow(snapshotID)
			case strings.Contains(sql, "INSERT INTO snapshot"):
				// Belt-and-braces: FinalizePause contains an INSERT inside
				// the upserted CTE; match that too in case the SQL text
				// routing misses the CTE alias.
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

	// Pause now returns 204 No Content — no response body.
	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d; body: %s", w.Code, http.StatusNoContent, w.Body.String())
	}
	if !pauseCalled {
		t.Error("VMD.PauseInstance was not called")
	}
	if w.Body.Len() != 0 {
		t.Errorf("expected empty body on 204, got: %s", w.Body.String())
	}
}

func TestPauseSandbox_NotActive(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()

	// BeginPause's WHERE status = 'active' clause excludes a paused
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

func TestCreateSandbox_WithMetadata(t *testing.T) {
	teamID := uuid.New()
	sandboxID := uuid.New()

	var capturedMetadata []byte
	vmd := &stubVMD{}
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			if strings.Contains(sql, "-- name: HostHasCapability :one") {
				return previewCapableHostRow()
			}
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
			if strings.Contains(sql, "FROM template") {
				return templateRow(defaultReadyTemplate())
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
	vmd := &stubVMD{}
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			if strings.Contains(sql, "-- name: HostHasCapability :one") {
				return previewCapableHostRow()
			}
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
			if strings.Contains(sql, "FROM template") {
				return templateRow(defaultReadyTemplate())
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

func TestFailSandboxAfterBootUsesDetachedCleanupOnSandboxHost(t *testing.T) {
	var defaultDestroyed, hostDestroyed string
	var destroyContextErr error
	var dbCalls int
	defaultVMD := &stubVMD{destroyFn: func(_ context.Context, id string, _ bool) error {
		defaultDestroyed = id
		return nil
	}}
	hostVMD := &stubVMD{destroyFn: func(ctx context.Context, id string, _ bool) error {
		hostDestroyed = id
		destroyContextErr = ctx.Err()
		return nil
	}}
	mock := &mockDBTX{
		execFn: func(ctx context.Context, _ string, _ ...any) (pgconn.CommandTag, error) {
			dbCalls++
			if err := ctx.Err(); err != nil {
				t.Errorf("cleanup DB context already canceled: %v", err)
			}
			return pgconn.NewCommandTag(""), nil
		},
	}
	h := &Handlers{VMD: defaultVMD, DB: db.New(mock)}

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	h.failSandboxAfterBoot(canceledCtx, hostVMD, uuid.New(), uuid.New(), "instance-xyz", "host-a")

	if hostDestroyed != "instance-xyz" {
		t.Errorf("destroy routed to host client = %q, want instance-xyz", hostDestroyed)
	}
	if defaultDestroyed != "" {
		t.Errorf("default client must not destroy; got %q", defaultDestroyed)
	}
	if destroyContextErr != nil {
		t.Errorf("destroy cleanup context already canceled: %v", destroyContextErr)
	}
	if dbCalls != 2 {
		t.Errorf("cleanup DB writes = %d, want status update + secret cleanup", dbCalls)
	}
}

func TestListSandboxFiles_Success(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Name: "test-sb", Status: db.SandboxStatusActive}

	var gotPath string
	vmd := &stubVMD{
		listDirFn: func(_ context.Context, id, path string) ([]vmdclient.DirEntry, error) {
			gotPath = path
			if id != sandboxID.String() {
				t.Errorf("ListDir id = %q, want %q", id, sandboxID)
			}
			return []vmdclient.DirEntry{
				{Name: "src", IsDir: true, Size: 4096, ModifiedUnix: 1700000000},
				{Name: "readme.md", IsDir: false, Size: 12, ModifiedUnix: 0},
			}, nil
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
	req := httptest.NewRequest(http.MethodGet, "/sandboxes/"+sandboxID.String()+"/files?path=/home/user", nil)
	setupTestRouter(h, teamID.String()).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
	if gotPath != "/home/user" {
		t.Errorf("ListDir path = %q, want %q", gotPath, "/home/user")
	}
	body := parseJSON(t, w)
	entries, ok := body["entries"].([]any)
	if !ok || len(entries) != 2 {
		t.Fatalf("entries = %v, want 2 items", body["entries"])
	}
	first := entries[0].(map[string]any)
	if first["name"] != "src" || first["is_dir"] != true {
		t.Errorf("first entry = %v, want src/dir", first)
	}
	if first["modified_unix"] != float64(1700000000) {
		t.Errorf("modified_unix = %v, want 1700000000", first["modified_unix"])
	}
}

// A missing directory must surface as 404, never 410 Gone: listing must not
// mistake a boxd "not found" for a dead VM and mark the sandbox failed.
func TestListSandboxFiles_NotFoundIsNotFatal(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Name: "test-sb", Status: db.SandboxStatusActive}

	vmd := &stubVMD{
		listDirFn: func(context.Context, string, string) ([]vmdclient.DirEntry, error) {
			return nil, status.Error(codes.NotFound, "directory not found")
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
	req := httptest.NewRequest(http.MethodGet, "/sandboxes/"+sandboxID.String()+"/files?path=/nope", nil)
	setupTestRouter(h, teamID.String()).ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d (a missing dir must be 404, not 410 Gone); body: %s", w.Code, http.StatusNotFound, w.Body.String())
	}
}

func TestListSandboxFiles_PathTraversalRejected(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Name: "test-sb", Status: db.SandboxStatusActive}

	var listCalled bool
	vmd := &stubVMD{
		listDirFn: func(context.Context, string, string) ([]vmdclient.DirEntry, error) {
			listCalled = true
			return nil, nil
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
	req := httptest.NewRequest(http.MethodGet, "/sandboxes/"+sandboxID.String()+"/files?path=/a/../b", nil)
	setupTestRouter(h, teamID.String()).ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d; body: %s", w.Code, http.StatusBadRequest, w.Body.String())
	}
	if listCalled {
		t.Error("ListDir should not be called for a traversal path")
	}
}

func TestPauseWithRetry_RetriesTransientThenSucceeds(t *testing.T) {
	calls := 0
	vmd := &stubVMD{pauseFn: func(ctx context.Context, id, dir string) (string, string, error) {
		calls++
		if calls == 1 {
			return "", "", context.DeadlineExceeded
		}
		return "/snap/vmstate.snap", "/snap/mem.snap", nil
	}}
	snap, mem, err := pauseWithRetry(context.Background(), vmd, "vm-1")
	if err != nil {
		t.Fatalf("retry should recover a transient failure, got %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected 1 retry (2 calls), got %d", calls)
	}
	if snap == "" || mem == "" {
		t.Fatalf("expected snapshot artifacts, got (%q,%q)", snap, mem)
	}
}

func TestPauseWithRetry_NotFoundIsTerminal(t *testing.T) {
	calls := 0
	notFound := status.Error(codes.NotFound, "no such vm")
	vmd := &stubVMD{pauseFn: func(ctx context.Context, id, dir string) (string, string, error) {
		calls++
		return "", "", notFound
	}}
	_, _, err := pauseWithRetry(context.Background(), vmd, "vm-1")
	if !isVMDNotFound(err) {
		t.Fatalf("expected NotFound to surface, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("NotFound must not be retried, got %d calls", calls)
	}
}
