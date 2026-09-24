package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

// sandboxSnapshotRow scans a db.SandboxSnapshot in the column order of the
// generated queries (see internal/db/models.go).
func sandboxSnapshotRow(s db.SandboxSnapshot) *mockRow {
	return &mockRow{scanFn: func(dest ...any) error {
		if len(dest) != 27 {
			return fmt.Errorf("sandbox_snapshot scan wants 27 columns, got %d", len(dest))
		}
		*dest[0].(*uuid.UUID) = s.ID
		*dest[1].(*uuid.UUID) = s.TeamID
		*dest[2].(*uuid.UUID) = s.SandboxID
		*dest[3].(*pgtype.UUID) = s.TemplateID
		*dest[4].(*string) = s.Kind
		*dest[5].(*string) = s.Status
		*dest[6].(**string) = s.Name
		*dest[7].(**string) = s.IdempotencyKey
		*dest[8].(*string) = s.HostID
		*dest[9].(*int32) = s.VcpuCount
		*dest[10].(*int32) = s.MemoryMib
		*dest[11].(*int32) = s.DiskMib
		*dest[12].(*string) = s.BasePath
		*dest[13].(**string) = s.BaseMemPath
		*dest[14].(**string) = s.SnapshotPath
		*dest[15].(**string) = s.MemPath
		*dest[16].(**string) = s.OverlayPath
		*dest[17].(*int64) = s.SizeBytes
		*dest[18].(**int32) = s.TimeoutSeconds
		*dest[19].(*[]byte) = s.NetworkConfig
		*dest[20].(*[]byte) = s.SecretBindings
		*dest[21].(**string) = s.FcBuildSha
		*dest[22].(**string) = s.GuestKernel
		*dest[23].(**string) = s.SnapshotFormat
		*dest[24].(*time.Time) = s.CreatedAt
		*dest[25].(*pgtype.Timestamptz) = s.ReadyAt
		*dest[26].(*pgtype.Timestamptz) = s.DeletedAt
		return nil
	}}
}

func countRow(n int64) *mockRow {
	return &mockRow{scanFn: func(dest ...any) error {
		*dest[0].(*int64) = n
		return nil
	}}
}

func errRow(err error) *mockRow {
	return &mockRow{scanFn: func(...any) error { return err }}
}

// scriptedRows is a pgx.Rows over prepared scan functions.
type scriptedRows struct {
	emptyRows
	rows []*mockRow
	i    int
}

func (r *scriptedRows) Next() bool {
	if r.i >= len(r.rows) {
		return false
	}
	r.i++
	return true
}

func (r *scriptedRows) Scan(dest ...any) error { return r.rows[r.i-1].Scan(dest...) }

func snapshotRouter(h *Handlers, teamID uuid.UUID) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("team_id", teamID.String())
		c.Next()
	})
	r.POST("/sandboxes/:sandbox_id/snapshot", h.CreateSandboxSnapshot)
	r.GET("/sandboxes/:sandbox_id/snapshots", h.ListSandboxSnapshots)
	r.GET("/snapshots/:snapshot_id", h.GetSnapshot)
	r.PATCH("/snapshots/:snapshot_id", h.PatchSnapshot)
	r.DELETE("/snapshots/:snapshot_id", h.DeleteSnapshot)
	return r
}

func jsonReq(method, path string, body any) *http.Request {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	return req
}

func snapshotFixture(teamID, sandboxID uuid.UUID, status string) db.SandboxSnapshot {
	base := "/base.ext4"
	return db.SandboxSnapshot{
		ID: uuid.New(), TeamID: teamID, SandboxID: sandboxID, Kind: "mem+fs", Status: status,
		HostID: "host-1", VcpuCount: 2, MemoryMib: 2048, DiskMib: 8192, BasePath: base,
		NetworkConfig: []byte("{}"), SecretBindings: []byte("[]"), CreatedAt: time.Now(),
	}
}

func TestCreateSandboxSnapshotCapturesAndAnswersReady(t *testing.T) {
	teamID, sandboxID := uuid.New(), uuid.New()
	base := "/templates/t/base.ext4"
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Name: "sb", Status: db.SandboxStatusActive, HostID: "host-1", BasePath: &base, VcpuCount: 2, MemoryMib: 2048, DiskMib: 8192}
	var inserted db.SandboxSnapshot
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "-- name: GetSandbox :one"):
				return sandboxRow(sb)
			case strings.Contains(sql, "-- name: CountTeamSnapshotsCreating :one"):
				return countRow(0)
			case strings.Contains(sql, "-- name: CreateSandboxSnapshot :one"):
				inserted = snapshotFixture(teamID, sandboxID, "creating")
				inserted.ID = args[0].(uuid.UUID)
				inserted.Kind = args[4].(string)
				return sandboxSnapshotRow(inserted)
			case strings.Contains(sql, "-- name: MarkSandboxSnapshotReady :one"):
				ready := inserted
				ready.Status = "ready"
				ready.SizeBytes = 4096
				ready.ReadyAt = pgtype.Timestamptz{Time: time.Now(), Valid: true}
				return sandboxSnapshotRow(ready)
			}
			return errRow(fmt.Errorf("unexpected query: %s", sql))
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}
	var capturedVM, capturedID, capturedKind string
	vmd := &stubVMD{createSavedFn: func(_ context.Context, id, snapshotID, kind string) (vmdclient.SavedSnapshot, error) {
		capturedVM, capturedID, capturedKind = id, snapshotID, kind
		return vmdclient.SavedSnapshot{Kind: kind, DiskPath: "/saved/" + snapshotID + "/overlay.ext4", SnapshotPath: "/saved/" + snapshotID + "/vmstate.snap", MemPath: "/saved/" + snapshotID + "/mem.diff", SizeBytes: 4096}, nil
	}}
	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	snapshotRouter(h, teamID).ServeHTTP(w, jsonReq(http.MethodPost, "/sandboxes/"+sandboxID.String()+"/snapshot", map[string]any{"kind": "mem+fs", "name": "before-upgrade"}))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", w.Code, w.Body.String())
	}
	if capturedVM != sandboxID.String() || capturedID != inserted.ID.String() || capturedKind != "mem+fs" {
		t.Fatalf("host asked for vm=%s id=%s kind=%s; want the sandbox, the row's id and mem+fs", capturedVM, capturedID, capturedKind)
	}
	body := parseJSON(t, w)
	if body["status"] != "ready" || body["kind"] != "mem+fs" || body["size_bytes"].(float64) != 4096 || body["id"] != inserted.ID.String() {
		t.Errorf("body = %v", body)
	}
}

func TestCreateSandboxSnapshotRefusesASandboxInTransition(t *testing.T) {
	teamID, sandboxID := uuid.New(), uuid.New()
	base := "/base.ext4"
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Status: db.SandboxStatusPausing, HostID: "host-1", BasePath: &base}
	inserted := false
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if strings.Contains(sql, "-- name: GetSandbox :one") {
				return sandboxRow(sb)
			}
			inserted = true
			return errRow(fmt.Errorf("unexpected query: %s", sql))
		},
	}
	captured := false
	vmd := &stubVMD{createSavedFn: func(context.Context, string, string, string) (vmdclient.SavedSnapshot, error) {
		captured = true
		return vmdclient.SavedSnapshot{}, nil
	}}
	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	snapshotRouter(h, teamID).ServeHTTP(w, jsonReq(http.MethodPost, "/sandboxes/"+sandboxID.String()+"/snapshot", nil))
	if w.Code != http.StatusConflict || inserted || captured {
		t.Fatalf("status=%d inserted=%v captured=%v; want 409 and nothing done", w.Code, inserted, captured)
	}
}

func TestCreateSandboxSnapshotAnswersNotFoundAcrossTeams(t *testing.T) {
	teamID, sandboxID := uuid.New(), uuid.New()
	mock := &mockDBTX{queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
		return errRow(pgx.ErrNoRows)
	}}
	h := &Handlers{VMD: &stubVMD{}, DB: db.New(mock)}
	w := httptest.NewRecorder()
	snapshotRouter(h, teamID).ServeHTTP(w, jsonReq(http.MethodPost, "/sandboxes/"+sandboxID.String()+"/snapshot", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestCreateSandboxSnapshotMapsQuotaAndIdempotentReplay(t *testing.T) {
	teamID, sandboxID := uuid.New(), uuid.New()
	base := "/base.ext4"
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Status: db.SandboxStatusPaused, HostID: "host-1", BasePath: &base, VcpuCount: 1, MemoryMib: 1024, DiskMib: 4096}
	existing := snapshotFixture(teamID, sandboxID, "ready")
	key := "deploy-42"
	existing.IdempotencyKey = &key
	insertErr := error(&pgconn.PgError{Code: snapshotQuotaErrCode, Message: "snapshot quota exceeded"})
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "-- name: GetSandbox :one"):
				return sandboxRow(sb)
			case strings.Contains(sql, "-- name: CountTeamSnapshotsCreating :one"):
				return countRow(1)
			case strings.Contains(sql, "-- name: CreateSandboxSnapshot :one"):
				return errRow(insertErr)
			case strings.Contains(sql, "-- name: GetSandboxSnapshotByIdempotencyKey :one"):
				return sandboxSnapshotRow(existing)
			}
			return errRow(fmt.Errorf("unexpected query: %s", sql))
		},
	}
	captured := 0
	vmd := &stubVMD{createSavedFn: func(context.Context, string, string, string) (vmdclient.SavedSnapshot, error) {
		captured++
		return vmdclient.SavedSnapshot{}, nil
	}}
	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	r := snapshotRouter(h, teamID)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, jsonReq(http.MethodPost, "/sandboxes/"+sandboxID.String()+"/snapshot", map[string]any{"kind": "fs"}))
	if w.Code != http.StatusTooManyRequests || parseJSON(t, w)["error"].(map[string]any)["code"] != "too_many_snapshots" {
		t.Fatalf("quota: status=%d body=%s", w.Code, w.Body.String())
	}

	insertErr = &pgconn.PgError{Code: "23505", ConstraintName: "sandbox_snapshot_idempotency"}
	w = httptest.NewRecorder()
	r.ServeHTTP(w, jsonReq(http.MethodPost, "/sandboxes/"+sandboxID.String()+"/snapshot", map[string]any{"kind": "mem+fs", "idempotency_key": key}))
	if w.Code != http.StatusOK || parseJSON(t, w)["id"] != existing.ID.String() {
		t.Fatalf("replay: status=%d body=%s", w.Code, w.Body.String())
	}
	if captured != 0 {
		t.Fatalf("the host was asked %d time(s); a refused insert must never capture", captured)
	}
}

func TestCreateSandboxSnapshotFailsTheRowWhenTheHostCannot(t *testing.T) {
	teamID, sandboxID := uuid.New(), uuid.New()
	base := "/base.ext4"
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Status: db.SandboxStatusActive, HostID: "host-1", BasePath: &base, VcpuCount: 1, MemoryMib: 1024, DiskMib: 4096}
	failed, hostCleaned := false, false
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "-- name: GetSandbox :one"):
				return sandboxRow(sb)
			case strings.Contains(sql, "-- name: CountTeamSnapshotsCreating :one"):
				return countRow(0)
			case strings.Contains(sql, "-- name: CreateSandboxSnapshot :one"):
				row := snapshotFixture(teamID, sandboxID, "creating")
				row.ID = args[0].(uuid.UUID)
				return sandboxSnapshotRow(row)
			}
			return errRow(fmt.Errorf("unexpected query: %s", sql))
		},
		execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			if strings.Contains(sql, "-- name: MarkSandboxSnapshotFailed :execrows") {
				failed = true
			}
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}
	vmd := &stubVMD{
		createSavedFn: func(context.Context, string, string, string) (vmdclient.SavedSnapshot, error) {
			return vmdclient.SavedSnapshot{}, status.Error(codes.Unimplemented, "unknown method CreateSavedSnapshot")
		},
		deleteSavedFn: func(context.Context, string) error { hostCleaned = true; return nil },
	}
	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	snapshotRouter(h, teamID).ServeHTTP(w, jsonReq(http.MethodPost, "/sandboxes/"+sandboxID.String()+"/snapshot", nil))
	if w.Code != http.StatusServiceUnavailable || parseJSON(t, w)["error"].(map[string]any)["code"] != "host_not_ready" {
		t.Fatalf("status=%d body=%s; want 503 host_not_ready", w.Code, w.Body.String())
	}
	if !failed || !hostCleaned {
		t.Fatalf("failed=%v hostCleaned=%v; want the row failed and the host cleaned", failed, hostCleaned)
	}
}

func TestDeleteSnapshotRemovesReadyRefusesCreatingDefersOnHostError(t *testing.T) {
	teamID, sandboxID := uuid.New(), uuid.New()
	row := snapshotFixture(teamID, sandboxID, "ready")
	creating := snapshotFixture(teamID, sandboxID, "creating")
	hostErr := error(nil)
	deleted := 0
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			id := args[0].(uuid.UUID)
			switch {
			case strings.Contains(sql, "-- name: BeginSandboxSnapshotDelete :one"):
				if id == creating.ID {
					return errRow(pgx.ErrNoRows)
				}
				r := row
				r.Status = "deleting"
				return sandboxSnapshotRow(r)
			case strings.Contains(sql, "-- name: GetSandboxSnapshot :one"):
				if id == creating.ID {
					return sandboxSnapshotRow(creating)
				}
				return errRow(pgx.ErrNoRows)
			}
			return errRow(fmt.Errorf("unexpected query: %s", sql))
		},
		execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			if strings.Contains(sql, "-- name: MarkSandboxSnapshotDeleted :execrows") {
				deleted++
			}
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}
	hostAsked := []string{}
	vmd := &stubVMD{deleteSavedFn: func(_ context.Context, id string) error { hostAsked = append(hostAsked, id); return hostErr }}
	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	r := snapshotRouter(h, teamID)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/snapshots/"+row.ID.String(), nil))
	if w.Code != http.StatusNoContent || deleted != 1 || len(hostAsked) != 1 || hostAsked[0] != row.ID.String() {
		t.Fatalf("ready delete: status=%d deleted=%d hostAsked=%v", w.Code, deleted, hostAsked)
	}

	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/snapshots/"+creating.ID.String(), nil))
	if w.Code != http.StatusConflict || len(hostAsked) != 1 {
		t.Fatalf("creating delete: status=%d hostAsked=%v; want 409 and no host call", w.Code, hostAsked)
	}

	hostErr = status.Error(codes.Unavailable, "host restarting")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/snapshots/"+row.ID.String(), nil))
	if w.Code != http.StatusAccepted || w.Header().Get("Retry-After") == "" || deleted != 1 {
		t.Fatalf("host error: status=%d retry-after=%q deleted=%d; want 202 with the row left deleting", w.Code, w.Header().Get("Retry-After"), deleted)
	}
}

func TestPatchSnapshotRenames(t *testing.T) {
	teamID, sandboxID := uuid.New(), uuid.New()
	row := snapshotFixture(teamID, sandboxID, "ready")
	mock := &mockDBTX{queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
		if strings.Contains(sql, "-- name: RenameSandboxSnapshot :one") {
			r := row
			name := *args[2].(*string)
			r.Name = &name
			return sandboxSnapshotRow(r)
		}
		return errRow(fmt.Errorf("unexpected query: %s", sql))
	}}
	h := &Handlers{VMD: &stubVMD{}, DB: db.New(mock)}
	r := snapshotRouter(h, teamID)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, jsonReq(http.MethodPatch, "/snapshots/"+row.ID.String(), map[string]any{"name": ""}))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("empty name: status=%d", w.Code)
	}
	w = httptest.NewRecorder()
	r.ServeHTTP(w, jsonReq(http.MethodPatch, "/snapshots/"+row.ID.String(), map[string]any{"name": "golden"}))
	if w.Code != http.StatusOK || parseJSON(t, w)["name"] != "golden" {
		t.Fatalf("rename: status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestListSandboxSnapshotsReturnsNewestFirstWithTotal(t *testing.T) {
	teamID, sandboxID := uuid.New(), uuid.New()
	newer := snapshotFixture(teamID, sandboxID, "ready")
	older := snapshotFixture(teamID, sandboxID, "ready")
	older.CreatedAt = newer.CreatedAt.Add(-time.Hour)
	mock := &mockDBTX{queryFn: func(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
		if strings.Contains(sql, "-- name: ListSandboxSnapshots :many") {
			return &scriptedRows{rows: []*mockRow{sandboxSnapshotRow(newer), sandboxSnapshotRow(older)}}, nil
		}
		return nil, fmt.Errorf("unexpected query: %s", sql)
	}}
	h := &Handlers{VMD: &stubVMD{}, DB: db.New(mock)}
	w := httptest.NewRecorder()
	snapshotRouter(h, teamID).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/sandboxes/"+sandboxID.String()+"/snapshots", nil))
	if w.Code != http.StatusOK || w.Header().Get("X-Total-Count") != "2" {
		t.Fatalf("status=%d total=%q body=%s", w.Code, w.Header().Get("X-Total-Count"), w.Body.String())
	}
	var out []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || len(out) != 2 || out[0]["id"] != newer.ID.String() {
		t.Fatalf("body = %s (%v)", w.Body.String(), err)
	}
}

func TestSnapshotSweepSettlesRowsFromTheHost(t *testing.T) {
	teamID, sandboxID := uuid.New(), uuid.New()
	committed := snapshotFixture(teamID, sandboxID, "creating")
	gone := snapshotFixture(teamID, sandboxID, "creating")
	deleting := snapshotFixture(teamID, sandboxID, "deleting")
	var readied, failed, deleted []uuid.UUID
	mock := &mockDBTX{
		queryFn: func(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
			if strings.Contains(sql, "-- name: ListStuckSandboxSnapshots :many") {
				return &scriptedRows{rows: []*mockRow{sandboxSnapshotRow(committed), sandboxSnapshotRow(gone), sandboxSnapshotRow(deleting)}}, nil
			}
			return nil, fmt.Errorf("unexpected query: %s", sql)
		},
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			if strings.Contains(sql, "-- name: MarkSandboxSnapshotReady :one") {
				id := args[len(args)-1].(uuid.UUID)
				readied = append(readied, id)
				r := committed
				r.ID, r.Status = id, "ready"
				return sandboxSnapshotRow(r)
			}
			return errRow(fmt.Errorf("unexpected query: %s", sql))
		},
		execFn: func(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
			id := args[0].(uuid.UUID)
			switch {
			case strings.Contains(sql, "-- name: MarkSandboxSnapshotFailed :execrows"):
				failed = append(failed, id)
			case strings.Contains(sql, "-- name: MarkSandboxSnapshotDeleted :execrows"):
				deleted = append(deleted, id)
			}
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}
	vmd := &stubVMD{
		createSavedFn: func(_ context.Context, _, snapshotID, kind string) (vmdclient.SavedSnapshot, error) {
			if snapshotID == gone.ID.String() {
				return vmdclient.SavedSnapshot{}, status.Error(codes.NotFound, "vm gone")
			}
			return vmdclient.SavedSnapshot{Kind: kind, DiskPath: "/saved/x/overlay.ext4", SnapshotPath: "/saved/x/vmstate.snap", MemPath: "/saved/x/mem.diff", SizeBytes: 1}, nil
		},
	}
	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	h.SweepSnapshotsOnce(context.Background(), zerolog.Nop())
	if len(readied) != 1 || readied[0] != committed.ID {
		t.Errorf("readied = %v, want only the committed row", readied)
	}
	if len(failed) != 1 || failed[0] != gone.ID {
		t.Errorf("failed = %v, want only the row whose VM is gone", failed)
	}
	if len(deleted) != 1 || deleted[0] != deleting.ID {
		t.Errorf("deleted = %v, want only the deleting row", deleted)
	}
}
