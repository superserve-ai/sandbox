package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
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
		if len(dest) != 28 {
			return fmt.Errorf("sandbox_snapshot scan wants 28 columns, got %d", len(dest))
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
		*dest[27].(*pgtype.Timestamptz) = s.SweepAfter
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
	keyOnFile := false
	inserts, loadedSandbox := 0, 0
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "-- name: GetSandbox :one"):
				loadedSandbox++
				return sandboxRow(sb)
			case strings.Contains(sql, "-- name: CreateSandboxSnapshot :one"):
				inserts++
				if pe, ok := insertErr.(*pgconn.PgError); ok && pe.Code == "23505" {
					keyOnFile = true
				}
				return errRow(insertErr)
			case strings.Contains(sql, "-- name: GetSandboxSnapshotByIdempotencyKey :one"):
				if !keyOnFile {
					return errRow(pgx.ErrNoRows)
				}
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
	post := func(body map[string]any) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, jsonReq(http.MethodPost, "/sandboxes/"+sandboxID.String()+"/snapshot", body))
		return w
	}
	errCode := func(w *httptest.ResponseRecorder) string {
		return parseJSON(t, w)["error"].(map[string]any)["code"].(string)
	}

	// The limits are the trigger's verdict, one code each.
	if w := post(map[string]any{"kind": "fs"}); w.Code != http.StatusTooManyRequests || errCode(w) != "too_many_snapshots" {
		t.Fatalf("quota: status=%d body=%s", w.Code, w.Body.String())
	}
	insertErr = &pgconn.PgError{Code: snapshotInFlightErrCode, Message: "snapshots in flight limit reached"}
	if w := post(map[string]any{"kind": "fs"}); w.Code != http.StatusTooManyRequests || errCode(w) != "too_many_snapshots_in_flight" {
		t.Fatalf("in flight: status=%d body=%s", w.Code, w.Body.String())
	}

	// Two first requests with one key: the loser re-reads the winner's row.
	insertErr = &pgconn.PgError{Code: "23505", ConstraintName: "sandbox_snapshot_idempotency"}
	if w := post(map[string]any{"kind": "mem+fs", "idempotency_key": key}); w.Code != http.StatusOK || parseJSON(t, w)["id"] != existing.ID.String() {
		t.Fatalf("replay after a lost race: status=%d body=%s", w.Code, w.Body.String())
	}

	// A key on file is answered before the source or the limits are looked
	// at: the same replay works with the team at its limits and the source
	// gone, and never inserts or captures.
	insertErr, loadedSandbox, inserts = &pgconn.PgError{Code: snapshotInFlightErrCode}, 0, 0
	sb.Status = db.SandboxStatusDeleted
	if w := post(map[string]any{"kind": "mem+fs", "idempotency_key": key}); w.Code != http.StatusOK || parseJSON(t, w)["id"] != existing.ID.String() {
		t.Fatalf("replay: status=%d body=%s", w.Code, w.Body.String())
	}
	if loadedSandbox != 0 || inserts != 0 {
		t.Fatalf("replay loaded the sandbox %d time(s) and inserted %d time(s); want neither", loadedSandbox, inserts)
	}
	existing.Status, existing.DeletedAt = "deleting", pgtype.Timestamptz{Time: time.Now(), Valid: true}
	if w := post(map[string]any{"kind": "mem+fs", "idempotency_key": key}); w.Code != http.StatusGone || errCode(w) != "gone" {
		t.Fatalf("replay of a deleted snapshot: status=%d body=%s; want 410", w.Code, w.Body.String())
	}
	if captured != 0 {
		t.Fatalf("the host was asked %d time(s); a refused insert or a replay must never capture", captured)
	}
}

func TestCreateSandboxSnapshotLeavesALostAnswerToTheSweep(t *testing.T) {
	teamID, sandboxID := uuid.New(), uuid.New()
	base := "/base.ext4"
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Status: db.SandboxStatusActive, HostID: "host-1", BasePath: &base, VcpuCount: 1, MemoryMib: 1024, DiskMib: 4096}
	failed, released := false, false
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "-- name: GetSandbox :one"):
				return sandboxRow(sb)
			case strings.Contains(sql, "-- name: CreateSandboxSnapshot :one"):
				row := snapshotFixture(teamID, sandboxID, "creating")
				row.ID = args[0].(uuid.UUID)
				return sandboxSnapshotRow(row)
			}
			return errRow(fmt.Errorf("unexpected query: %s", sql))
		},
		execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			switch {
			case strings.Contains(sql, "-- name: MarkSandboxSnapshotFailed :execrows"):
				failed = true
			case strings.Contains(sql, "-- name: ScheduleSandboxSnapshotSweep :execrows"):
				released = true
			}
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}
	hostCleaned := false
	vmd := &stubVMD{
		createSavedFn: func(context.Context, string, string, string) (vmdclient.SavedSnapshot, error) {
			return vmdclient.SavedSnapshot{}, status.Error(codes.Unavailable, "connection reset while the capture ran")
		},
		deleteSavedFn: func(context.Context, string) error { hostCleaned = true; return nil },
	}
	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	snapshotRouter(h, teamID).ServeHTTP(w, jsonReq(http.MethodPost, "/sandboxes/"+sandboxID.String()+"/snapshot", nil))
	if w.Code != http.StatusAccepted || parseJSON(t, w)["status"] != "creating" || w.Header().Get("Retry-After") == "" {
		t.Fatalf("status=%d retry-after=%q body=%s; want 202 with the row still creating", w.Code, w.Header().Get("Retry-After"), w.Body.String())
	}
	if failed || hostCleaned || !released {
		t.Fatalf("failed=%v hostCleaned=%v released=%v; a lost answer must destroy nothing and hand the row to the sweep", failed, hostCleaned, released)
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

	// A host that does not answer costs the caller the inline budget, not
	// the host timeout.
	hostErr = nil
	h.TeardownInlineBudget = 50 * time.Millisecond
	vmd.deleteSavedFn = func(ctx context.Context, _ string) error { <-ctx.Done(); return ctx.Err() }
	start := time.Now()
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/snapshots/"+row.ID.String(), nil))
	if w.Code != http.StatusAccepted || deleted != 1 || time.Since(start) > 5*time.Second {
		t.Fatalf("host hung: status=%d deleted=%d after %s; want 202 within the inline budget", w.Code, deleted, time.Since(start))
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
	lost := snapshotFixture(teamID, sandboxID, "creating")
	deleting := snapshotFixture(teamID, sandboxID, "deleting")
	var readied, failed, deleted []uuid.UUID
	var mu sync.Mutex
	mock := &mockDBTX{
		queryFn: func(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
			if strings.Contains(sql, "-- name: ClaimStuckSandboxSnapshots :many") {
				return &scriptedRows{rows: []*mockRow{sandboxSnapshotRow(committed), sandboxSnapshotRow(gone), sandboxSnapshotRow(lost), sandboxSnapshotRow(deleting)}}, nil
			}
			return nil, fmt.Errorf("unexpected query: %s", sql)
		},
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			mu.Lock()
			defer mu.Unlock()
			switch {
			case strings.Contains(sql, "-- name: MarkSandboxSnapshotReady :one"):
				id := args[len(args)-1].(uuid.UUID)
				readied = append(readied, id)
				r := committed
				r.ID, r.Status = id, "ready"
				return sandboxSnapshotRow(r)
			}
			return errRow(fmt.Errorf("unexpected query: %s", sql))
		},
		execFn: func(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
			mu.Lock()
			defer mu.Unlock()
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
	var hostDeleted []string
	vmd := &stubVMD{
		createSavedFn: func(_ context.Context, _, snapshotID, kind string) (vmdclient.SavedSnapshot, error) {
			switch snapshotID {
			case gone.ID.String():
				return vmdclient.SavedSnapshot{}, status.Error(codes.NotFound, "vm gone")
			case lost.ID.String():
				return vmdclient.SavedSnapshot{}, status.Error(codes.Unavailable, "host restarting")
			}
			return vmdclient.SavedSnapshot{Kind: kind, DiskPath: "/saved/x/overlay.ext4", SnapshotPath: "/saved/x/vmstate.snap", MemPath: "/saved/x/mem.diff", SizeBytes: 1}, nil
		},
		deleteSavedFn: func(_ context.Context, id string) error {
			mu.Lock()
			defer mu.Unlock()
			hostDeleted = append(hostDeleted, id)
			return nil
		},
	}
	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	<-h.SweepSnapshotsOnce(context.Background(), zerolog.Nop())
	if len(readied) != 1 || readied[0] != committed.ID {
		t.Errorf("readied = %v, want only the committed row", readied)
	}
	if len(failed) != 1 || failed[0] != gone.ID {
		t.Errorf("failed = %v, want only the row whose VM is gone; a lost answer stays creating", failed)
	}
	if len(deleted) != 1 || deleted[0] != deleting.ID {
		t.Errorf("deleted = %v, want only the deleting row", deleted)
	}
	want := map[string]bool{gone.ID.String(): true, deleting.ID.String(): true}
	if len(hostDeleted) != len(want) {
		t.Fatalf("host deletes = %v; want the refused row's leftovers and the deleting row", hostDeleted)
	}
	for _, id := range hostDeleted {
		if !want[id] {
			t.Errorf("host delete of %s; want only %v", id, want)
		}
	}
}

func TestSnapshotSweepNeverWaitsOnAHost(t *testing.T) {
	teamID, sandboxID := uuid.New(), uuid.New()
	stuck := snapshotFixture(teamID, sandboxID, "creating")
	stuck.HostID = "host-hung"
	other := snapshotFixture(teamID, sandboxID, "deleting")
	other.HostID = "host-fine"
	// The first pass claims only the row on the host that never answers;
	// the next claims it again, its retry time past, with another host's row.
	passes := [][]*mockRow{
		{sandboxSnapshotRow(stuck)},
		{sandboxSnapshotRow(stuck), sandboxSnapshotRow(other)},
	}
	mock := &mockDBTX{
		queryFn: func(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
			if strings.Contains(sql, "-- name: ClaimStuckSandboxSnapshots :many") {
				rows := passes[0]
				passes = passes[1:]
				return &scriptedRows{rows: rows}, nil
			}
			return nil, fmt.Errorf("unexpected query: %s", sql)
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}
	release := make(chan struct{})
	settled := make(chan struct{})
	var captures atomic.Int32
	vmd := &stubVMD{
		createSavedFn: func(ctx context.Context, _, _, _ string) (vmdclient.SavedSnapshot, error) {
			captures.Add(1)
			select {
			case <-release:
			case <-ctx.Done():
			}
			return vmdclient.SavedSnapshot{}, status.Error(codes.Unavailable, "never answered")
		},
		deleteSavedFn: func(context.Context, string) error { close(settled); return nil },
	}
	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	first := h.SweepSnapshotsOnce(context.Background(), zerolog.Nop())
	second := h.SweepSnapshotsOnce(context.Background(), zerolog.Nop())
	select {
	case <-settled:
	case <-time.After(5 * time.Second):
		t.Fatal("the other host's delete waited behind a host that does not answer")
	}
	select {
	case <-second:
	case <-time.After(5 * time.Second):
		t.Fatal("a pass waited on the host that does not answer")
	}
	select {
	case <-first:
		t.Fatal("the first pass finished while its capture was still held by the host")
	default:
	}
	close(release)
	<-first
	if n := captures.Load(); n != 1 {
		t.Fatalf("the held row was captured %d times; a row in flight is not doubled", n)
	}
}
