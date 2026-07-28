package api

import (
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

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/preview"
)

func setupPreviewRouter(h *Handlers, teamID string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("team_id", teamID)
		c.Next()
	})
	r.GET("/sandboxes/:sandbox_id/preview-ports", h.ListSandboxPreviewPorts)
	r.POST("/sandboxes/:sandbox_id/preview-ports", h.PublishSandboxPreviewPort)
	r.DELETE("/sandboxes/:sandbox_id/preview-ports/:port", h.UnpublishSandboxPreviewPort)
	return r
}

func scalarInt32Row(value int32) pgx.Row {
	return &mockRow{scanFn: func(dest ...any) error {
		*dest[0].(*int32) = value
		return nil
	}}
}

func scalarBoolRow(value bool) pgx.Row {
	return &mockRow{scanFn: func(dest ...any) error {
		*dest[0].(*bool) = value
		return nil
	}}
}

func scalarUUIDRow(value uuid.UUID) pgx.Row {
	return &mockRow{scanFn: func(dest ...any) error {
		*dest[0].(*uuid.UUID) = value
		return nil
	}}
}

func previewPolicyRow(access string, revision int64) pgx.Row {
	return &mockRow{scanFn: func(dest ...any) error {
		*dest[0].(*string) = access
		*dest[1].(*int64) = revision
		return nil
	}}
}

func previewPortRows(ports ...int32) pgx.Rows {
	rows := make([]func(dest ...any) error, 0, len(ports))
	for _, item := range ports {
		port := item
		rows = append(rows, func(dest ...any) error {
			*dest[0].(*int32) = port
			return nil
		})
	}
	return &scanRows{rows: rows}
}

func TestListSandboxPreviewPortsReturnsAuthoritativeAllowlist(t *testing.T) {
	sandboxID, teamID := uuid.New(), uuid.New()
	sandbox := db.Sandbox{
		ID: sandboxID, TeamID: teamID, HostID: "host-a",
	}
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "-- name: GetSandbox :one"):
				return sandboxRow(sandbox)
			case strings.Contains(sql, "-- name: GetSandboxPreviewPolicy :one"):
				return previewPolicyRow(preview.AccessPublic, 7)
			}
			return errorRow(fmt.Errorf("unexpected QueryRow: %s", sql))
		},
		queryFn: func(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
			if strings.Contains(sql, "-- name: ListPublishedPorts :many") {
				return previewPortRows(3000, 8080), nil
			}
			return nil, fmt.Errorf("unexpected Query: %s", sql)
		},
		execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, fmt.Errorf("unexpected Exec: %s", sql)
		},
	}

	h := &Handlers{DB: db.New(mock)}
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sandboxes/"+sandboxID.String()+"/preview-ports", nil)
	setupPreviewRouter(h, teamID.String()).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	var got listPreviewPortsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.PreviewAccess != preview.AccessPublic {
		t.Fatalf("preview_access = %q, want %q", got.PreviewAccess, preview.AccessPublic)
	}
	if len(got.Ports) != 2 || got.Ports[0].Port != 3000 || got.Ports[1].Port != 8080 {
		t.Fatalf("ports = %#v, want [3000, 8080]", got.Ports)
	}
}

func TestPublishPreviewPortRejectsHostWithoutCapabilityBeforeMutation(t *testing.T) {
	sandboxID, teamID := uuid.New(), uuid.New()
	sandbox := db.Sandbox{
		ID: sandboxID, TeamID: teamID, HostID: "host-old",
	}
	mutated := false
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "-- name: GetSandbox :one"):
				return sandboxRow(sandbox)
			case strings.Contains(sql, "-- name: HostHasCapability :one"):
				return scalarBoolRow(false)
			case strings.Contains(sql, "AdvanceSandboxPreviewPolicy"), strings.Contains(sql, "PublishPort"), strings.Contains(sql, "LockSandboxForPreviewMutation"):
				mutated = true
				return errorRow(fmt.Errorf("mutation must not run"))
			default:
				return errorRow(fmt.Errorf("unexpected QueryRow: %s", sql))
			}
		},
		execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			mutated = true
			return pgconn.CommandTag{}, fmt.Errorf("unexpected Exec: %s", sql)
		},
	}
	vmdCalled := false
	h := &Handlers{
		DB: db.New(mock),
		VMD: &stubVMD{updatePreviewFn: func(context.Context, string, string, map[int32]struct{}, int64) error {
			vmdCalled = true
			return nil
		}},
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sandboxes/"+sandboxID.String()+"/preview-ports", strings.NewReader(`{"port":3000}`))
	setupPreviewRouter(h, teamID.String()).ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body: %s", w.Code, w.Body.String())
	}
	if mutated || vmdCalled {
		t.Fatalf("incapable host reached mutation=%v vmd=%v", mutated, vmdCalled)
	}
}

func TestPublishPreviewPortPushesAuthoritativePolicySnapshot(t *testing.T) {
	sandboxID, teamID := uuid.New(), uuid.New()
	sandbox := db.Sandbox{
		ID: sandboxID, TeamID: teamID, HostID: "host-new", Name: "preview",
	}
	activityFinished := make(chan struct{}, 1)
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "-- name: GetSandbox :one"):
				return sandboxRow(sandbox)
			case strings.Contains(sql, "-- name: HostHasCapability :one"):
				return scalarBoolRow(true)
			case strings.Contains(sql, "-- name: LockSandboxForPreviewMutation :one"):
				return scalarUUIDRow(sandboxID)
			case strings.Contains(sql, "-- name: AdvanceSandboxPreviewPolicy :one"):
				return previewPolicyRow(preview.AccessPublic, 11)
			case strings.Contains(sql, "-- name: PublishPort :one"):
				return scalarInt32Row(3000)
			case strings.Contains(sql, "-- name: CreateActivity :one"):
				row := activityRow()
				return &mockRow{scanFn: func(dest ...any) error {
					err := row.Scan(dest...)
					activityFinished <- struct{}{}
					return err
				}}
			default:
				return errorRow(fmt.Errorf("unexpected QueryRow: %s", sql))
			}
		},
		queryFn: func(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
			if strings.Contains(sql, "-- name: ListPublishedPorts :many") {
				return previewPortRows(3000, 8080), nil
			}
			return nil, fmt.Errorf("unexpected Query: %s", sql)
		},
		execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			if strings.Contains(sql, "-- name: EnsureSandboxPreviewPolicy :exec") {
				return pgconn.NewCommandTag("INSERT 0 1"), nil
			}
			return pgconn.CommandTag{}, fmt.Errorf("unexpected Exec: %s", sql)
		},
	}

	pushes := 0
	h := &Handlers{
		DB: db.New(mock),
		VMD: &stubVMD{updatePreviewFn: func(_ context.Context, id, access string, ports map[int32]struct{}, revision int64) error {
			pushes++
			if id != sandboxID.String() || access != preview.AccessPublic || revision != 11 {
				t.Errorf("push = (%q, %q, %d), want (%q, %q, 11)", id, access, revision, sandboxID, preview.AccessPublic)
			}
			if len(ports) != 2 {
				t.Errorf("pushed ports = %#v, want 3000 and 8080", ports)
			}
			if _, ok := ports[3000]; !ok {
				t.Errorf("pushed ports = %#v, missing 3000", ports)
			}
			if _, ok := ports[8080]; !ok {
				t.Errorf("pushed ports = %#v, missing 8080", ports)
			}
			return nil
		}},
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sandboxes/"+sandboxID.String()+"/preview-ports", strings.NewReader(`{"port":3000}`))
	setupPreviewRouter(h, teamID.String()).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if pushes != 1 {
		t.Fatalf("policy pushes = %d, want 1", pushes)
	}
	var body publishedPortResponse
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.Port != 3000 {
		t.Fatalf("response = (%+v, %v), want port 3000", body, err)
	}
	select {
	case <-activityFinished:
	case <-time.After(time.Second):
		t.Fatal("publish activity was not written")
	}
}

func TestPublishPreviewPortUsesStrictRequestShape(t *testing.T) {
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			return errorRow(fmt.Errorf("DB must not be called: %s", sql))
		},
		execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, fmt.Errorf("DB must not be called: %s", sql)
		},
	}
	h := &Handlers{DB: db.New(mock)}
	sandboxID, teamID := uuid.New(), uuid.New()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sandboxes/"+sandboxID.String()+"/preview-ports", strings.NewReader(`{"port":3000,"label":"web"}`))
	setupPreviewRouter(h, teamID.String()).ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
}

func TestPreviewPortMutationsRejectReservedBoxdPortBeforeDB(t *testing.T) {
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			return errorRow(fmt.Errorf("DB must not be called: %s", sql))
		},
		execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, fmt.Errorf("DB must not be called: %s", sql)
		},
	}
	h := &Handlers{DB: db.New(mock)}
	sandboxID, teamID := uuid.New(), uuid.New()
	tests := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{
			name:   "publish",
			method: http.MethodPost,
			path:   "/sandboxes/" + sandboxID.String() + "/preview-ports",
			body:   fmt.Sprintf(`{"port":%d}`, preview.ReservedBoxdPort),
		},
		{
			name:   "unpublish",
			method: http.MethodDelete,
			path:   fmt.Sprintf("/sandboxes/%s/preview-ports/%d", sandboxID, preview.ReservedBoxdPort),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			setupPreviewRouter(h, teamID.String()).ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "reserved") {
				t.Fatalf("body = %q, want reserved-port explanation", w.Body.String())
			}
		})
	}
}

func TestUnpublishPreviewPortRetryRepushesFullAllowlist(t *testing.T) {
	sandboxID, teamID := uuid.New(), uuid.New()
	sandbox := db.Sandbox{
		ID: sandboxID, TeamID: teamID, HostID: "host-a", Name: "preview",
	}
	revision := int64(40)
	deleteCalls := 0
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "-- name: GetSandbox :one"):
				return sandboxRow(sandbox)
			case strings.Contains(sql, "-- name: LockSandboxForPreviewMutation :one"):
				return scalarUUIDRow(sandboxID)
			case strings.Contains(sql, "-- name: AdvanceSandboxPreviewPolicy :one"):
				revision++
				return previewPolicyRow(preview.AccessPublic, revision)
			default:
				return errorRow(fmt.Errorf("unexpected QueryRow: %s", sql))
			}
		},
		queryFn: func(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
			if strings.Contains(sql, "-- name: ListPublishedPorts :many") {
				return previewPortRows(8080), nil
			}
			return nil, fmt.Errorf("unexpected Query: %s", sql)
		},
		execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			if strings.Contains(sql, "-- name: EnsureSandboxPreviewPolicy :exec") {
				return pgconn.NewCommandTag("INSERT 0 1"), nil
			}
			if strings.Contains(sql, "-- name: UnpublishPort :execrows") {
				deleteCalls++
				if deleteCalls == 1 {
					return pgconn.NewCommandTag("DELETE 1"), nil
				}
				return pgconn.NewCommandTag("DELETE 0"), nil
			}
			return pgconn.CommandTag{}, fmt.Errorf("unexpected Exec: %s", sql)
		},
	}

	var pushedRevisions []int64
	h := &Handlers{
		DB: db.New(mock),
		VMD: &stubVMD{updatePreviewFn: func(_ context.Context, id, access string, ports map[int32]struct{}, gotRevision int64) error {
			if id != sandboxID.String() || access != preview.AccessPublic {
				t.Errorf("push target = (%q, %q), want (%q, %q)", id, access, sandboxID, preview.AccessPublic)
			}
			if len(ports) != 1 {
				t.Errorf("pushed ports = %#v, want only 8080", ports)
			} else if _, ok := ports[8080]; !ok {
				t.Errorf("pushed ports = %#v, want only 8080", ports)
			}
			pushedRevisions = append(pushedRevisions, gotRevision)
			if len(pushedRevisions) == 1 {
				return fmt.Errorf("first policy push failed")
			}
			return nil
		}},
	}
	router := setupPreviewRouter(h, teamID.String())
	wantStatuses := []int{http.StatusInternalServerError, http.StatusNoContent}
	for attempt := 0; attempt < 2; attempt++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodDelete, "/sandboxes/"+sandboxID.String()+"/preview-ports/3000", nil)
		router.ServeHTTP(w, req)
		if w.Code != wantStatuses[attempt] {
			t.Fatalf("attempt %d status = %d, want %d; body: %s", attempt+1, w.Code, wantStatuses[attempt], w.Body.String())
		}
	}

	if deleteCalls != 2 {
		t.Fatalf("DELETE calls = %d, want 2", deleteCalls)
	}
	if len(pushedRevisions) != 2 || pushedRevisions[0] != 41 || pushedRevisions[1] != 42 {
		t.Fatalf("pushed revisions = %#v, want [41 42]", pushedRevisions)
	}
}
