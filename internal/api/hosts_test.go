package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/preview"
)

func setupHostHeartbeatRouter(h *Handlers) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/internal/hosts/:host_id/heartbeat", h.HostHeartbeat)
	return r
}

func TestHostHeartbeatReplacesAdvertisedCapabilities(t *testing.T) {
	var gotHostID string
	var gotCapabilities []string
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			if !strings.Contains(sql, "-- name: UpdateHostHeartbeat :one") {
				return errorRow(fmt.Errorf("unexpected QueryRow: %s", sql))
			}
			gotHostID = args[0].(string)
			return hostRow(db.Host{ID: gotHostID, Status: "active"})
		},
		execFn: func(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
			switch {
			case strings.Contains(sql, "-- name: DeleteHostCapabilities :exec"):
				if args[0] != "host-a" {
					t.Errorf("delete host id = %v, want host-a", args[0])
				}
				gotCapabilities = nil
			case strings.Contains(sql, "-- name: InsertHostCapability :exec"):
				if args[1] != "host-a" {
					t.Errorf("insert host id = %v, want host-a", args[1])
				}
				gotCapabilities = append(gotCapabilities, args[0].(string))
			default:
				return pgconn.CommandTag{}, fmt.Errorf("unexpected Exec: %s", sql)
			}
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}
	h := &Handlers{DB: db.New(mock)}
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/internal/hosts/host-a/heartbeat", strings.NewReader(`{"capabilities":["preview_ports_v1"]}`))
	setupHostHeartbeatRouter(h).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if gotHostID != "host-a" {
		t.Fatalf("host id = %q, want host-a", gotHostID)
	}
	if len(gotCapabilities) != 1 || gotCapabilities[0] != preview.HostCapabilityPorts {
		t.Fatalf("capabilities = %#v, want [%q]", gotCapabilities, preview.HostCapabilityPorts)
	}
}

func TestHostHeartbeatWithoutBodyClearsCapabilities(t *testing.T) {
	called := false
	cleared := false
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			if !strings.Contains(sql, "-- name: UpdateHostHeartbeat :one") {
				return errorRow(fmt.Errorf("unexpected QueryRow: %s", sql))
			}
			called = true
			return hostRow(db.Host{ID: args[0].(string), Status: "active"})
		},
		execFn: func(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
			if !strings.Contains(sql, "-- name: DeleteHostCapabilities :exec") {
				return pgconn.CommandTag{}, fmt.Errorf("unexpected Exec: %s", sql)
			}
			if args[0] != "host-old" {
				t.Errorf("delete host id = %v, want host-old", args[0])
			}
			cleared = true
			return pgconn.NewCommandTag("DELETE 1"), nil
		},
	}
	h := &Handlers{DB: db.New(mock)}
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/internal/hosts/host-old/heartbeat", nil)
	setupHostHeartbeatRouter(h).ServeHTTP(w, req)

	if w.Code != http.StatusOK || !called || !cleared {
		t.Fatalf("status = %d called = %v cleared = %v, want 200/true/true; body: %s", w.Code, called, cleared, w.Body.String())
	}
}

func TestHostHeartbeatRejectsMalformedCapabilityBeforeDB(t *testing.T) {
	called := false
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, _ string, _ ...any) pgx.Row {
			called = true
			return errorRow(fmt.Errorf("DB must not be called"))
		},
		execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, fmt.Errorf("unexpected Exec: %s", sql)
		},
	}
	h := &Handlers{DB: db.New(mock)}
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/internal/hosts/host-a/heartbeat", strings.NewReader(`{"capabilities":[""]}`))
	setupHostHeartbeatRouter(h).ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
	if called {
		t.Fatal("invalid heartbeat reached the database")
	}
}

func drainTestMock(t *testing.T, hostStatus string, wantDrain bool) (*mockDBTX, *int32, *int32) {
	t.Helper()
	var windowWrites, drains int32
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			if !strings.Contains(sql, "-- name: UpdateHostHeartbeat :one") {
				return errorRow(fmt.Errorf("unexpected QueryRow: %s", sql))
			}
			return hostRow(db.Host{ID: args[0].(string), Status: hostStatus})
		},
		execFn: func(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
			switch {
			case strings.Contains(sql, "-- name: DeleteHostCapabilities :exec"),
				strings.Contains(sql, "-- name: InsertHostCapability :exec"):
			case strings.Contains(sql, "-- name: UpdateHostMaintenanceWindow :exec"):
				atomic.AddInt32(&windowWrites, 1)
			case strings.Contains(sql, "-- name: DrainHost :execrows"):
				atomic.AddInt32(&drains, 1)
				if !wantDrain {
					t.Error("DrainHost must not run in this scenario")
				}
				return pgconn.NewCommandTag("UPDATE 1"), nil
			default:
				return pgconn.CommandTag{}, fmt.Errorf("unexpected Exec: %s", sql)
			}
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}
	return mock, &windowWrites, &drains
}

func postHeartbeat(t *testing.T, h *Handlers, body string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/internal/hosts/host-a/heartbeat", strings.NewReader(body))
	setupHostHeartbeatRouter(h).ServeHTTP(w, req)
	return w
}

// TestHostHeartbeatDrainsOnImminentMaintenance pins the auto-drain decision:
// an active host reporting a maintenance window inside the lead time flips
// to draining in the same heartbeat.
func TestHostHeartbeatDrainsOnImminentMaintenance(t *testing.T) {
	mock, windowWrites, drains := drainTestMock(t, "active", true)
	h := &Handlers{DB: db.New(mock)}
	soon := time.Now().Add(30 * time.Minute).UTC().Format(time.RFC3339)

	w := postHeartbeat(t, h, `{"maintenance_window_start":"`+soon+`"}`)

	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if *windowWrites != 1 || *drains != 1 {
		t.Fatalf("windowWrites=%d drains=%d, want 1/1", *windowWrites, *drains)
	}
	if !strings.Contains(w.Body.String(), `"draining"`) {
		t.Fatalf("response must report draining, got %s", w.Body.String())
	}
}

// TestHostHeartbeatFarWindowRecordsWithoutDraining pins the late-drain
// policy: a window beyond the lead time is recorded but the host keeps
// serving and taking placement.
func TestHostHeartbeatFarWindowRecordsWithoutDraining(t *testing.T) {
	mock, windowWrites, _ := drainTestMock(t, "active", false)
	h := &Handlers{DB: db.New(mock)}
	far := time.Now().Add(6 * time.Hour).UTC().Format(time.RFC3339)

	w := postHeartbeat(t, h, `{"maintenance_window_start":"`+far+`"}`)

	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if *windowWrites != 1 {
		t.Fatalf("windowWrites=%d, want 1", *windowWrites)
	}
	if !strings.Contains(w.Body.String(), `"active"`) {
		t.Fatalf("response must stay active, got %s", w.Body.String())
	}
}

// TestHostHeartbeatOmittedMaintenanceKeepsState pins the flaky-metadata
// rule: absence means "no change" — no window write, no drain.
func TestHostHeartbeatOmittedMaintenanceKeepsState(t *testing.T) {
	mock, windowWrites, _ := drainTestMock(t, "active", false)
	h := &Handlers{DB: db.New(mock)}

	w := postHeartbeat(t, h, `{"capabilities":[]}`)

	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if *windowWrites != 0 {
		t.Fatalf("windowWrites=%d, want 0 — absence must not touch recorded state", *windowWrites)
	}
}

// TestHostHeartbeatClearRecordsEmptyWindow pins the authoritative clear: an
// empty string means "nothing announced" and nulls the recorded window —
// without un-draining anything (that stays manual).
func TestHostHeartbeatClearRecordsEmptyWindow(t *testing.T) {
	mock, windowWrites, drains := drainTestMock(t, "draining", false)
	h := &Handlers{DB: db.New(mock)}

	w := postHeartbeat(t, h, `{"maintenance_window_start":""}`)

	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if *windowWrites != 1 || *drains != 0 {
		t.Fatalf("windowWrites=%d drains=%d, want 1/0 — clear records but never un-drains", *windowWrites, *drains)
	}
}

func setupDrainRouter(h *Handlers) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/internal/hosts/:host_id/drain", h.DrainHost)
	r.POST("/internal/hosts/:host_id/undrain", h.UndrainHost)
	return r
}

// TestDrainEndpoints pins the operator surface: guarded transitions with a
// 409 when the host is not in the expected source state.
func TestDrainEndpoints(t *testing.T) {
	cases := []struct {
		name     string
		path     string
		affected int64
		wantCode int
	}{
		{"drain active host", "/internal/hosts/host-a/drain", 1, http.StatusOK},
		{"drain non-active host conflicts", "/internal/hosts/host-a/drain", 0, http.StatusConflict},
		{"undrain draining host", "/internal/hosts/host-a/undrain", 1, http.StatusOK},
		{"undrain non-draining host conflicts", "/internal/hosts/host-a/undrain", 0, http.StatusConflict},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mock := &mockDBTX{
				execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
					if !strings.Contains(sql, "-- name: DrainHost :execrows") && !strings.Contains(sql, "-- name: UndrainHost :execrows") {
						return pgconn.CommandTag{}, fmt.Errorf("unexpected Exec: %s", sql)
					}
					return pgconn.NewCommandTag(fmt.Sprintf("UPDATE %d", tc.affected)), nil
				},
			}
			h := &Handlers{DB: db.New(mock)}
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, tc.path, nil)
			setupDrainRouter(h).ServeHTTP(w, req)
			if w.Code != tc.wantCode {
				t.Fatalf("code %d, want %d: %s", w.Code, tc.wantCode, w.Body.String())
			}
		})
	}
}
