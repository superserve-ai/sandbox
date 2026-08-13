package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

func TestHostHeartbeatWrappedErrNoRowsReturns404(t *testing.T) {
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, _ string, _ ...any) pgx.Row {
			return errorRow(fmt.Errorf("query update host heartbeat: %w", pgx.ErrNoRows))
		},
	}
	h := &Handlers{DB: db.New(mock)}
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/internal/hosts/nonexistent-host/heartbeat", nil)
	setupHostHeartbeatRouter(h).ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body: %s", w.Code, w.Body.String())
	}
}
