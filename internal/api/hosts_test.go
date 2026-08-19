package api

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/preview"
)

func setupHostHeartbeatRouter(h *Handlers) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/internal/hosts/:host_id/heartbeat", h.HostHeartbeat)
	return r
}

func TestHostHeartbeatSyncsAdvertisedCapabilities(t *testing.T) {
	var logOutput bytes.Buffer
	oldLogger := log.Logger
	log.Logger = zerolog.New(&logOutput)
	defer func() { log.Logger = oldLogger }()
	var gotHostID string
	var gotCapabilities []string
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			if !strings.Contains(sql, "-- name: UpdateHostHeartbeat :one") {
				return errorRow(fmt.Errorf("unexpected QueryRow: %s", sql))
			}
			gotHostID = args[0].(string)
			return hostRow(db.Host{
				ID:              gotHostID,
				Status:          "active",
				LastHeartbeatAt: pgtype.Timestamptz{Time: time.Date(2026, 8, 20, 2, 0, 0, 0, time.UTC), Valid: true},
			})
		},
		execFn: func(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
			if !strings.Contains(sql, "-- name: SyncHostCapabilities :exec") {
				return pgconn.CommandTag{}, fmt.Errorf("unexpected Exec: %s", sql)
			}
			if args[0] != "host-a" {
				t.Errorf("sync host id = %v, want host-a", args[0])
			}
			gotCapabilities = append(gotCapabilities, args[1].([]string)...)
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
	if !bytes.Contains(logOutput.Bytes(), []byte(`"message":"host heartbeat persisted"`)) ||
		!bytes.Contains(logOutput.Bytes(), []byte(`"host_id":"host-a"`)) ||
		!bytes.Contains(logOutput.Bytes(), []byte(`"capabilities":["preview_ports_v1"]`)) ||
		!bytes.Contains(logOutput.Bytes(), []byte(`"last_heartbeat_at":"2026-08-20T02:00:00Z"`)) {
		t.Fatalf("heartbeat persistence diagnostics=%s, want host, capabilities, and formatted generation", logOutput.String())
	}
}

func TestHostHeartbeatWithoutBodyClearsCapabilities(t *testing.T) {
	called := false
	var gotCapabilities []string
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			if !strings.Contains(sql, "-- name: UpdateHostHeartbeat :one") {
				return errorRow(fmt.Errorf("unexpected QueryRow: %s", sql))
			}
			called = true
			return hostRow(db.Host{ID: args[0].(string), Status: "active"})
		},
		execFn: func(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
			if !strings.Contains(sql, "-- name: SyncHostCapabilities :exec") {
				return pgconn.CommandTag{}, fmt.Errorf("unexpected Exec: %s", sql)
			}
			if args[0] != "host-old" {
				t.Errorf("sync host id = %v, want host-old", args[0])
			}
			gotCapabilities = args[1].([]string)
			return pgconn.NewCommandTag("DELETE 1"), nil
		},
	}
	h := &Handlers{DB: db.New(mock)}
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/internal/hosts/host-old/heartbeat", nil)
	setupHostHeartbeatRouter(h).ServeHTTP(w, req)

	if w.Code != http.StatusOK || !called || gotCapabilities == nil || len(gotCapabilities) != 0 {
		t.Fatalf("status = %d called = %v capabilities = %#v, want 200/true/empty; body: %s", w.Code, called, gotCapabilities, w.Body.String())
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
