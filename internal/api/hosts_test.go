package api

import (
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

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/preview"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

func setupHostHeartbeatRouter(h *Handlers) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/internal/hosts/:host_id/heartbeat", h.HostHeartbeat)
	return r
}

func TestHostHeartbeatSyncsAdvertisedCapabilities(t *testing.T) {
	var gotHostID string
	var gotCapabilities []string
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "-- name: GetHostForUpdate :one"):
				return hostRow(db.Host{ID: args[0].(string), Status: "active"})
			case strings.Contains(sql, "-- name: UpdateHostHeartbeat :one"):
				gotHostID = args[0].(string)
				return hostRow(db.Host{ID: gotHostID, Status: "active"})
			default:
				return errorRow(fmt.Errorf("unexpected QueryRow: %s", sql))
			}
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
}

func TestHostHeartbeatWithoutBodyClearsCapabilities(t *testing.T) {
	called := false
	var gotCapabilities []string
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "-- name: GetHostForUpdate :one"):
				return hostRow(db.Host{ID: args[0].(string), Status: "active"})
			case strings.Contains(sql, "-- name: UpdateHostHeartbeat :one"):
				called = true
				return hostRow(db.Host{ID: args[0].(string), Status: "active"})
			default:
				return errorRow(fmt.Errorf("unexpected QueryRow: %s", sql))
			}
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

type fakeHostRegistry struct{ invalidated []string }

func (f *fakeHostRegistry) ClientFor(context.Context, string) (vmdclient.Client, error) {
	return nil, fmt.Errorf("not used in this test")
}
func (f *fakeHostRegistry) Invalidate(hostID string) {
	f.invalidated = append(f.invalidated, hostID)
}
func (f *fakeHostRegistry) MarkVerified(context.Context, string, string, time.Time) {}

// Reclaiming a silent holder's identity rewrites vmd_addr, so the cached
// client for that host id must be evicted — it still dials the old machine
// otherwise. A rejected claim against a live holder must evict nothing.
func TestHostHeartbeatReclaimEvictsCachedClient(t *testing.T) {
	stale := pgtype.Timestamptz{Time: time.Now().Add(-3 * time.Minute), Valid: true}
	fresh := pgtype.Timestamptz{Time: time.Now(), Valid: true}
	full := `{"vmd_addr":"10.0.0.2:50051","proxy_addr":"10.0.0.2:5007",` +
		`"region":"region-a","capacity_memory_mib":1024,"capacity_vcpus":8}`
	partial := `{"vmd_addr":"10.0.0.2:50051","capacity_memory_mib":1024,"capacity_vcpus":8}`

	run := func(t *testing.T, heartbeatAt pgtype.Timestamptz, body string) (int, *fakeHostRegistry) {
		mock := &mockDBTX{
			queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
				switch {
				case strings.Contains(sql, "-- name: GetHostForUpdate :one"):
					return hostRow(db.Host{
						ID: args[0].(string), Status: "active",
						VmdAddr: "10.0.0.1:50051", LastHeartbeatAt: heartbeatAt,
					})
				case strings.Contains(sql, "-- name: UpdateHostHeartbeat :one"):
					return hostRow(db.Host{ID: args[0].(string), Status: "active"})
				default:
					return errorRow(fmt.Errorf("unexpected QueryRow: %s", sql))
				}
			},
			execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
				switch {
				case strings.Contains(sql, "-- name: UpdateHostAddresses :exec"),
					strings.Contains(sql, "-- name: DeleteHostPressure :exec"),
					strings.Contains(sql, "-- name: SyncHostCapabilities :exec"):
					return pgconn.NewCommandTag("UPDATE 1"), nil
				default:
					return pgconn.CommandTag{}, fmt.Errorf("unexpected Exec: %s", sql)
				}
			},
		}
		reg := &fakeHostRegistry{}
		h := &Handlers{DB: db.New(mock), Hosts: reg}
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/internal/hosts/host-a/heartbeat", strings.NewReader(body))
		setupHostHeartbeatRouter(h).ServeHTTP(w, req)
		return w.Code, reg
	}

	if code, reg := run(t, stale, full); code != http.StatusOK ||
		len(reg.invalidated) != 1 || reg.invalidated[0] != "host-a" {
		t.Fatalf("stale reclaim: code = %d invalidated = %v, want 200 [host-a]", code, reg.invalidated)
	}
	if code, reg := run(t, fresh, full); code != http.StatusConflict || len(reg.invalidated) != 0 {
		t.Fatalf("live conflict: code = %d invalidated = %v, want 409 none", code, reg.invalidated)
	}
	// A partial description must not reclaim (it would blank row fields) and
	// must not heartbeat the row either — 400, no writes, no eviction.
	if code, reg := run(t, stale, partial); code != http.StatusBadRequest || len(reg.invalidated) != 0 {
		t.Fatalf("partial claim: code = %d invalidated = %v, want 400 none", code, reg.invalidated)
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
