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
)

func setupHostHeartbeatRouter(h *Handlers) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/internal/hosts/:host_id/heartbeat", h.HostHeartbeat)
	return r
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

func TestHostHeartbeatRequiresTransactionPool(t *testing.T) {
	for _, body := range []string{
		"",
		`{"incarnation_id":"0f794b2e-f7a4-46eb-85b4-60f69e6cc831","vmd_addr":"192.0.2.1:50051","proxy_addr":"192.0.2.1:5007","region":"example-region","capacity_memory_mib":1024,"capacity_vcpus":2}`,
	} {
		t.Run(body, func(t *testing.T) {
			mock := &mockDBTX{
				queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
					t.Fatalf("heartbeat without a pool reached QueryRow: %s", sql)
					return nil
				},
				execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
					t.Fatalf("heartbeat without a pool reached Exec: %s", sql)
					return pgconn.CommandTag{}, nil
				},
			}
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/internal/hosts/example-host/heartbeat", strings.NewReader(body))
			setupHostHeartbeatRouter(&Handlers{DB: db.New(mock)}).ServeHTTP(w, req)
			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want 503; body: %s", w.Code, w.Body.String())
			}
		})
	}
}
