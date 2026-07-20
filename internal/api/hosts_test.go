package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/superserve-ai/sandbox/internal/db"
)

// newHeartbeatEnv wires the heartbeat handler over a mock that captures the
// capabilities argument passed to UpdateHostHeartbeat.
func newHeartbeatEnv(t *testing.T) (*gin.Engine, *[]string) {
	t.Helper()
	var gotCaps []string
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			if !strings.Contains(sql, "last_heartbeat_at = now()") {
				t.Fatalf("unexpected query: %s", sql)
			}
			if len(args) >= 2 {
				gotCaps, _ = args[1].([]string)
			}
			return &mockRow{scanFn: func(dest ...any) error {
				*dest[0].(*string) = "host-1"
				*dest[1].(*string) = "vmd:50051"
				*dest[2].(*string) = "proxy:443"
				*dest[3].(*string) = "region"
				*dest[4].(*string) = "active"
				*dest[5].(*int32) = 1
				*dest[6].(*int32) = 1
				*dest[7].(*pgtype.Timestamptz) = pgtype.Timestamptz{Time: time.Now(), Valid: true}
				*dest[8].(*time.Time) = time.Now()
				*dest[9].(*time.Time) = time.Now()
				*dest[10].(*[]string) = gotCaps
				return nil
			}}
		},
	}
	h := &Handlers{DB: db.New(mock)}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/internal/hosts/:host_id/heartbeat", h.HostHeartbeat)
	return r, &gotCaps
}

func heartbeat(r *gin.Engine, body string) *httptest.ResponseRecorder {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(http.MethodPost, "/internal/hosts/host-1/heartbeat", nil)
	} else {
		req = httptest.NewRequest(http.MethodPost, "/internal/hosts/host-1/heartbeat", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestHostHeartbeat_StoresCapabilities(t *testing.T) {
	r, caps := newHeartbeatEnv(t)
	w := heartbeat(r, `{"capabilities": ["preview_ports_v1", "preview_port_tokens_v1"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if len(*caps) != 2 || (*caps)[0] != "preview_ports_v1" || (*caps)[1] != "preview_port_tokens_v1" {
		t.Errorf("stored capabilities = %v", *caps)
	}
}

// An old vmd posts no body; the row's capabilities are REPLACED with the
// empty set — a rolled-back binary must immediately stop qualifying.
func TestHostHeartbeat_EmptyBodyClearsCapabilities(t *testing.T) {
	r, caps := newHeartbeatEnv(t)
	w := heartbeat(r, "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if len(*caps) != 0 {
		t.Errorf("stored capabilities = %v, want empty", *caps)
	}
}

func TestHostHeartbeat_RejectsHostileAdvertisements(t *testing.T) {
	r, _ := newHeartbeatEnv(t)
	tooMany := `{"capabilities": [` + strings.Repeat(`"x",`, 33)[:33*4-1] + `]}`
	huge := `{"capabilities": ["` + strings.Repeat("a", 65) + `"]}`
	for name, body := range map[string]string{
		"too many entries": tooMany,
		"oversized entry":  huge,
		"empty entry":      `{"capabilities": [""]}`,
	} {
		if w := heartbeat(r, body); w.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", name, w.Code)
		}
	}
}
