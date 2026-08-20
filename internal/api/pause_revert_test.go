package api

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/db"
)

// A pause that fails after BeginPause — whether at host resolution or at the
// daemon — must compensate: status back to 'active' AND the billing interval
// reopened. Without both, the sandbox is stuck in 'pausing' and unbilled
// even after the underlying problem is repaired.
func TestRevertPauseAsyncRestoresStatusAndInterval(t *testing.T) {
	var mu sync.Mutex
	var reverted, reopened bool
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			return errorRow(fmt.Errorf("unexpected QueryRow: %s", sql))
		},
		execFn: func(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
			mu.Lock()
			defer mu.Unlock()
			switch {
			case strings.Contains(sql, "-- name: UpdateSandboxStatus :exec"):
				if args[1] != db.SandboxStatusActive {
					t.Errorf("revert status = %v, want active", args[1])
				}
				reverted = true
			case strings.Contains(sql, "-- name: OpenSandboxActiveInterval :exec"):
				reopened = true
			default:
				return pgconn.CommandTag{}, fmt.Errorf("unexpected Exec: %s", sql)
			}
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}
	h := &Handlers{DB: db.New(mock)}

	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("POST", "/sandboxes/x/pause", nil)

	h.revertPauseAsync(c, uuid.New(), uuid.New(), zerolog.Nop())

	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		done := reverted && reopened
		mu.Unlock()
		if done {
			return
		}
		if time.Now().After(deadline) {
			mu.Lock()
			t.Fatalf("revert incomplete: status=%v interval=%v", reverted, reopened)
		}
		time.Sleep(2 * time.Millisecond)
	}
}
