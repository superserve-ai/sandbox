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
	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/db"
)

// A pause that fails after BeginPause — whether at host resolution or at the
// daemon — must compensate: status back to 'active' AND the billing interval
// reopened. The two facts commit as ONE statement (RevertPauseToActive), so
// this test asserts that single query fires with the sandbox's identity; the
// atomicity and status-gating live in the SQL and are covered by the
// integration test.
func TestRevertPauseAsyncRestoresStatusAndInterval(t *testing.T) {
	sandboxID, teamID := uuid.New(), uuid.New()
	var mu sync.Mutex
	var reverted bool
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			if !strings.Contains(sql, "-- name: RevertPauseToActive :one") {
				return errorRow(fmt.Errorf("unexpected QueryRow: %s", sql))
			}
			mu.Lock()
			defer mu.Unlock()
			if args[0] != sandboxID || args[1] != teamID {
				t.Errorf("revert args = %v, %v; want %v, %v", args[0], args[1], sandboxID, teamID)
			}
			reverted = true
			return &mockRow{scanFn: func(dest ...any) error {
				*dest[0].(*int64) = 1
				return nil
			}}
		},
	}
	h := &Handlers{DB: db.New(mock)}

	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("POST", "/sandboxes/x/pause", nil)

	h.revertPauseAsync(c, sandboxID, teamID, zerolog.Nop())

	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		done := reverted
		mu.Unlock()
		if done {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("revert query never fired")
		}
		time.Sleep(2 * time.Millisecond)
	}
}
