package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

// A pause that fails before anything is dispatched compensates in ONE fenced
// statement (RevertPauseToActive): status back to 'active' and the billing
// interval reopened, so a failure between the two facts is unrepresentable.
func TestRevertPause_RestoresStatusAndIntervalUnderTheLease(t *testing.T) {
	sandboxID, teamID := uuid.New(), uuid.New()
	lease := pauseLease{id: pgtype.UUID{Bytes: uuid.New(), Valid: true}, version: 3}
	var reverted bool
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			if !strings.Contains(sql, "-- name: RevertPauseToActive :one") {
				return errorRow(fmt.Errorf("unexpected QueryRow: %s", sql))
			}
			if args[0] != sandboxID || args[1] != teamID || args[2] != lease.id || *(args[3].(*int64)) != lease.version {
				t.Errorf("revert args = %v; want the sandbox, team, and the lease it holds", args)
			}
			reverted = true
			return &mockRow{scanFn: func(dest ...any) error {
				*dest[0].(*int64) = 1
				return nil
			}}
		},
	}
	h := &Handlers{DB: db.New(mock)}

	h.revertPause(context.Background(), sandboxID, teamID, lease, nil, zerolog.Nop())

	if !reverted {
		t.Fatal("revert query never fired")
	}
}

// When the host cannot be resolved the operation is undone before the
// request is answered: the caller hears "failed" about a row that is already
// 'active' again, and nothing is left for the reconciler to pick up.
func TestPauseSandbox_UnresolvedHostRevertsBeforeResponding(t *testing.T) {
	sandboxID, teamID := uuid.New(), uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, HostID: "host-1", Name: "sb", Status: db.SandboxStatusActive,
		PauseOpID: pgtype.UUID{Bytes: uuid.New(), Valid: true}, PauseOpLeaseVersion: 1}
	var reverted bool
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "-- name: RevertPauseToActive :one"):
				if args[2] != sb.PauseOpID || *(args[3].(*int64)) != sb.PauseOpLeaseVersion {
					t.Errorf("revert args = %v; want the lease BeginPause minted", args)
				}
				reverted = true
				return &mockRow{scanFn: func(dest ...any) error {
					*dest[0].(*int64) = 1
					return nil
				}}
			case strings.Contains(sql, "'pausing'"), strings.Contains(sql, "FROM sandbox"):
				return sandboxRow(sb)
			}
			return activityRow()
		},
	}
	h := &Handlers{DB: db.New(mock), Hosts: &stubHosts{resolve: func() (vmdclient.Client, error) {
		return nil, errors.New("host not registered")
	}}}

	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, pauseRequest(sandboxID.String()))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
	if !reverted {
		t.Fatal("responded before the operation was reverted")
	}
}
