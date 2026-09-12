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

// A client that prefers an asynchronous answer is told 'pausing' before the
// host is even resolved; when resolution then fails, the revert still lands
// in the background.
func TestPauseSandbox_RespondAsync_UnresolvedHostRevertsInTheBackground(t *testing.T) {
	sandboxID, teamID := uuid.New(), uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, HostID: "host-1", Name: "sb", Status: db.SandboxStatusActive,
		PauseOpID: pgtype.UUID{Bytes: uuid.New(), Valid: true}, PauseOpLeaseVersion: 1}
	var reverted bool
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "-- name: RevertPauseToActive :one"):
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
	resolved := make(chan struct{})
	h := &Handlers{DB: db.New(mock), Hosts: &stubHosts{resolve: func() (vmdclient.Client, error) {
		close(resolved)
		return nil, errors.New("host not registered")
	}}}

	req := pauseRequest(sandboxID.String())
	req.Header.Set("Prefer", "respond-async")
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusAccepted, w.Body.String())
	}
	h.WaitAsyncBookkeeping()
	select {
	case <-resolved:
	default:
		t.Fatal("host was never resolved by the detached dispatch")
	}
	if !reverted {
		t.Fatal("unresolved host did not revert the operation")
	}
}

// A transient failure of the revert write is retried rather than left as a
// pending operation for the reconciler to turn into a pause.
func TestRevertPause_RetriesATransientFailure(t *testing.T) {
	sandboxID, teamID := uuid.New(), uuid.New()
	lease := pauseLease{id: pgtype.UUID{Bytes: uuid.New(), Valid: true}, version: 1}
	attempts := 0
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if !strings.Contains(sql, "-- name: RevertPauseToActive :one") {
				return errorRow(fmt.Errorf("unexpected QueryRow: %s", sql))
			}
			attempts++
			if attempts == 1 {
				return errorRow(errors.New("connection reset"))
			}
			return &mockRow{scanFn: func(dest ...any) error {
				*dest[0].(*int64) = 1
				return nil
			}}
		},
	}
	h := &Handlers{DB: db.New(mock)}

	if !h.revertPause(context.Background(), sandboxID, teamID, lease, nil, zerolog.Nop()) {
		t.Fatal("revert reported as not landed after a successful retry")
	}

	if attempts != 2 {
		t.Fatalf("revert attempts = %d, want a retry after the transient failure", attempts)
	}
}

// When the revert cannot be written at all the claim stands and the
// reconciler will pause the VM, so the caller hears 'pausing', not "failed".
func TestPauseSandbox_UnresolvedHostWithUnwritableRevertAnswersPausing(t *testing.T) {
	sandboxID, teamID := uuid.New(), uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, HostID: "host-1", Name: "sb", Status: db.SandboxStatusActive,
		PauseOpID: pgtype.UUID{Bytes: uuid.New(), Valid: true}, PauseOpLeaseVersion: 1}
	attempts := 0
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "-- name: RevertPauseToActive :one"):
				attempts++
				return errorRow(errors.New("connection reset"))
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

	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusAccepted, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"pausing"`) {
		t.Fatalf("body = %s, want status pausing", w.Body.String())
	}
	if attempts != 3 {
		t.Fatalf("revert attempts = %d, want 3 before giving up", attempts)
	}
}
