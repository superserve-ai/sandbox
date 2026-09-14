package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

// Two prompt undecided answers leave the row 'pausing' and reconciling; a
// client that asked for an asynchronous answer is told so, not given a 500.
func TestPauseSandbox_RespondAsync_EarlyUndecidedIsAccepted(t *testing.T) {
	sandboxID, teamID := uuid.New(), uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Name: "sb", Status: db.SandboxStatusActive,
		PauseOpID: pgtype.UUID{Bytes: uuid.New(), Valid: true}, PauseOpLeaseVersion: 1}
	var finalizes int32
	h := &Handlers{DB: db.New(pauseMocks(sb, &finalizes)), VMD: &stubVMD{
		pauseFn: func(context.Context, string, string) (string, string, error) {
			return "", "", status.Error(codes.Unknown, "record paused state failed")
		},
	}}

	req := pauseRequest(sandboxID.String())
	req.Header.Set("Prefer", "respond-async")
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, req)
	h.WaitAsyncBookkeeping()

	if w.Code != http.StatusAccepted || w.Header().Get("Retry-After") != "1" {
		t.Fatalf("undecided pause with async preference = %d %s; want 202 pausing", w.Code, w.Body.String())
	}
}

// The recovery attempt goes to whoever serves the host now: the machine the
// first attempt reached may have been replaced in between.
func TestPauseSandbox_RecoveryResolvesTheReplacementHost(t *testing.T) {
	sandboxID, teamID := uuid.New(), uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, HostID: "host-1", Name: "sb", Status: db.SandboxStatusActive,
		PauseOpID: pgtype.UUID{Bytes: uuid.New(), Valid: true}, PauseOpLeaseVersion: 1}
	var oldCalls, newCalls, resolves atomic.Int32
	old := &stubVMD{pauseFn: func(context.Context, string, string) (string, string, error) {
		if oldCalls.Add(1) == 1 {
			return "", "", status.Error(codes.Unavailable, "host address replaced")
		}
		return "", "", status.Error(codes.NotFound, "old host has no VM")
	}}
	current := &stubVMD{pauseFn: func(context.Context, string, string) (string, string, error) {
		newCalls.Add(1)
		return "/snapshots/vmstate.snap", "/snapshots/mem.snap", nil
	}}
	var finalizes int32
	h := &Handlers{DB: db.New(pauseMocks(sb, &finalizes)), Hosts: &stubHosts{
		resolve: func() (vmdclient.Client, error) {
			if resolves.Add(1) == 1 {
				return old, nil
			}
			return current, nil
		},
	}}

	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, pauseRequest(sandboxID.String()))
	h.WaitAsyncBookkeeping()

	if w.Code != http.StatusNoContent || oldCalls.Load() != 1 || newCalls.Load() != 1 {
		t.Fatalf("pause = %d, old host calls = %d, replacement calls = %d; want 204 with the retry on the replacement",
			w.Code, oldCalls.Load(), newCalls.Load())
	}
}

// When the host cannot be resolved for the retry, the old client is not a
// fallback: its answer would be about a machine the host no longer maps to.
func TestPauseWithRetry_UnresolvedHostDoesNotRetryTheOldClient(t *testing.T) {
	var oldCalls atomic.Int32
	old := &stubVMD{pauseFn: func(context.Context, string, string) (string, string, error) {
		if oldCalls.Add(1) == 1 {
			return "", "", status.Error(codes.Unavailable, "old host disconnected")
		}
		return "", "", status.Error(codes.NotFound, "old machine no longer has this sandbox")
	}}
	h := &Handlers{Hosts: &stubHosts{resolve: func() (vmdclient.Client, error) {
		return nil, errors.New("cannot verify current host address")
	}}}

	_, _, _, _, err := h.pauseWithRetry(context.Background(), old, "host-1", uuid.NewString(), uuid.NewString(), time.Now().Add(time.Minute))

	if oldCalls.Load() != 1 || err == nil || isVMDNotFound(err) {
		t.Fatalf("unresolved retry: old client calls = %d, err = %v; want one call and an undecided error", oldCalls.Load(), err)
	}
}

// A claim can already have expired by the time its row comes back (a delayed
// query, a suspended process); nothing is sent to the host on it.
func TestPauseSandbox_ExpiredClaimDoesNotDispatch(t *testing.T) {
	sandboxID, teamID := uuid.New(), uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Name: "sb", Status: db.SandboxStatusActive,
		PauseOpID: pgtype.UUID{Bytes: uuid.New(), Valid: true}, PauseOpLeaseVersion: 1,
		PauseOpLeaseUntil: pgtype.Timestamptz{Time: time.Now().Add(-time.Second), Valid: true}}
	var calls atomic.Int32
	var finalizes int32
	h := &Handlers{DB: db.New(pauseMocks(sb, &finalizes)), VMD: &stubVMD{
		pauseFn: func(context.Context, string, string) (string, string, error) {
			calls.Add(1)
			return "/snapshots/vmstate.snap", "/snapshots/mem.snap", nil
		},
	}}

	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, pauseRequest(sandboxID.String()))
	h.WaitAsyncBookkeeping()

	if calls.Load() != 0 {
		t.Fatalf("foreground sent %d pause RPCs on an expired claim", calls.Load())
	}
}

// The success entry for a pause is written when the row says paused, not
// when the host answers: a finalize the reconciler must redo would otherwise
// leave two entries for one pause.
func TestPauseSandbox_NoPausedActivityUntilFinalized(t *testing.T) {
	for _, tc := range []struct {
		name         string
		finalizeErr  error
		landed       bool // the row reads paused despite the error: the reply was lost after commit
		wantActivity int32
	}{
		{name: "finalize succeeds", wantActivity: 1},
		{name: "finalize fails", finalizeErr: errors.New("db unavailable"), wantActivity: 0},
		{name: "finalize reply lost after commit", finalizeErr: errors.New("connection reset"), landed: true, wantActivity: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sandboxID, teamID := uuid.New(), uuid.New()
			sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Name: "sb", Status: db.SandboxStatusActive,
				PauseOpID: pgtype.UUID{Bytes: uuid.New(), Valid: true}, PauseOpLeaseVersion: 1}
			var activities int32
			mock := &mockDBTX{
				queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
					switch {
					case strings.Contains(sql, "-- name: CreateActivity "):
						atomic.AddInt32(&activities, 1)
						return activityRow()
					case strings.Contains(sql, "upserted AS"), strings.Contains(sql, "INSERT INTO snapshot"):
						if tc.finalizeErr != nil {
							return errorRow(tc.finalizeErr)
						}
						return finalizePauseRow(uuid.New())
					case strings.Contains(sql, "-- name: GetSandbox :one") && tc.landed:
						paused := sb
						paused.Status = db.SandboxStatusPaused
						paused.PauseOpID = pgtype.UUID{}
						return sandboxRow(paused)
					case strings.Contains(sql, "'pausing'"), strings.Contains(sql, "FROM sandbox"):
						return sandboxRow(sb)
					}
					return activityRow()
				},
				execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
					return pgconn.NewCommandTag("UPDATE 1"), nil
				},
			}
			h := &Handlers{VMD: &stubVMD{}, DB: db.New(mock)}

			w := httptest.NewRecorder()
			setupTestRouter(h, teamID.String()).ServeHTTP(w, pauseRequest(sandboxID.String()))
			h.WaitAsyncBookkeeping()

			if w.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusNoContent)
			}
			// The activity write runs on its own goroutine; give it a moment
			// either way so an absent entry is a decision, not a race.
			for deadline := time.Now().Add(300 * time.Millisecond); time.Now().Before(deadline) && atomic.LoadInt32(&activities) != tc.wantActivity; {
				time.Sleep(5 * time.Millisecond)
			}
			if got := atomic.LoadInt32(&activities); got != tc.wantActivity {
				t.Fatalf("paused activity entries = %d, want %d", got, tc.wantActivity)
			}
		})
	}
}

func TestPauseWithRetry_FailedPreconditionIsNotRetried(t *testing.T) {
	calls := 0
	vmd := &stubVMD{pauseFn: func(context.Context, string, string) (string, string, error) {
		calls++
		return "", "", status.Error(codes.FailedPrecondition, "vm is in error state and cannot be paused")
	}}
	_, _, _, _, err := (&Handlers{VMD: vmd}).pauseWithRetry(context.Background(), vmd, "host-1", "vm-1", "tok", time.Now().Add(time.Minute))
	if !isVMDFailedPrecondition(err) || calls != 1 {
		t.Fatalf("calls = %d, err = %v; want one attempt and the precondition surfaced", calls, err)
	}
}
