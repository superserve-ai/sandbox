package api

import (
	"context"
	"errors"
	"fmt"
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
	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/telemetry"
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
// host is even resolved. It was promised paused or failed, so when resolution
// then fails the claim is not reverted: its lease is handed back and the
// reconciler resolves the host again.
func TestPauseSandbox_RespondAsync_UnresolvedHostLeavesPausing(t *testing.T) {
	sandboxID, teamID := uuid.New(), uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, HostID: "host-1", Name: "sb", Status: db.SandboxStatusActive,
		PauseOpID: pgtype.UUID{Bytes: uuid.New(), Valid: true}, PauseOpLeaseVersion: 1}
	var reverted bool
	var releases int32
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
		execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			if strings.Contains(sql, "-- name: ReleasePauseLease ") {
				atomic.AddInt32(&releases, 1)
			}
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}
	resolved := make(chan struct{})
	h := &Handlers{DB: db.New(mock), Hosts: &stubHosts{resolve: func() (vmdclient.Client, error) {
		close(resolved)
		return nil, errors.New("host not registered")
	}}}
	rec := &captureTelemetryRecorder{}
	SetTelemetryRecorder(rec)
	t.Cleanup(func() { SetTelemetryRecorder(nil) })

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
	if reverted || atomic.LoadInt32(&releases) != 1 {
		t.Fatalf("reverted = %v, releases = %d; want the accepted claim kept and its lease handed back", reverted, releases)
	}
	if len(rec.transitions) != 1 || rec.transitions[0].Operation != "pause" || rec.transitions[0].Result != telemetry.ResultTimeout {
		t.Fatalf("transitions = %+v, want the detached dispatch recorded as a pause timeout", rec.transitions)
	}
}

// A transient failure of the revert write is retried rather than left as a
// pending operation for the reconciler to turn into a pause.
func TestRevertPause_RetriesATransientFailure(t *testing.T) {
	sandboxID, teamID := uuid.New(), uuid.New()
	lease := pauseLease{id: pgtype.UUID{Bytes: uuid.New(), Valid: true}, version: 1}
	attempts := 0
	var deadlines []time.Time
	mock := &mockDBTX{
		queryRowFn: func(ctx context.Context, sql string, _ ...any) pgx.Row {
			if !strings.Contains(sql, "-- name: RevertPauseToActive :one") {
				return errorRow(fmt.Errorf("unexpected QueryRow: %s", sql))
			}
			attempts++
			deadline, ok := ctx.Deadline()
			if !ok {
				t.Error("revert attempt carries no deadline")
			}
			deadlines = append(deadlines, deadline)
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
	// On the synchronous path the retries run inside the request, so they
	// share one deadline rather than each starting a fresh one.
	if !deadlines[1].Equal(deadlines[0]) {
		t.Fatalf("retry deadline %v differs from the first attempt's %v; want one shared deadline", deadlines[1], deadlines[0])
	}
}

// A database that never answers holds the revert for one timeout in total,
// not one per attempt.
func TestRevertPause_UnansweredDatabaseHoldsForOneTimeout(t *testing.T) {
	sandboxID, teamID := uuid.New(), uuid.New()
	lease := pauseLease{id: pgtype.UUID{Bytes: uuid.New(), Valid: true}, version: 1}
	mock := &mockDBTX{
		queryRowFn: func(ctx context.Context, _ string, _ ...any) pgx.Row {
			<-ctx.Done()
			return errorRow(ctx.Err())
		},
	}
	h := &Handlers{DB: db.New(mock)}

	started := time.Now()
	if h.revertPause(context.Background(), sandboxID, teamID, lease, nil, zerolog.Nop()) {
		t.Fatal("revert reported as landed with a database that never answered")
	}
	if held := time.Since(started); held > asyncTimeout+time.Second {
		t.Fatalf("revert held the caller for %v; want about one timeout of %v", held, asyncTimeout)
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

// A BeginPause whose reply was lost after it committed has still claimed the
// row under this request's operation id: the pause goes on to the host, not
// to a 500 that the reconciler later contradicts. A claim that did not land
// is a plain failure.
func TestPauseSandbox_LostClaimReplyIsConfirmedFromTheRow(t *testing.T) {
	for _, tc := range []struct {
		name       string
		landed     bool
		late       bool // the reply came back only after the minted lease could have expired
		wantCode   int
		wantPauses int32
	}{
		{name: "claim committed", landed: true, wantCode: http.StatusNoContent, wantPauses: 1},
		{name: "claim did not land", landed: false, wantCode: http.StatusInternalServerError, wantPauses: 0},
		{name: "claim committed but the reply outlived the lease", landed: true, late: true, wantCode: http.StatusAccepted, wantPauses: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.late {
				window := pauseClaimConfirmWindow
				pauseClaimConfirmWindow = time.Millisecond
				t.Cleanup(func() { pauseClaimConfirmWindow = window })
			}
			sandboxID, teamID := uuid.New(), uuid.New()
			active := db.Sandbox{ID: sandboxID, TeamID: teamID, Name: "sb", Status: db.SandboxStatusActive}
			var minted pgtype.UUID
			var pauses, finalizes int32
			mock := &mockDBTX{
				queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
					switch {
					case strings.Contains(sql, "upserted AS"), strings.Contains(sql, "INSERT INTO snapshot"):
						atomic.AddInt32(&finalizes, 1)
						return finalizePauseRow(uuid.New())
					case strings.Contains(sql, "-- name: GetSandbox :one"):
						if !tc.landed {
							return sandboxRow(active)
						}
						claimed := active
						claimed.Status = db.SandboxStatusPausing
						claimed.PauseOpID = minted
						claimed.PauseOpLeaseVersion = 1
						return sandboxRow(claimed)
					case strings.Contains(sql, "'pausing'"):
						for _, a := range args {
							if id, ok := a.(pgtype.UUID); ok && id.Valid {
								minted = id
							}
						}
						if tc.late {
							time.Sleep(5 * time.Millisecond)
						}
						return errorRow(errors.New("connection reset"))
					case strings.Contains(sql, "FROM sandbox"):
						return sandboxRow(active)
					}
					return activityRow()
				},
				execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
					return pgconn.NewCommandTag("UPDATE 1"), nil
				},
			}
			h := &Handlers{DB: db.New(mock), VMD: &stubVMD{pauseFn: func(context.Context, string, string) (string, string, error) {
				atomic.AddInt32(&pauses, 1)
				return "/snapshots/vmstate.snap", "/snapshots/mem.snap", nil
			}}}

			w := httptest.NewRecorder()
			setupTestRouter(h, teamID.String()).ServeHTTP(w, pauseRequest(sandboxID.String()))
			h.WaitAsyncBookkeeping()

			if w.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d; body: %s", w.Code, tc.wantCode, w.Body.String())
			}
			if tc.late && !strings.Contains(w.Body.String(), `"pausing"`) {
				t.Fatalf("body = %s, want the pause left in progress", w.Body.String())
			}
			if atomic.LoadInt32(&pauses) != tc.wantPauses {
				t.Fatalf("host pauses = %d, want %d", pauses, tc.wantPauses)
			}
			if tc.landed && !tc.late && atomic.LoadInt32(&finalizes) != 1 {
				t.Fatalf("finalizes = %d, want the confirmed claim finalized", finalizes)
			}
		})
	}
}

// A revert that matches nothing means another worker already holds the
// operation (the request outlasted its lease) and its pause goes on: the
// caller hears 'pausing', not a failure the reconciler would soon contradict.
func TestPauseSandbox_UnresolvedHostWithReclaimedLeaseAnswersPausing(t *testing.T) {
	sandboxID, teamID := uuid.New(), uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, HostID: "host-1", Name: "sb", Status: db.SandboxStatusActive,
		PauseOpID: pgtype.UUID{Bytes: uuid.New(), Valid: true}, PauseOpLeaseVersion: 1}
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "-- name: RevertPauseToActive :one"):
				return &mockRow{scanFn: func(dest ...any) error {
					*dest[0].(*int64) = 0
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

	if w.Code != http.StatusAccepted || !strings.Contains(w.Body.String(), `"pausing"`) {
		t.Fatalf("status = %d body = %s; want accepted as pausing", w.Code, w.Body.String())
	}
}
