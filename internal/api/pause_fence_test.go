package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

// generationModeDB answers the finalize-mode probe with "generation" and
// records the fence the generation finalize was given.
type generationModeDB struct {
	*mockDBTX
	op      pgtype.UUID
	version *int64
}

func (d *generationModeDB) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	switch {
	case strings.Contains(sql, "-- name: HasLegacySnapshotUnique"):
		return boolRow(false)
	case strings.Contains(sql, "-- name: FinalizePauseGeneration"):
		d.op = args[2].(pgtype.UUID)
		d.version = args[3].(*int64)
		return finalizePauseRow(uuid.New())
	}
	return d.mockDBTX.QueryRow(ctx, sql, args...)
}

func TestFinalizePause_GenerationModeKeepsTheFence(t *testing.T) {
	d := &generationModeDB{mockDBTX: &mockDBTX{}}
	h := &Handlers{DB: db.New(d)}
	op := pgtype.UUID{Bytes: uuid.New(), Valid: true}
	version := int64(7)

	if _, err := h.finalizePause(context.Background(), db.FinalizePauseParams{
		ID: uuid.New(), TeamID: uuid.New(), PauseOpID: op, PauseOpLeaseVersion: &version,
		Path: "/snapshots/vmstate.snap",
	}); err != nil {
		t.Fatal(err)
	}
	if d.op != op || d.version == nil || *d.version != version {
		t.Fatalf("generation finalize dropped the fence: op=%v version=%v", d.op, d.version)
	}
}

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

type stubHosts struct {
	HostRegistry
	resolve func() (vmdclient.Client, error)
}

func (r *stubHosts) ClientFor(context.Context, string) (vmdclient.Client, error) { return r.resolve() }

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

// A worker whose lease cannot cover the attempt sends nothing to the host:
// past the lease another replica may already have finished and the sandbox
// may be running again.
func TestReconcilePause_ExpiredLeaseDoesNotDispatch(t *testing.T) {
	sandboxID, teamID := uuid.New(), uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Status: db.SandboxStatusPausing,
		PauseOpID: pgtype.UUID{Bytes: uuid.New(), Valid: true}, PauseOpLeaseVersion: 2}
	var calls atomic.Int32
	var finalizes int32
	h := &Handlers{DB: db.New(pauseMocks(sb, &finalizes)), VMD: &stubVMD{
		pauseFn: func(context.Context, string, string) (string, string, error) {
			calls.Add(1)
			return "/snapshots/vmstate.snap", "/snapshots/mem.snap", nil
		},
	}}
	row := db.ClaimPendingPausesRow{ID: sandboxID, TeamID: teamID, PauseOpID: sb.PauseOpID, PauseOpLeaseVersion: 2}

	h.reconcilePause(context.Background(), row, time.Now().Add(-time.Second), zerolog.Nop())
	if calls.Load() != 0 {
		t.Fatalf("worker with an expired lease sent %d pause RPCs", calls.Load())
	}

	h.reconcilePause(context.Background(), row, time.Now().Add(time.Minute), zerolog.Nop())
	if calls.Load() != 1 || atomic.LoadInt32(&finalizes) != 1 {
		t.Fatalf("worker with a live lease: calls = %d, finalizes = %d; want 1 and 1", calls.Load(), finalizes)
	}
}
