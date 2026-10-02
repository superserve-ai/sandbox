package api

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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

type stubHosts struct {
	HostRegistry
	resolve func() (vmdclient.Client, error)
}

func (r *stubHosts) ClientFor(context.Context, string) (vmdclient.Client, error) { return r.resolve() }

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
	row := db.ClaimPendingPauseRow{ID: sandboxID, TeamID: teamID, PauseOpID: sb.PauseOpID, PauseOpLeaseVersion: 2}

	h.reconcilePause(context.Background(), row, time.Now().Add(-time.Second), zerolog.Nop())
	if calls.Load() != 0 {
		t.Fatalf("worker with an expired lease sent %d pause RPCs", calls.Load())
	}

	h.reconcilePause(context.Background(), row, time.Now().Add(time.Minute), zerolog.Nop())
	if calls.Load() != 1 || atomic.LoadInt32(&finalizes) != 1 {
		t.Fatalf("worker with a live lease: calls = %d, finalizes = %d; want 1 and 1", calls.Load(), finalizes)
	}
}

// Host resolution spends the same lease as the RPC: if it runs past the
// attempt deadline, the RPC is not sent.
func TestReconcilePause_ResolutionCannotOutliveTheLease(t *testing.T) {
	sandboxID, teamID := uuid.New(), uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, HostID: "host-1", Status: db.SandboxStatusPausing,
		PauseOpID: pgtype.UUID{Bytes: uuid.New(), Valid: true}, PauseOpLeaseVersion: 1}
	var calls atomic.Int32
	var finalizes int32
	leaseUntil := time.Now().Add(asyncTimeout + pauseLeaseSkew + 40*time.Millisecond)
	h := &Handlers{DB: db.New(pauseMocks(sb, &finalizes)), Hosts: &stubHosts{resolve: func() (vmdclient.Client, error) {
		time.Sleep(time.Until(leaseUntil.Add(-asyncTimeout-pauseLeaseSkew)) + 20*time.Millisecond)
		return &stubVMD{pauseFn: func(ctx context.Context, _, _ string) (string, string, error) {
			if ctx.Err() == nil {
				calls.Add(1)
			}
			return "", "", status.Error(codes.Unavailable, "probe")
		}}, nil
	}}}

	h.reconcilePause(context.Background(), db.ClaimPendingPauseRow{ID: sandboxID, TeamID: teamID, HostID: "host-1",
		PauseOpID: sb.PauseOpID, PauseOpLeaseVersion: 1}, leaseUntil, zerolog.Nop())

	if calls.Load() != 0 {
		t.Fatalf("resolution crossed the attempt deadline, yet %d live RPCs were sent", calls.Load())
	}
}

// A finalize whose reply was lost after it committed leaves the row paused
// with no operation; the reconciler records the pause instead of retrying a
// lease that no longer exists.
func TestReconcilePause_LostFinalizeReplyStillRecordsThePause(t *testing.T) {
	sandboxID, teamID := uuid.New(), uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Name: "sb", Status: db.SandboxStatusPausing,
		PauseOpID: pgtype.UUID{Bytes: uuid.New(), Valid: true}, PauseOpLeaseVersion: 1}
	paused := sb
	paused.Status = db.SandboxStatusPaused
	paused.PauseOpID = pgtype.UUID{}
	var activities, releases int32
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "-- name: CreateActivity "):
				atomic.AddInt32(&activities, 1)
				return activityRow()
			case strings.Contains(sql, "upserted AS"), strings.Contains(sql, "INSERT INTO snapshot"):
				return errorRow(errors.New("connection reset"))
			case strings.Contains(sql, "-- name: GetSandbox :one"):
				return sandboxRow(paused)
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
	h := &Handlers{DB: db.New(mock), VMD: &stubVMD{}}

	h.reconcilePause(context.Background(), db.ClaimPendingPauseRow{ID: sandboxID, TeamID: teamID, Name: sb.Name, PauseOpID: sb.PauseOpID, PauseOpLeaseVersion: 1},
		time.Now().Add(time.Minute), zerolog.Nop())

	for deadline := time.Now().Add(300 * time.Millisecond); time.Now().Before(deadline) && atomic.LoadInt32(&activities) != 1; {
		time.Sleep(5 * time.Millisecond)
	}
	if atomic.LoadInt32(&activities) != 1 || atomic.LoadInt32(&releases) != 0 {
		t.Fatalf("activities = %d, releases = %d; want the pause recorded once and no retry", activities, releases)
	}
}

// A host that can never pause the VM as it stands (artifacts gone, VM parked
// in an error state) is a decided answer: the row is failed, not retried.
func TestReconcilePause_FailedPreconditionIsTerminal(t *testing.T) {
	sandboxID, teamID := uuid.New(), uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Status: db.SandboxStatusPausing,
		PauseOpID: pgtype.UUID{Bytes: uuid.New(), Valid: true}, PauseOpLeaseVersion: 1}
	var finalizes, fails, releases int32
	mock := pauseMocks(sb, &finalizes)
	inner := mock.queryRowFn
	mock.queryRowFn = func(ctx context.Context, sql string, args ...any) pgx.Row {
		if strings.Contains(sql, "-- name: MarkSandboxFailed :one") {
			atomic.AddInt32(&fails, 1)
			return &mockRow{scanFn: func(dest ...any) error {
				*dest[0].(*int64) = 1
				return nil
			}}
		}
		return inner(ctx, sql, args...)
	}
	mock.execFn = func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
		if strings.Contains(sql, "-- name: ReleasePauseLease ") {
			atomic.AddInt32(&releases, 1)
		}
		return pgconn.NewCommandTag("UPDATE 1"), nil
	}
	h := &Handlers{DB: db.New(mock), VMD: &stubVMD{pauseFn: func(context.Context, string, string) (string, string, error) {
		return "", "", status.Error(codes.FailedPrecondition, "paused VM artifacts missing on host")
	}}}

	h.reconcilePause(context.Background(), db.ClaimPendingPauseRow{ID: sandboxID, TeamID: teamID, PauseOpID: sb.PauseOpID, PauseOpLeaseVersion: 1},
		time.Now().Add(time.Minute), zerolog.Nop())

	if atomic.LoadInt32(&fails) != 1 || atomic.LoadInt32(&releases) != 0 {
		t.Fatalf("fails = %d, releases = %d; want the row failed and no retry", fails, releases)
	}
}

// A candidate whose claim keeps failing for a reason other than contention is
// listed again a bounded number of times, not forever.
func TestClaimBatch_BoundsRefillRounds(t *testing.T) {
	id := uuid.New()
	lists := 0
	claimed, err := claimBatch(context.Background(), 1, 1, func(context.Context, int32) ([]uuid.UUID, error) {
		lists++
		return []uuid.UUID{id}, nil
	}, func(context.Context, uuid.UUID) (struct{}, error) {
		return struct{}{}, pgx.ErrNoRows
	}, func(struct{}, time.Time) {
		t.Error("processed a row that was never claimed")
	})
	if err != nil || claimed != 0 || lists != claimRefillRounds {
		t.Fatalf("claimed = %d, lists = %d, err = %v; want nothing claimed after %d listings", claimed, lists, err, claimRefillRounds)
	}
}
