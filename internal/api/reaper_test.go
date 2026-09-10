package api

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
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
)

// ---------------------------------------------------------------------------
// pgx.Rows stub
// ---------------------------------------------------------------------------

// stubRows implements pgx.Rows backed by a slice of ClaimExpiredSandboxesRow.
type stubRows struct {
	items []db.ClaimExpiredSandboxesRow
	idx   int
	err   error
}

func newStubRows(items []db.ClaimExpiredSandboxesRow) *stubRows {
	return &stubRows{items: items, idx: -1}
}

func (r *stubRows) Next() bool {
	r.idx++
	return r.idx < len(r.items)
}

func (r *stubRows) Scan(dest ...any) error {
	row := r.items[r.idx]
	*dest[0].(*uuid.UUID) = row.ID
	*dest[1].(*uuid.UUID) = row.TeamID
	*dest[2].(*string) = row.Name
	*dest[3].(*pgtype.UUID) = row.SnapshotID
	*dest[4].(*string) = row.HostID
	*dest[6].(*pgtype.UUID) = row.PauseOpID
	*dest[7].(*int64) = row.PauseOpLeaseVersion
	*dest[8].(*pgtype.Timestamptz) = row.PauseOpLeaseUntil
	return nil
}

func (r *stubRows) Close()                                       {}
func (r *stubRows) Err() error                                   { return r.err }
func (r *stubRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *stubRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *stubRows) Values() ([]any, error)                       { return nil, nil }
func (r *stubRows) RawValues() [][]byte                          { return nil }
func (r *stubRows) Conn() *pgx.Conn                              { return nil }

// ---------------------------------------------------------------------------
// DBTX mock for reaper tests
// ---------------------------------------------------------------------------

// reaperMockDBTX backs db.Queries for reaper tests.
// queryFn handles ClaimExpiredSandboxes; queryRowFn handles CreateSnapshot and
// CreateActivity (distinguished by SQL content); execFn handles status updates.
type reaperMockDBTX struct {
	queryFn    func(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	queryRowFn func(ctx context.Context, sql string, args ...any) pgx.Row
	execFn     func(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

func (m *reaperMockDBTX) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	if m.queryFn != nil {
		return m.queryFn(ctx, sql, args...)
	}
	return newStubRows(nil), nil
}

func (m *reaperMockDBTX) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	// The finalize-mode probe runs before every FinalizePause; answer it
	// centrally (legacy mode) ahead of per-test scripts, same as mockDBTX.
	if strings.Contains(sql, "to_regclass('public.snapshot_sandbox_unique')") {
		return &mockRow{scanFn: func(dest ...any) error {
			if b, ok := dest[0].(*bool); ok {
				*b = true
			}
			return nil
		}}
	}
	if m.queryRowFn != nil {
		return m.queryRowFn(ctx, sql, args...)
	}
	switch {
	case strings.Contains(sql, "upserted AS"):
		return finalizePauseRow(uuid.New())
	case strings.Contains(sql, "INSERT INTO snapshot"):
		return reaperSnapshotRow()
	case strings.Contains(sql, "FROM sandbox_active_interval"):
		// GetMostRecentClosedSandboxIntervalActor — return ErrNoRows so the
		// inherit-actor lookup falls through to NULL (no prior interval in
		// these tests).
		return notFoundRow()
	}
	return activityRow()
}

func (m *reaperMockDBTX) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if m.execFn != nil {
		return m.execFn(ctx, sql, args...)
	}
	return pgconn.CommandTag{}, nil
}

// ---------------------------------------------------------------------------
// Row stubs
// ---------------------------------------------------------------------------

func reaperSnapshotRow() pgx.Row {
	trigger := "timeout"
	return snapshotRow(db.Snapshot{
		ID:        uuid.New(),
		SandboxID: uuid.New(),
		TeamID:    uuid.New(),
		Path:      "/snapshots/vmstate.snap",
		Trigger:   trigger,
		CreatedAt: time.Now(),
	})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newReaperHandlers(dbtx *reaperMockDBTX, vmd *stubVMD) *Handlers {
	return &Handlers{
		VMD: vmd,
		DB:  db.New(dbtx),
	}
}

// rowsOnce serves rows to the first expired-sandbox claim and nothing to any
// later one, as a real claim would once the rows are leased. Other queries
// (the loops share the mock) get nothing.
func rowsOnce(rows []db.ClaimExpiredSandboxesRow) func(context.Context, string, ...any) (pgx.Rows, error) {
	var served int32
	return func(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
		if !strings.Contains(sql, "-- name: ClaimExpiredSandboxes ") || atomic.AddInt32(&served, 1) > 1 {
			return newStubRows(nil), nil
		}
		return newStubRows(rows), nil
	}
}

func expiredRow(name string) db.ClaimExpiredSandboxesRow {
	return db.ClaimExpiredSandboxesRow{
		ID:     uuid.New(),
		TeamID: uuid.New(),
		Name:   name,
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestReaper_NothingExpired verifies that when ClaimExpiredSandboxes returns
// empty, no VMD calls are made.
func TestReaper_NothingExpired(t *testing.T) {
	var pauseCalled int32
	h := newReaperHandlers(
		&reaperMockDBTX{},
		&stubVMD{pauseFn: func(_ context.Context, _ string, _ string) (string, string, error) {
			atomic.AddInt32(&pauseCalled, 1)
			return "", "", nil
		}},
	)

	h.reapOnce(context.Background(), 10, 1, zerolog.Nop())

	if atomic.LoadInt32(&pauseCalled) != 0 {
		t.Fatal("PauseInstance should not be called when no sandboxes are expired")
	}
}

// TestReaper_VMDSucceeds verifies that a claimed sandbox triggers a VMD
// pause followed by the atomic FinalizePause bookkeeping query.
func TestReaper_VMDSucceeds(t *testing.T) {
	row := expiredRow("sbx-a")
	var pausedID string
	var finalizeCalls int32

	h := newReaperHandlers(
		&reaperMockDBTX{
			queryFn: rowsOnce([]db.ClaimExpiredSandboxesRow{row}),
			queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
				if strings.Contains(sql, "upserted AS") {
					atomic.AddInt32(&finalizeCalls, 1)
					return finalizePauseRow(uuid.New())
				}
				return activityRow()
			},
		},
		&stubVMD{pauseFn: func(_ context.Context, id string, _ string) (string, string, error) {
			pausedID = id
			return "/snapshots/vmstate.snap", "/snapshots/mem.snap", nil
		}},
	)

	h.reapOnce(context.Background(), 10, 1, zerolog.Nop())

	if pausedID != row.ID.String() {
		t.Fatalf("expected PauseInstance called with %s, got %q", row.ID, pausedID)
	}
	if got := atomic.LoadInt32(&finalizeCalls); got != 1 {
		t.Fatalf("expected exactly 1 FinalizePause call, got %d", got)
	}
}

// A pause the host never answered stays 'pausing' with its lease handed back
// for the reconciler; nothing reverts the row.
func TestReaper_VMDFails_ReconcilerLeavesPausing(t *testing.T) {
	row := expiredRow("sbx-a")
	row.PauseOpID = pgtype.UUID{Bytes: uuid.New(), Valid: true}
	row.PauseOpLeaseVersion = 1
	var reverts, releases int32

	h := newReaperHandlers(
		&reaperMockDBTX{
			queryFn: rowsOnce([]db.ClaimExpiredSandboxesRow{row}),
			execFn: func(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
				switch {
				case strings.Contains(sql, "-- name: ReleasePauseLease :execrows"):
					atomic.AddInt32(&releases, 1)
					if args[0].(int32) != 0 || args[2].(pgtype.UUID) != row.PauseOpID || args[3].(int64) != 1 {
						t.Errorf("release args = %v, want retry 0 fenced to the claimed lease", args)
					}
				case strings.Contains(sql, "-- name: UpdateSandboxStatus"):
					atomic.AddInt32(&reverts, 1)
				}
				return pgconn.NewCommandTag("UPDATE 1"), nil
			},
		},
		&stubVMD{pauseFn: func(context.Context, string, string) (string, string, error) {
			return "", "", status.Error(codes.DeadlineExceeded, "pause timed out")
		}},
	)

	h.reapOnce(context.Background(), 10, 1, zerolog.Nop())

	if got := atomic.LoadInt32(&releases); got != 1 {
		t.Fatalf("expected 1 lease release, got %d", got)
	}
	if got := atomic.LoadInt32(&reverts); got != 0 {
		t.Fatalf("expected no revert to active, got %d", got)
	}
}

// NotFound from the resolved host is the one error that decides the pause:
// the VM is gone, so the row is failed under the lease's fence, not reverted.
func TestReaper_VMDNotFound_ReconcilerMarksFailed(t *testing.T) {
	row := expiredRow("sbx-a")
	row.PauseOpID = pgtype.UUID{Bytes: uuid.New(), Valid: true}
	row.PauseOpLeaseVersion = 1
	var reverts, fails int32

	h := newReaperHandlers(
		&reaperMockDBTX{
			queryFn: rowsOnce([]db.ClaimExpiredSandboxesRow{row}),
			queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
				if strings.Contains(sql, "-- name: MarkSandboxFailed :one") {
					atomic.AddInt32(&fails, 1)
					if args[1].(db.SandboxStatus) != db.SandboxStatusPausing || args[2].(pgtype.UUID) != row.PauseOpID {
						t.Errorf("mark-failed args = %v, want observed pausing fenced to the claimed lease", args)
					}
					return &mockRow{scanFn: func(dest ...any) error {
						*dest[0].(*int64) = 1
						return nil
					}}
				}
				return activityRow()
			},
			execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
				if strings.Contains(sql, "-- name: UpdateSandboxStatus") {
					atomic.AddInt32(&reverts, 1)
				}
				return pgconn.NewCommandTag("UPDATE 1"), nil
			},
		},
		&stubVMD{pauseFn: func(context.Context, string, string) (string, string, error) {
			return "", "", status.Error(codes.NotFound, "no such vm")
		}},
	)

	h.reapOnce(context.Background(), 10, 1, zerolog.Nop())

	if got := atomic.LoadInt32(&fails); got != 1 {
		t.Fatalf("expected 1 fenced mark-failed, got %d", got)
	}
	if got := atomic.LoadInt32(&reverts); got != 0 {
		t.Fatalf("expected no revert to active, got %d", got)
	}
}

// TestReaper_DBError verifies that a ClaimExpiredSandboxes failure causes the
// reaper to skip the cycle without calling VMD.
func TestReaper_DBError(t *testing.T) {
	var pauseCalled int32

	h := newReaperHandlers(
		&reaperMockDBTX{
			queryFn: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
				return nil, errors.New("db: connection refused")
			},
		},
		&stubVMD{pauseFn: func(_ context.Context, _ string, _ string) (string, string, error) {
			atomic.AddInt32(&pauseCalled, 1)
			return "", "", nil
		}},
	)

	h.reapOnce(context.Background(), 10, 1, zerolog.Nop())

	if atomic.LoadInt32(&pauseCalled) != 0 {
		t.Fatal("PauseInstance should not be called when DB query fails")
	}
}

// TestReaper_BatchSizeRespected verifies that the batch limit is passed to
// ClaimExpiredSandboxes (the SQL enforces LIMIT, but we confirm the value
// reaches the query layer).
// Each worker claims one row at a time, and the batch size caps the tick:
// 3 workers with a cap of 7 make 7 single-row claims.
func TestReaper_ClaimsOnePerFreeWorker(t *testing.T) {
	var mu sync.Mutex
	var limits []int32
	var pauses int32

	h := newReaperHandlers(
		&reaperMockDBTX{
			queryFn: func(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
				if !strings.Contains(sql, "-- name: ClaimExpiredSandboxes ") {
					return newStubRows(nil), nil
				}
				limit := args[0].(int32)
				mu.Lock()
				limits = append(limits, limit)
				mu.Unlock()
				rows := make([]db.ClaimExpiredSandboxesRow, limit)
				for i := range rows {
					rows[i] = expiredRow("sbx")
				}
				return newStubRows(rows), nil
			},
		},
		&stubVMD{pauseFn: func(context.Context, string, string) (string, string, error) {
			atomic.AddInt32(&pauses, 1)
			return "/snapshots/vmstate.snap", "/snapshots/mem.snap", nil
		}},
	)

	h.reapOnce(context.Background(), 7, 3, zerolog.Nop())

	mu.Lock()
	defer mu.Unlock()
	if len(limits) != 7 {
		t.Fatalf("claims = %v, want 7 of them", limits)
	}
	for _, l := range limits {
		if l != 1 {
			t.Fatalf("claim limits = %v, want one row each", limits)
		}
	}
	if got := atomic.LoadInt32(&pauses); got != 7 {
		t.Fatalf("pauses = %d, want the batch size 7", got)
	}
}

// A worker that finishes claims the next row while another is still on a
// slow pause; one slow host never idles the rest.
func TestReaper_FreeWorkerStartsTheNextPause(t *testing.T) {
	rows := []db.ClaimExpiredSandboxesRow{expiredRow("slow"), expiredRow("fast"), expiredRow("next")}
	var mu sync.Mutex
	remaining := rows
	calls := make(chan string, 3)
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })

	h := newReaperHandlers(
		&reaperMockDBTX{queryFn: func(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
			if !strings.Contains(sql, "-- name: ClaimExpiredSandboxes ") {
				return newStubRows(nil), nil
			}
			mu.Lock()
			defer mu.Unlock()
			n := min(int(args[0].(int32)), len(remaining))
			claimed := remaining[:n]
			remaining = remaining[n:]
			return newStubRows(claimed), nil
		}},
		&stubVMD{pauseFn: func(ctx context.Context, id, _ string) (string, string, error) {
			calls <- id
			if id == rows[0].ID.String() {
				select {
				case <-release:
				case <-ctx.Done():
					return "", "", ctx.Err()
				}
			}
			return "/snapshots/vmstate.snap", "/snapshots/mem.snap", nil
		}},
	)

	done := make(chan struct{})
	go func() {
		defer close(done)
		h.reapOnce(context.Background(), 3, 2, zerolog.Nop())
	}()
	defer func() {
		releaseOnce.Do(func() { close(release) })
		<-done
		h.WaitAsyncBookkeeping()
	}()

	for i := 0; i < 2; i++ {
		select {
		case <-calls:
		case <-time.After(time.Second):
			t.Fatal("first workers did not start")
		}
	}
	select {
	case id := <-calls:
		if id != rows[2].ID.String() {
			t.Fatalf("next pause = %s, want the third row", id)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("one slow pause blocked the next sandbox while a worker was idle")
	}
}

// TestReaper_ContextCancelledMidBatch verifies that the reaper stops
// processing the batch when the context is cancelled.
func TestReaper_ContextCancelledMidBatch(t *testing.T) {
	rows := make([]db.ClaimExpiredSandboxesRow, 5)
	for i := range rows {
		rows[i] = expiredRow("sbx")
	}

	ctx, cancel := context.WithCancel(context.Background())
	var pauseCount int32

	h := newReaperHandlers(
		&reaperMockDBTX{
			queryFn: rowsOnce(rows),
		},
		&stubVMD{pauseFn: func(_ context.Context, _ string, _ string) (string, string, error) {
			if atomic.AddInt32(&pauseCount, 1) == 2 {
				cancel() // cancel after processing 2 sandboxes
			}
			return "/snapshots/vmstate.snap", "/snapshots/mem.snap", nil
		}},
	)

	h.reapOnce(ctx, 10, 1, zerolog.Nop())

	// The loop checks ctx.Done() between each sandbox. After cancel() the loop
	// should exit before processing all 5.
	if got := atomic.LoadInt32(&pauseCount); got >= 5 {
		t.Fatalf("expected context cancel to stop the batch early, but all 5 sandboxes were processed")
	}
}

// TestReaper_LoopRunsImmediately verifies that the reaper processes expired
// sandboxes on startup without waiting for the first tick.
func TestReaper_LoopRunsImmediately(t *testing.T) {
	row := expiredRow("sbx-immediate")
	var pauseCalled int32

	h := newReaperHandlers(
		&reaperMockDBTX{
			queryFn: rowsOnce([]db.ClaimExpiredSandboxesRow{row}),
		},
		&stubVMD{pauseFn: func(_ context.Context, _ string, _ string) (string, string, error) {
			atomic.AddInt32(&pauseCalled, 1)
			return "/snapshots/vmstate.snap", "/snapshots/mem.snap", nil
		}},
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Use a very long interval so the test doesn't depend on a ticker firing.
	cfg := ReaperConfig{Interval: 24 * time.Hour, BatchSize: 10}
	h.StartTimeoutReaper(ctx, cfg)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&pauseCalled) > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("reaper did not run immediately on startup")
}

// An unset SweepInterval must fall back to the default — a zero value reaching
// time.NewTicker panics — and the sweeps must still run at startup so a restart
// after a crash cleans up without waiting a full sweep period.
func TestReaper_SweepsRunOnStartupWithUnsetSweepInterval(t *testing.T) {
	var snapshotSweeps int32

	h := newReaperHandlers(
		&reaperMockDBTX{
			execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
				if strings.Contains(sql, "DELETE FROM snapshot s") {
					atomic.AddInt32(&snapshotSweeps, 1)
				}
				return pgconn.NewCommandTag("DELETE 0"), nil
			},
		},
		&stubVMD{},
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Long poll interval so nothing here depends on a ticker firing.
	h.StartTimeoutReaper(ctx, ReaperConfig{Interval: 24 * time.Hour, BatchSize: 10})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&snapshotSweeps) > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("snapshot sweep did not run on startup")
}

// The billing pass schedules like the reaper: a free worker claims the next
// sandbox while another is still on a slow pause.
func TestBillingPause_FreeWorkerStartsTheNextPause(t *testing.T) {
	teamID := uuid.New()
	rows := make([]db.ClaimExpiredSandboxesRow, 11)
	for i := range rows {
		rows[i] = expiredRow(fmt.Sprintf("billing-%d", i))
		rows[i].TeamID = teamID
	}
	var mu sync.Mutex
	remaining := rows
	calls := make(chan string, len(rows))
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })

	h := newReaperHandlers(
		&reaperMockDBTX{queryFn: func(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
			if !strings.Contains(sql, "-- name: ClaimBillingIneligibleSandboxes") {
				return newStubRows(nil), nil
			}
			mu.Lock()
			defer mu.Unlock()
			n := min(int(args[1].(int32)), len(remaining))
			claimed := remaining[:n]
			remaining = remaining[n:]
			return newStubRows(claimed), nil
		}},
		&stubVMD{pauseFn: func(ctx context.Context, id, _ string) (string, string, error) {
			calls <- id
			if id == rows[0].ID.String() {
				select {
				case <-release:
				case <-ctx.Done():
					return "", "", ctx.Err()
				}
			}
			return "/snapshots/vmstate.snap", "/snapshots/mem.snap", nil
		}},
	)

	done := make(chan struct{})
	go func() {
		defer close(done)
		h.pauseBillingIneligibleTeam(context.Background(), teamID)
	}()
	defer func() {
		releaseOnce.Do(func() { close(release) })
		<-done
		h.WaitAsyncBookkeeping()
	}()

	for i := 0; i < 10; i++ {
		select {
		case <-calls:
		case <-time.After(time.Second):
			t.Fatal("initial billing pauses did not start")
		}
	}
	select {
	case id := <-calls:
		if id != rows[10].ID.String() {
			t.Fatalf("next pause = %s, want the eleventh row", id)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("one slow pause blocked the eleventh sandbox while workers were idle")
	}
}
