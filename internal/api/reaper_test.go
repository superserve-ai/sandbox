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

// idRows implements pgx.Rows over candidate ids, as the list queries return.
type idRows struct {
	ids []uuid.UUID
	idx int
}

func newIDRows(ids []uuid.UUID) *idRows { return &idRows{ids: ids, idx: -1} }

func (r *idRows) Next() bool {
	r.idx++
	return r.idx < len(r.ids)
}

func (r *idRows) Scan(dest ...any) error {
	*dest[0].(*uuid.UUID) = r.ids[r.idx]
	return nil
}

func (r *idRows) Close()                                       {}
func (r *idRows) Err() error                                   { return nil }
func (r *idRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *idRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *idRows) Values() ([]any, error)                       { return nil, nil }
func (r *idRows) RawValues() [][]byte                          { return nil }
func (r *idRows) Conn() *pgx.Conn                              { return nil }

// claimedRow is what a claim-by-id returns for a candidate.
func claimedRow(c db.ClaimExpiredSandboxRow) *mockRow {
	return &mockRow{scanFn: func(dest ...any) error {
		*dest[0].(*uuid.UUID) = c.ID
		*dest[1].(*uuid.UUID) = c.TeamID
		*dest[2].(*string) = c.Name
		*dest[3].(*pgtype.UUID) = c.SnapshotID
		*dest[4].(*string) = c.HostID
		*dest[5].(*[]byte) = c.NetworkConfig
		*dest[6].(*pgtype.UUID) = c.PauseOpID
		*dest[7].(*int64) = c.PauseOpLeaseVersion
		*dest[8].(*pgtype.Timestamptz) = c.PauseOpLeaseUntil
		return nil
	}}
}

// ---------------------------------------------------------------------------
// DBTX mock for reaper tests
// ---------------------------------------------------------------------------

// reaperMockDBTX backs db.Queries for reaper tests. candidates are served to
// the list queries in order and to the claim-by-id queries once each, the way
// a real claim is one-shot; queryFn/queryRowFn/execFn override the rest.
type reaperMockDBTX struct {
	queryFn    func(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	queryRowFn func(ctx context.Context, sql string, args ...any) pgx.Row
	execFn     func(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	candidates []db.ClaimExpiredSandboxRow

	mu     sync.Mutex
	taken  map[uuid.UUID]bool
	lists  atomic.Int32
	claims atomic.Int32
}

func isListSQL(sql string) bool {
	return strings.Contains(sql, "-- name: ListExpiredSandboxes ") || strings.Contains(sql, "-- name: ListBillingIneligibleSandboxes ")
}

func isClaimSQL(sql string) bool {
	return strings.Contains(sql, "-- name: ClaimExpiredSandbox ") || strings.Contains(sql, "-- name: ClaimBillingIneligibleSandbox ")
}

func (m *reaperMockDBTX) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	if m.queryFn != nil {
		return m.queryFn(ctx, sql, args...)
	}
	if isListSQL(sql) {
		m.lists.Add(1)
		ids := make([]uuid.UUID, 0, len(m.candidates))
		for _, c := range m.candidates {
			ids = append(ids, c.ID)
		}
		return newIDRows(ids), nil
	}
	return newIDRows(nil), nil
}

func (m *reaperMockDBTX) claim(id uuid.UUID) pgx.Row {
	m.claims.Add(1)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.taken == nil {
		m.taken = map[uuid.UUID]bool{}
	}
	for _, c := range m.candidates {
		if c.ID == id && !m.taken[id] {
			m.taken[id] = true
			return claimedRow(c)
		}
	}
	return notFoundRow()
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
	if isClaimSQL(sql) {
		return m.claim(args[0].(uuid.UUID))
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

func expiredRow(name string) db.ClaimExpiredSandboxRow {
	return db.ClaimExpiredSandboxRow{
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
			candidates: []db.ClaimExpiredSandboxRow{row},
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
			candidates: []db.ClaimExpiredSandboxRow{row},
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
			candidates: []db.ClaimExpiredSandboxRow{row},
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
// One candidate scan per tick; each worker then claims its own row at
// dispatch time: 7 candidates with 3 workers is one list and 7 claims.
func TestReaper_ScansOnceAndClaimsPerWorker(t *testing.T) {
	rows := make([]db.ClaimExpiredSandboxRow, 7)
	for i := range rows {
		rows[i] = expiredRow("sbx")
	}
	var pauses int32
	mock := &reaperMockDBTX{candidates: rows}
	h := newReaperHandlers(mock, &stubVMD{pauseFn: func(context.Context, string, string) (string, string, error) {
		atomic.AddInt32(&pauses, 1)
		return "/snapshots/vmstate.snap", "/snapshots/mem.snap", nil
	}})

	h.reapOnce(context.Background(), 7, 3, zerolog.Nop())

	if mock.lists.Load() != 1 || mock.claims.Load() != 7 || atomic.LoadInt32(&pauses) != 7 {
		t.Fatalf("lists = %d, claims = %d, pauses = %d; want 1, 7, 7", mock.lists.Load(), mock.claims.Load(), pauses)
	}
}

// A worker that finishes claims the next candidate while another is still on
// a slow pause; one slow host never idles the rest.
func TestReaper_FreeWorkerStartsTheNextPause(t *testing.T) {
	rows := []db.ClaimExpiredSandboxRow{expiredRow("slow"), expiredRow("fast"), expiredRow("next")}
	calls := make(chan string, 3)
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })

	h := newReaperHandlers(
		&reaperMockDBTX{candidates: rows},
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

	// With the first row held, every row must still start.
	assertAllStart(t, calls, rows, "one slow pause blocked the next sandbox while a worker was idle")
}

// assertAllStart reads one start per row from calls and fails if any row
// never starts or an unknown id shows up. Starts arrive in any order.
func assertAllStart(t *testing.T, calls <-chan string, rows []db.ClaimExpiredSandboxRow, blocked string) {
	t.Helper()
	want := make(map[string]bool, len(rows))
	for _, r := range rows {
		want[r.ID.String()] = true
	}
	for range rows {
		select {
		case id := <-calls:
			if !want[id] {
				t.Fatalf("unexpected pause %s", id)
			}
			delete(want, id)
		case <-time.After(time.Second):
			t.Fatalf("%s (%d never started)", blocked, len(want))
		}
	}
}

// TestReaper_ContextCancelledMidBatch verifies that the reaper stops
// processing the batch when the context is cancelled.
func TestReaper_ContextCancelledMidBatch(t *testing.T) {
	rows := make([]db.ClaimExpiredSandboxRow, 5)
	for i := range rows {
		rows[i] = expiredRow("sbx")
	}

	ctx, cancel := context.WithCancel(context.Background())
	var pauseCount int32

	h := newReaperHandlers(
		&reaperMockDBTX{
			candidates: rows,
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
			candidates: []db.ClaimExpiredSandboxRow{row},
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

// The billing pass schedules like the reaper: one list, then a free worker
// claims the next sandbox while another is still on a slow pause.
func TestBillingPause_FreeWorkerStartsTheNextPause(t *testing.T) {
	teamID := uuid.New()
	rows := make([]db.ClaimExpiredSandboxRow, 11)
	for i := range rows {
		rows[i] = expiredRow(fmt.Sprintf("billing-%d", i))
		rows[i].TeamID = teamID
	}
	calls := make(chan string, len(rows))
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })

	mock := &reaperMockDBTX{candidates: rows}
	h := newReaperHandlers(mock, &stubVMD{pauseFn: func(ctx context.Context, id, _ string) (string, string, error) {
		calls <- id
		if id == rows[0].ID.String() {
			select {
			case <-release:
			case <-ctx.Done():
				return "", "", ctx.Err()
			}
		}
		return "/snapshots/vmstate.snap", "/snapshots/mem.snap", nil
	}})

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

	// With the first row held, the eleventh must still start on a free worker.
	assertAllStart(t, calls, rows, "one slow pause blocked the eleventh sandbox while workers were idle")
	if mock.lists.Load() != 1 {
		t.Fatalf("lists = %d, want one candidate scan for the pass", mock.lists.Load())
	}
}

// A cancelled process context (shutdown) must not turn an undispatched claim
// into a failed sandbox: the revert runs detached and lands, and the terminal
// fallback is never reached.
func TestRevertToActiveOrFail_SurvivesCancellation(t *testing.T) {
	sbx := expiredRow("sbx")
	sbx.PauseOpID = pgtype.UUID{Bytes: uuid.New(), Valid: true}
	sbx.PauseOpLeaseVersion = 1
	var reverts, fails int32
	h := newReaperHandlers(&reaperMockDBTX{queryRowFn: func(ctx context.Context, sql string, _ ...any) pgx.Row {
		switch {
		case strings.Contains(sql, "-- name: RevertPauseToActive :one"):
			if ctx.Err() != nil {
				t.Errorf("revert issued on a dead context: %v", ctx.Err())
			}
			atomic.AddInt32(&reverts, 1)
			return &mockRow{scanFn: func(dest ...any) error {
				*dest[0].(*int64) = 1
				return nil
			}}
		case strings.Contains(sql, "-- name: MarkSandboxFailed :one"):
			atomic.AddInt32(&fails, 1)
			return &mockRow{scanFn: func(dest ...any) error {
				*dest[0].(*int64) = 1
				return nil
			}}
		}
		return activityRow()
	}}, &stubVMD{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h.revertToActiveOrFail(ctx, sbx, context.Canceled, zerolog.Nop())

	if atomic.LoadInt32(&reverts) != 1 || atomic.LoadInt32(&fails) != 0 {
		t.Fatalf("reverts = %d, fails = %d; want the revert to land and no terminal fallback", reverts, fails)
	}
}
