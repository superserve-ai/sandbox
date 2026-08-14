package api

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
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

	h.reapOnce(context.Background(), 10, 1)

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
			queryFn: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
				return newStubRows([]db.ClaimExpiredSandboxesRow{row}), nil
			},
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

	h.reapOnce(context.Background(), 10, 1)

	if pausedID != row.ID.String() {
		t.Fatalf("expected PauseInstance called with %s, got %q", row.ID, pausedID)
	}
	if got := atomic.LoadInt32(&finalizeCalls); got != 1 {
		t.Fatalf("expected exactly 1 FinalizePause call, got %d", got)
	}
}

// TestReaper_VMDFails verifies that a VMD pause error reverts status to active
// and does not stop the reaper from processing subsequent sandboxes.
func TestReaper_VMDFails(t *testing.T) {
	rows := []db.ClaimExpiredSandboxesRow{expiredRow("sbx-a"), expiredRow("sbx-b")}
	var pauseCallCount int32
	var revertCallCount int32

	h := newReaperHandlers(
		&reaperMockDBTX{
			queryFn: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
				return newStubRows(rows), nil
			},
			execFn: func(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
				// Count revert-to-active calls (UpdateSandboxStatus with 'active').
				if strings.Contains(sql, "status") {
					for _, a := range args {
						if s, ok := a.(db.SandboxStatus); ok && s == db.SandboxStatusActive {
							atomic.AddInt32(&revertCallCount, 1)
						}
					}
				}
				return pgconn.CommandTag{}, nil
			},
		},
		&stubVMD{pauseFn: func(_ context.Context, _ string, _ string) (string, string, error) {
			atomic.AddInt32(&pauseCallCount, 1)
			return "", "", errors.New("vmd: pause failed")
		}},
	)

	h.reapOnce(context.Background(), 10, 1)

	// Both sandboxes are attempted, and pauseWithRetry retries each failure
	// once (a timed-out pause may have completed on the host), so 2 sandboxes
	// × 2 attempts = 4 calls.
	if got := atomic.LoadInt32(&pauseCallCount); got != 4 {
		t.Fatalf("expected 4 PauseInstance calls (2 sandboxes × retry), got %d", got)
	}
	// A failure that doesn't converge after the retry reverts to active.
	if got := atomic.LoadInt32(&revertCallCount); got != 2 {
		t.Fatalf("expected 2 revert-to-active calls, got %d", got)
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

	h.reapOnce(context.Background(), 10, 1)

	if atomic.LoadInt32(&pauseCalled) != 0 {
		t.Fatal("PauseInstance should not be called when DB query fails")
	}
}

// TestReaper_BatchSizeRespected verifies that the batch limit is passed to
// ClaimExpiredSandboxes (the SQL enforces LIMIT, but we confirm the value
// reaches the query layer).
func TestReaper_BatchSizeRespected(t *testing.T) {
	var capturedLimit int32

	h := newReaperHandlers(
		&reaperMockDBTX{
			queryFn: func(_ context.Context, _ string, args ...any) (pgx.Rows, error) {
				if len(args) > 0 {
					if v, ok := args[0].(int32); ok {
						atomic.StoreInt32(&capturedLimit, v)
					}
				}
				return newStubRows(nil), nil
			},
		},
		&stubVMD{},
	)

	h.reapOnce(context.Background(), 7, 1)

	if got := atomic.LoadInt32(&capturedLimit); got != 7 {
		t.Fatalf("expected batch size 7 passed to query, got %d", got)
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
			queryFn: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
				return newStubRows(rows), nil
			},
		},
		&stubVMD{pauseFn: func(_ context.Context, _ string, _ string) (string, string, error) {
			if atomic.AddInt32(&pauseCount, 1) == 2 {
				cancel() // cancel after processing 2 sandboxes
			}
			return "/snapshots/vmstate.snap", "/snapshots/mem.snap", nil
		}},
	)

	h.reapOnce(ctx, 10, 1)

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
			queryFn: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
				return newStubRows([]db.ClaimExpiredSandboxesRow{row}), nil
			},
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

// rollbackPausedVM must persist the resumed host/IP before it flips the row
// back to active, otherwise the DB can keep advertising a recycled slot.
func TestRollbackPausedVM_PersistsReplacementHostAndIP(t *testing.T) {
	resumeIP := "10.11.0.99"
	var callOrder []string
	var gotHost string
	var gotIP string
	var gotPID *int32

	h := &Handlers{
		VMD: &stubVMD{resumeFn: func(context.Context, string, string, string, []byte) (string, error) {
			return resumeIP, nil
		}},
		DB: db.New(&reaperMockDBTX{
			execFn: func(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
				switch {
				case strings.Contains(sql, "SET host_id = $2, ip_address = $3, pid = COALESCE($4, pid)"):
					callOrder = append(callOrder, "host")
					gotHost = args[1].(string)
					gotIP = args[2].(*netip.Addr).String()
					gotPID = args[3].(*int32)
				case strings.Contains(sql, "SET status = $2"):
					callOrder = append(callOrder, "status")
				}
				return pgconn.CommandTag{}, nil
			},
		}),
	}

	sbx := db.ClaimExpiredSandboxesRow{
		ID:            uuid.New(),
		TeamID:        uuid.New(),
		HostID:        "host-1",
		Name:          "sbx",
		NetworkConfig: []byte(`{"allowed_cidrs":["10.0.0.0/8"]}`),
	}

	h.rollbackPausedVM(context.Background(), sbx, "/snapshots/vmstate.snap", "/snapshots/mem.snap", errors.New("pause write failed"), zerolog.Nop())

	if gotHost != "host-1" || gotIP != resumeIP {
		t.Fatalf("replacement host/IP = %q/%q, want host-1/%s", gotHost, gotIP, resumeIP)
	}
	if gotPID != nil {
		t.Fatalf("replacement pid arg = %#v, want nil to preserve the existing PID", gotPID)
	}
	if strings.Join(callOrder, ",") != "host,status" {
		t.Fatalf("rollback write order = %v, want host then status", callOrder)
	}
}

// drainRows adapts stubRows to the queries drainOnce issues: the
// ListDrainingHosts scan (id, maintenance_window_start) and the claim scan
// (same shape as ClaimExpiredSandboxes).
type drainingHostRows struct {
	hosts []db.ListDrainingHostsRow
	idx   int
}

func (r *drainingHostRows) Next() bool { r.idx++; return r.idx <= len(r.hosts) }
func (r *drainingHostRows) Scan(dest ...any) error {
	row := r.hosts[r.idx-1]
	*dest[0].(*string) = row.ID
	*dest[1].(*pgtype.Timestamptz) = row.MaintenanceWindowStart
	return nil
}
func (r *drainingHostRows) Close()                                       {}
func (r *drainingHostRows) Err() error                                   { return nil }
func (r *drainingHostRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *drainingHostRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *drainingHostRows) Values() ([]any, error)                       { return nil, nil }
func (r *drainingHostRows) RawValues() [][]byte                          { return nil }
func (r *drainingHostRows) Conn() *pgx.Conn                              { return nil }

// TestDrain_PausesActivesOnDrainingHost pins the drain saga end to end: a
// draining host's claimed sandbox is paused via VMD and finalized with the
// maintenance trigger — the same battle-tested path as the timeout reaper.
func TestDrain_PausesActivesOnDrainingHost(t *testing.T) {
	row := expiredRow("sbx-drain") // HostID empty: routes to the stub VMD, matching suite convention
	var pausedID string
	var finalizeCalls int32
	var remainingChecks int32

	h := newReaperHandlers(
		&reaperMockDBTX{
			queryFn: func(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
				switch {
				case strings.Contains(sql, "-- name: ListDrainingHosts :many"):
					return &drainingHostRows{hosts: []db.ListDrainingHostsRow{{
						ID:                     "host-a",
						MaintenanceWindowStart: pgtype.Timestamptz{Time: time.Now().Add(50 * time.Minute), Valid: true},
					}}}, nil
				case strings.Contains(sql, "-- name: ClaimDrainingSandboxes :many"):
					return newStubRows([]db.ClaimExpiredSandboxesRow{row}), nil
				}
				return newStubRows(nil), nil
			},
			queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
				switch {
				case strings.Contains(sql, "-- name: CountUnpausedOnHost :one"):
					atomic.AddInt32(&remainingChecks, 1)
					return &mockRow{scanFn: func(dest ...any) error {
						*dest[0].(*int64) = 0
						return nil
					}}
				case strings.Contains(sql, "upserted AS"):
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

	h.drainOnce(context.Background(), 10, 1)

	if pausedID != row.ID.String() {
		t.Fatalf("expected drain to pause %s, got %q", row.ID, pausedID)
	}
	if got := atomic.LoadInt32(&finalizeCalls); got != 1 {
		t.Fatalf("expected exactly 1 FinalizePause, got %d", got)
	}
	if atomic.LoadInt32(&remainingChecks) != 1 {
		t.Fatal("drain must check remaining unpaused count for the alert decision")
	}
}

// TestDrain_NoDrainingHostsNoWork pins the steady state: with nothing
// draining, the drain arm issues no claims and no VMD calls.
func TestDrain_NoDrainingHostsNoWork(t *testing.T) {
	var claims int32
	h := newReaperHandlers(
		&reaperMockDBTX{
			queryFn: func(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
				if strings.Contains(sql, "-- name: ClaimDrainingSandboxes :many") {
					atomic.AddInt32(&claims, 1)
				}
				return newStubRows(nil), nil
			},
		},
		&stubVMD{pauseFn: func(_ context.Context, _ string, _ string) (string, string, error) {
			t.Error("no VMD calls expected with no draining hosts")
			return "", "", nil
		}},
	)
	h.drainOnce(context.Background(), 10, 1)
	if atomic.LoadInt32(&claims) != 0 {
		t.Fatal("no claims expected with no draining hosts")
	}
}

// TestDrain_VMDFailureRevertsToActive pins the saga's failure arm under the
// maintenance cause: a pause the VMD refuses reverts the row to active so
// the next tick retries, exactly like the timeout path.
func TestDrain_VMDFailureRevertsToActive(t *testing.T) {
	row := expiredRow("sbx-drain-fail")
	var reverts int32

	h := newReaperHandlers(
		&reaperMockDBTX{
			queryFn: func(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
				switch {
				case strings.Contains(sql, "-- name: ListDrainingHosts :many"):
					return &drainingHostRows{hosts: []db.ListDrainingHostsRow{{ID: "host-a"}}}, nil
				case strings.Contains(sql, "-- name: ClaimDrainingSandboxes :many"):
					return newStubRows([]db.ClaimExpiredSandboxesRow{row}), nil
				}
				return newStubRows(nil), nil
			},
			queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
				switch {
				case strings.Contains(sql, "-- name: CountUnpausedOnHost :one"):
					return &mockRow{scanFn: func(dest ...any) error {
						*dest[0].(*int64) = 1
						return nil
					}}
				case strings.Contains(sql, "FROM sandbox_active_interval"):
					return notFoundRow()
				}
				return activityRow()
			},
			execFn: func(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
				if strings.Contains(sql, "-- name: UpdateSandboxStatus :exec") && len(args) > 1 && args[1] == db.SandboxStatusActive {
					atomic.AddInt32(&reverts, 1)
				}
				return pgconn.NewCommandTag("UPDATE 1"), nil
			},
		},
		&stubVMD{pauseFn: func(_ context.Context, _ string, _ string) (string, string, error) {
			return "", "", errors.New("vmd unavailable")
		}},
	)

	h.drainOnce(context.Background(), 10, 1)
	if atomic.LoadInt32(&reverts) != 1 {
		t.Fatalf("failed pause must revert to active, got %d reverts", atomic.LoadInt32(&reverts))
	}
}

// TestDrain_BatchSharedAcrossHosts pins the per-tick work bound: with N
// draining hosts, each gets batchSize/N of the claim budget and the pauses
// dispatch through one shared fan-out — a slow host cannot starve the rest
// or blow ReaperConfig's documented per-cycle bound.
func TestDrain_BatchSharedAcrossHosts(t *testing.T) {
	var claimSizes []int32
	h := newReaperHandlers(
		&reaperMockDBTX{
			queryFn: func(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
				switch {
				case strings.Contains(sql, "-- name: ListDrainingHosts :many"):
					return &drainingHostRows{hosts: []db.ListDrainingHostsRow{{ID: "host-a"}, {ID: "host-b"}}}, nil
				case strings.Contains(sql, "-- name: ClaimDrainingSandboxes :many"):
					claimSizes = append(claimSizes, args[1].(int32))
					return newStubRows(nil), nil
				}
				return newStubRows(nil), nil
			},
			queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
				if strings.Contains(sql, "-- name: CountUnpausedOnHost :one") {
					return &mockRow{scanFn: func(dest ...any) error {
						*dest[0].(*int64) = 0
						return nil
					}}
				}
				return activityRow()
			},
		},
		&stubVMD{},
	)

	h.drainOnce(context.Background(), 10, 2)

	// First host gets an even split of the budget; having claimed nothing,
	// its share flows onward, so the second host may use the full remainder.
	if len(claimSizes) != 2 || claimSizes[0] != 5 || claimSizes[1] != 10 {
		t.Fatalf("claim sizes %v, want [5 10] — even split, unspent budget flows on", claimSizes)
	}
}

// TestDrain_TickBudgetBoundsFleetWideWork pins the whole-tick bound when
// hosts outnumber the batch: actual claims spend a shared budget, and once
// it is gone the remaining hosts defer to the next tick — total pauses per
// tick never exceed BatchSize no matter how many hosts drain at once.
func TestDrain_TickBudgetBoundsFleetWideWork(t *testing.T) {
	var totalClaimed int32
	var claimCalls int32
	sandboxRows := func(n int32) []db.ClaimExpiredSandboxesRow {
		rows := make([]db.ClaimExpiredSandboxesRow, n)
		for i := range rows {
			rows[i] = expiredRow(fmt.Sprintf("sbx-%d", i))
		}
		return rows
	}
	h := newReaperHandlers(
		&reaperMockDBTX{
			queryFn: func(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
				switch {
				case strings.Contains(sql, "-- name: ListDrainingHosts :many"):
					return &drainingHostRows{hosts: []db.ListDrainingHostsRow{
						{ID: "host-a"}, {ID: "host-b"}, {ID: "host-c"}, {ID: "host-d"},
					}}, nil
				case strings.Contains(sql, "-- name: ClaimDrainingSandboxes :many"):
					atomic.AddInt32(&claimCalls, 1)
					n := args[1].(int32) // every host has more actives than its share
					atomic.AddInt32(&totalClaimed, n)
					return newStubRows(sandboxRows(n)), nil
				}
				return newStubRows(nil), nil
			},
			queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
				switch {
				case strings.Contains(sql, "-- name: CountUnpausedOnHost :one"):
					return &mockRow{scanFn: func(dest ...any) error {
						*dest[0].(*int64) = 0
						return nil
					}}
				case strings.Contains(sql, "upserted AS"):
					return finalizePauseRow(uuid.New())
				case strings.Contains(sql, "FROM sandbox_active_interval"):
					return notFoundRow()
				}
				return activityRow()
			},
		},
		&stubVMD{pauseFn: func(_ context.Context, _ string, _ string) (string, string, error) {
			return "/snapshots/vmstate.snap", "/snapshots/mem.snap", nil
		}},
	)

	h.drainOnce(context.Background(), 2, 1)

	if got := atomic.LoadInt32(&totalClaimed); got > 2 {
		t.Fatalf("tick claimed %d sandboxes with batch 2 — the whole-tick bound is broken", got)
	}
	if atomic.LoadInt32(&claimCalls) >= 4 {
		t.Fatal("hosts beyond the budget must defer, not claim")
	}
}

// TestDrainDueHosts pins the persisted-deadline decision: the flip query is
// the single place hosts become draining on schedule, so a window recorded
// long ago drains on time even when later heartbeats fail to report.
// (The lead-time bounds themselves live in the SQL and are asserted by the
// guard test on the query text below.)
func TestDrainDueHosts_FlipsAndLogs(t *testing.T) {
	var flips int32
	h := newReaperHandlers(
		&reaperMockDBTX{
			queryFn: func(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
				if strings.Contains(sql, "-- name: DrainHostsDueForMaintenance :many") {
					atomic.AddInt32(&flips, 1)
					if got := args[0].(int32); got != int32(drainLeadTime/time.Second) {
						t.Errorf("lead seconds = %d, want %d", got, int32(drainLeadTime/time.Second))
					}
					return &drainingHostRows{hosts: []db.ListDrainingHostsRow{{
						ID:                     "host-a",
						MaintenanceWindowStart: pgtype.Timestamptz{Time: time.Now().Add(30 * time.Minute), Valid: true},
					}}}, nil
				}
				return newStubRows(nil), nil
			},
		},
		&stubVMD{},
	)
	h.drainDueHosts(context.Background())
	if atomic.LoadInt32(&flips) != 1 {
		t.Fatal("drainDueHosts must run the flip query")
	}
}

// TestDrainDueForMaintenanceQueryBounds pins the SQL-side lead window: both
// bounds present, so long-stale windows cannot re-drain an un-drained host.
func TestDrainDueForMaintenanceQueryBounds(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "db", "queries", "hosts.sql"))
	if err != nil {
		t.Fatal(err)
	}
	q := string(raw)
	start := strings.Index(q, "-- name: DrainHostsDueForMaintenance :many")
	if start < 0 {
		t.Fatal("DrainHostsDueForMaintenance query missing")
	}
	block := q[start : start+strings.Index(q[start:], "RETURNING")]
	for _, required := range []string{
		"status = 'active'",
		"maintenance_window_start <= now() + make_interval",
		"maintenance_window_start >= now() - make_interval",
	} {
		if !strings.Contains(block, required) {
			t.Errorf("flip query missing %q", required)
		}
	}
}
