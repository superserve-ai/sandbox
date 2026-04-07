package api

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

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
	*dest[4].(**string) = row.HostID
	return nil
}

func (r *stubRows) Close()                                  {}
func (r *stubRows) Err() error                              { return r.err }
func (r *stubRows) CommandTag() pgconn.CommandTag           { return pgconn.CommandTag{} }
func (r *stubRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *stubRows) Values() ([]any, error)                  { return nil, nil }
func (r *stubRows) RawValues() [][]byte                     { return nil }
func (r *stubRows) Conn() *pgx.Conn                         { return nil }

// ---------------------------------------------------------------------------
// DBTX mock for reaper tests
// ---------------------------------------------------------------------------

// reaperMockDBTX backs db.Queries for reaper tests.
// queryFn handles ClaimExpiredSandboxes; queryRowFn handles CreateActivity.
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
	if m.queryRowFn != nil {
		return m.queryRowFn(ctx, sql, args...)
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
	var destroyCalled int32
	h := newReaperHandlers(
		&reaperMockDBTX{},
		&stubVMD{destroyFn: func(_ context.Context, _ string, _ bool) error {
			atomic.AddInt32(&destroyCalled, 1)
			return nil
		}},
	)

	h.reapOnce(context.Background(), 10)

	if atomic.LoadInt32(&destroyCalled) != 0 {
		t.Fatal("DestroyInstance should not be called when no sandboxes are expired")
	}
}

// TestReaper_VMDSucceeds verifies that a claimed sandbox triggers a VMD destroy.
func TestReaper_VMDSucceeds(t *testing.T) {
	row := expiredRow("sbx-a")
	var destroyedID string

	h := newReaperHandlers(
		&reaperMockDBTX{
			queryFn: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
				return newStubRows([]db.ClaimExpiredSandboxesRow{row}), nil
			},
		},
		&stubVMD{destroyFn: func(_ context.Context, id string, _ bool) error {
			destroyedID = id
			return nil
		}},
	)

	h.reapOnce(context.Background(), 10)

	if destroyedID != row.ID.String() {
		t.Fatalf("expected DestroyInstance called with %s, got %q", row.ID, destroyedID)
	}
}

// TestReaper_VMDFails verifies that a VMD error does not stop the reaper
// from processing subsequent sandboxes.
func TestReaper_VMDFails(t *testing.T) {
	rows := []db.ClaimExpiredSandboxesRow{expiredRow("sbx-a"), expiredRow("sbx-b")}
	var destroyCallCount int32

	h := newReaperHandlers(
		&reaperMockDBTX{
			queryFn: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
				return newStubRows(rows), nil
			},
		},
		&stubVMD{destroyFn: func(_ context.Context, _ string, _ bool) error {
			atomic.AddInt32(&destroyCallCount, 1)
			return errors.New("vmd: unknown instance")
		}},
	)

	h.reapOnce(context.Background(), 10)

	// Both sandboxes should be attempted even though the first VMD call fails.
	if got := atomic.LoadInt32(&destroyCallCount); got != 2 {
		t.Fatalf("expected 2 DestroyInstance calls, got %d", got)
	}
}

// TestReaper_DBError verifies that a ClaimExpiredSandboxes failure causes the
// reaper to skip the cycle without calling VMD.
func TestReaper_DBError(t *testing.T) {
	var destroyCalled int32

	h := newReaperHandlers(
		&reaperMockDBTX{
			queryFn: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
				return nil, errors.New("db: connection refused")
			},
		},
		&stubVMD{destroyFn: func(_ context.Context, _ string, _ bool) error {
			atomic.AddInt32(&destroyCalled, 1)
			return nil
		}},
	)

	h.reapOnce(context.Background(), 10)

	if atomic.LoadInt32(&destroyCalled) != 0 {
		t.Fatal("DestroyInstance should not be called when DB query fails")
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

	h.reapOnce(context.Background(), 7)

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
	var destroyCount int32

	h := newReaperHandlers(
		&reaperMockDBTX{
			queryFn: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
				return newStubRows(rows), nil
			},
		},
		&stubVMD{destroyFn: func(_ context.Context, _ string, _ bool) error {
			if atomic.AddInt32(&destroyCount, 1) == 2 {
				cancel() // cancel after processing 2 sandboxes
			}
			return nil
		}},
	)

	h.reapOnce(ctx, 10)

	// The loop checks ctx.Done() between each sandbox. After cancel() the loop
	// should exit. We expect 2 destroys (the ones that ran before the cancel
	// propagated) — and strictly fewer than 5.
	if got := atomic.LoadInt32(&destroyCount); got >= 5 {
		t.Fatalf("expected context cancel to stop the batch early, but all 5 sandboxes were processed")
	}
}

// TestReaper_LoopRunsImmediately verifies that the reaper processes expired
// sandboxes on startup without waiting for the first tick.
func TestReaper_LoopRunsImmediately(t *testing.T) {
	row := expiredRow("sbx-immediate")
	var destroyCalled int32

	h := newReaperHandlers(
		&reaperMockDBTX{
			queryFn: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
				return newStubRows([]db.ClaimExpiredSandboxesRow{row}), nil
			},
		},
		&stubVMD{destroyFn: func(_ context.Context, _ string, _ bool) error {
			atomic.AddInt32(&destroyCalled, 1)
			return nil
		}},
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Use a very long interval so the test doesn't depend on a ticker firing.
	cfg := ReaperConfig{Interval: 24 * time.Hour, BatchSize: 10}
	h.StartTimeoutReaper(ctx, cfg)

	// Give the goroutine time to run the initial reapOnce before the interval.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&destroyCalled) > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("reaper did not run immediately on startup")
}
