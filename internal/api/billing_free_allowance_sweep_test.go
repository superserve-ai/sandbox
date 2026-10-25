package api

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/superserve-ai/sandbox/internal/db"
)

func TestFreeAllowanceSweepRetriesWithoutStarvingLaterPages(t *testing.T) {
	for _, mode := range []string{"durable_handoff", "retry_write_failure", "interrupted"} {
		t.Run(mode, func(t *testing.T) {
			teams := make([]uuid.UUID, freeAllowancePageSize+1)
			for i := range teams {
				teams[i] = uuid.New()
			}
			sort.Slice(teams, func(i, j int) bool { return teams[i].String() < teams[j].String() })
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var fail atomic.Bool
			fail.Store(true)
			var attempts, tail atomic.Int32
			var mu sync.Mutex
			queued := map[uuid.UUID]bool{}
			var cursor pgtype.UUID
			saves := 0
			mock := &mockDBTX{
				queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
					if strings.Contains(sql, "ClaimSweepLease") {
						return &mockRow{scanFn: func(dest ...any) error { *dest[0].(*pgtype.UUID) = cursor; return nil }}
					}
					return &mockRow{scanFn: func(dest ...any) error {
						id := args[0].(uuid.UUID)
						if id == teams[0] {
							attempts.Add(1)
							if fail.Load() {
								if mode == "interrupted" {
									cancel()
								}
								return context.DeadlineExceeded
							}
						}
						if id == teams[len(teams)-1] {
							tail.Add(1)
						}
						*dest[0].(*bool) = false
						return nil
					}}
				},
				queryFn: func(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
					mu.Lock()
					defer mu.Unlock()
					rows := &scanRows{}
					add := func(id uuid.UUID) {
						rows.rows = append(rows.rows, func(dest ...any) error { *dest[0].(*uuid.UUID) = id; return nil })
					}
					if strings.Contains(sql, "ClaimFreeAllowanceRetries") {
						for id := range queued {
							add(id)
						}
						return rows, nil
					}
					after := args[0].(pgtype.UUID)
					for _, id := range teams {
						if queued[id] || (after.Valid && id.String() <= uuid.UUID(after.Bytes).String()) {
							continue
						}
						add(id)
						if len(rows.rows) == int(freeAllowancePageSize) {
							break
						}
					}
					return rows, nil
				},
				execFn: func(execCtx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
					mu.Lock()
					defer mu.Unlock()
					switch {
					case strings.Contains(sql, "ScheduleFreeAllowanceRetry"):
						if execCtx.Err() != nil {
							return pgconn.CommandTag{}, execCtx.Err()
						}
						if mode == "retry_write_failure" {
							return pgconn.CommandTag{}, errors.New("retry persistence unavailable")
						}
						queued[args[0].(uuid.UUID)] = true
					case strings.Contains(sql, "ClearFreeAllowanceRetry"):
						delete(queued, args[0].(uuid.UUID))
					default:
						saves++
						cursor = args[0].(pgtype.UUID)
					}
					return pgconn.NewCommandTag("UPDATE 1"), nil
				},
			}
			h := &Handlers{DB: db.New(mock)}
			h.refreshFreeAllowances(ctx)
			if mode == "retry_write_failure" {
				if saves != 0 || len(queued) != 0 {
					t.Fatalf("unrecorded failure advanced cursor: saves=%d queued=%d", saves, len(queued))
				}
				return
			}
			if mode == "interrupted" {
				if !queued[teams[0]] || saves == 0 {
					t.Fatalf("interrupted dispatched work not durably handed off: queued=%v saves=%d", queued, saves)
				}
				return
			}
			if !queued[teams[0]] || tail.Load() != 1 {
				t.Fatalf("failed prefix lost or starved page2: queued=%v tail=%d", queued, tail.Load())
			}
			h.refreshFreeAllowances(ctx)
			if !queued[teams[0]] || tail.Load() != 2 || attempts.Load() < 2 {
				t.Fatalf("persistent failure starved progress/retry: queued=%v tail=%d attempts=%d", queued, tail.Load(), attempts.Load())
			}
			fail.Store(false)
			h.refreshFreeAllowances(ctx)
			if len(queued) != 0 {
				t.Fatalf("successful retry not cleared: %v", queued)
			}
		})
	}
}
