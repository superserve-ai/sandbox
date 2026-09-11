package api

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/superserve-ai/sandbox/internal/db"
)

func TestFinalizeInFlight(t *testing.T) {
	now := time.Now()
	at := func(t time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: t, Valid: true} }
	op := pgtype.UUID{Bytes: uuid.New(), Valid: true}
	for _, tc := range []struct {
		name string
		row  db.LockSandboxRowRow
		want bool
	}{
		{"fresh transition", db.LockSandboxRowRow{Status: db.SandboxStatusPausing, UpdatedAt: now}, true},
		{"stale transition, no operation", db.LockSandboxRowRow{Status: db.SandboxStatusPausing, UpdatedAt: now.Add(-20 * time.Minute)}, false},
		{"stale transition, lease held", db.LockSandboxRowRow{Status: db.SandboxStatusPausing, UpdatedAt: now.Add(-20 * time.Minute),
			PauseOpID: op, PauseOpLeaseUntil: at(now.Add(time.Minute))}, true},
		{"stale transition, lease just released", db.LockSandboxRowRow{Status: db.SandboxStatusResuming, UpdatedAt: now.Add(-20 * time.Minute),
			PauseOpID: op, PauseOpLeaseUntil: at(now.Add(-2 * time.Minute))}, true},
		{"flagged for an operator", db.LockSandboxRowRow{Status: db.SandboxStatusPausing, UpdatedAt: now.Add(-20 * time.Minute),
			PauseOpID: op, PauseOpLeaseUntil: at(now.Add(time.Minute)), PauseOpAttentionAt: at(now)}, false},
		{"lease nobody has touched", db.LockSandboxRowRow{Status: db.SandboxStatusPausing, UpdatedAt: now.Add(-20 * time.Minute),
			PauseOpID: op, PauseOpLeaseUntil: at(now.Add(-20 * time.Minute))}, false},
		{"not transitional", db.LockSandboxRowRow{Status: db.SandboxStatusActive, UpdatedAt: now, PauseOpID: op, PauseOpLeaseUntil: at(now.Add(time.Minute))}, false},
	} {
		if got := finalizeInFlight(tc.row); got != tc.want {
			t.Errorf("%s: finalizeInFlight = %v, want %v", tc.name, got, tc.want)
		}
	}
}
