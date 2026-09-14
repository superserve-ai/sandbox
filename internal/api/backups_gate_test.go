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
	op := pgtype.UUID{Bytes: uuid.New(), Valid: true}
	for _, tc := range []struct {
		name string
		row  db.LockSandboxRowRow
		want bool
	}{
		{"fresh transition", db.LockSandboxRowRow{Status: db.SandboxStatusPausing, UpdatedAt: now}, true},
		{"stale transition, no operation", db.LockSandboxRowRow{Status: db.SandboxStatusPausing, UpdatedAt: now.Add(-20 * time.Minute)}, false},
		{"stale transition, operation unresolved", db.LockSandboxRowRow{Status: db.SandboxStatusPausing, UpdatedAt: now.Add(-20 * time.Minute), PauseOpID: op}, true},
		{"stale resume revert, operation unresolved", db.LockSandboxRowRow{Status: db.SandboxStatusResuming, UpdatedAt: now.Add(-20 * time.Minute), PauseOpID: op}, true},
		{"not transitional", db.LockSandboxRowRow{Status: db.SandboxStatusActive, UpdatedAt: now, PauseOpID: op}, false},
	} {
		if got := finalizeInFlight(tc.row); got != tc.want {
			t.Errorf("%s: finalizeInFlight = %v, want %v", tc.name, got, tc.want)
		}
	}
}
