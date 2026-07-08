//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/superserve-ai/sandbox/internal/db"
)

// Guards the 42P08 type-deduction bug that broke every PATCH auto_delete_seconds
// in prod. Handler unit tests mock the DB, so only a real query catches it.
func TestIntegration_UpdateSandboxAutoDelete(t *testing.T) {
	ctx := context.Background()
	teamID, _ := seedTeamAndKey(t)
	sandboxID := insertSandboxAt(t, teamID, "autodel-"+uuid.New().String()[:8], "paused", time.Now())
	secs := func(v int32) *int32 { return &v }

	// Set a window on a paused sandbox — arms the deadline.
	n, err := testQueries.UpdateSandboxAutoDelete(ctx, db.UpdateSandboxAutoDeleteParams{
		ID: sandboxID, TeamID: teamID, AutoDeleteSeconds: secs(3600),
	})
	if err != nil {
		t.Fatalf("UpdateSandboxAutoDelete(3600): %v", err)
	}
	if n != 1 {
		t.Fatalf("rows affected = %d, want 1", n)
	}
	sb, err := testQueries.GetSandbox(ctx, db.GetSandboxParams{ID: sandboxID, TeamID: teamID})
	if err != nil {
		t.Fatal(err)
	}
	if sb.AutoDeleteSeconds == nil || *sb.AutoDeleteSeconds != 3600 {
		t.Fatalf("auto_delete_seconds = %v, want 3600", sb.AutoDeleteSeconds)
	}
	if !sb.AutoDeleteAt.Valid {
		t.Fatal("auto_delete_at should be armed on a paused sandbox")
	}

	// 0 = delete on pause (deadline ~now); must not error either.
	if _, err := testQueries.UpdateSandboxAutoDelete(ctx, db.UpdateSandboxAutoDeleteParams{
		ID: sandboxID, TeamID: teamID, AutoDeleteSeconds: secs(0),
	}); err != nil {
		t.Fatalf("UpdateSandboxAutoDelete(0): %v", err)
	}

	// nil clears the window.
	if _, err := testQueries.UpdateSandboxAutoDelete(ctx, db.UpdateSandboxAutoDeleteParams{
		ID: sandboxID, TeamID: teamID, AutoDeleteSeconds: nil,
	}); err != nil {
		t.Fatalf("UpdateSandboxAutoDelete(nil): %v", err)
	}
	sb, err = testQueries.GetSandbox(ctx, db.GetSandboxParams{ID: sandboxID, TeamID: teamID})
	if err != nil {
		t.Fatal(err)
	}
	if sb.AutoDeleteSeconds != nil {
		t.Fatalf("auto_delete_seconds should be nil after clear, got %v", *sb.AutoDeleteSeconds)
	}
}
