//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/superserve-ai/sandbox/internal/db"
)

func TestIntegration_FailSavedSnapshotSourceAfterRevocationClearsHeldClaimAndClosesUsage(t *testing.T) {
	seedSavedSnapshotTestHost(t)
	ctx := context.Background()
	team, err := testQueries.CreateTeam(ctx, "snapshot-source-fallback-"+uuid.NewString())
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE team SET snapshot_storage_quota_bytes = 1073741824 WHERE id = $1`, team.ID); err != nil {
		t.Fatalf("configure snapshot storage quota: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_feature_flag (team_id, key, enabled)
		VALUES ($1, 'sandbox_snapshots_v1', true)
	`, team.ID); err != nil {
		t.Fatalf("enable saved snapshots: %v", err)
	}

	sourceID, snapshotID := uuid.New(), uuid.New()
	startedAt := time.Now().UTC().Add(-time.Minute)
	if _, err := testPool.Exec(ctx, `
		INSERT INTO sandbox (
			id, team_id, name, status, host_id, vcpu_count, memory_mib, disk_mib
		) VALUES ($1, $2, $3, 'active', 'snapshot-host', 2, 2048, 8192)
	`, sourceID, team.ID, "source-"+sourceID.String()); err != nil {
		t.Fatalf("seed active source: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO sandbox_active_interval (sandbox_id, team_id, started_at)
		VALUES ($1, $2, $3)
	`, sourceID, team.ID, startedAt); err != nil {
		t.Fatalf("seed active interval: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO sandbox_compute_billing_interval (
			sandbox_id, team_id, vcpu_count, memory_mib, started_at
		) VALUES ($1, $2, 2, 2048, $3)
	`, sourceID, team.ID, startedAt); err != nil {
		t.Fatalf("seed compute interval: %v", err)
	}
	if _, err := testQueries.BeginSavedSnapshot(ctx, db.BeginSavedSnapshotParams{
		SnapshotID: snapshotID,
		SandboxID:  sourceID,
		TeamID:     team.ID,
		Trigger:    "manual",
	}); err != nil {
		t.Fatalf("BeginSavedSnapshot: %v", err)
	}
	if err := testQueries.UpsertSandboxRevocation(ctx, db.UpsertSandboxRevocationParams{
		SandboxID: sourceID,
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
	}); err != nil {
		t.Fatalf("UpsertSandboxRevocation: %v", err)
	}

	reason := "source_resume_failed"
	for attempt := 1; attempt <= 2; attempt++ {
		gotSourceID, err := testQueries.FailSavedSnapshotSourceAfterRevocation(ctx, db.FailSavedSnapshotSourceAfterRevocationParams{
			SnapshotID:    snapshotID,
			TeamID:        team.ID,
			FailureReason: &reason,
		})
		if err != nil {
			t.Fatalf("FailSavedSnapshotSourceAfterRevocation attempt %d: %v", attempt, err)
		}
		if gotSourceID != sourceID {
			t.Fatalf("fallback source ID = %s, want %s", gotSourceID, sourceID)
		}
	}

	var sourceStatus, snapshotStatus string
	var failureReason *string
	var operationID pgtype.UUID
	var activeEndedAt, computeEndedAt pgtype.Timestamptz
	var activeReason, computeReason *string
	if err := testPool.QueryRow(ctx, `
		SELECT source.status, source.snapshot_operation_id,
		       snap.status, snap.failure_reason,
		       active.ended_at, active.end_reason,
		       compute.ended_at, compute.end_reason
		FROM sandbox source
		JOIN snapshot snap ON snap.id = $2 AND snap.sandbox_id = source.id
		JOIN sandbox_active_interval active ON active.sandbox_id = source.id
		JOIN sandbox_compute_billing_interval compute ON compute.sandbox_id = source.id
		WHERE source.id = $1
	`, sourceID, snapshotID).Scan(
		&sourceStatus, &operationID, &snapshotStatus, &failureReason,
		&activeEndedAt, &activeReason, &computeEndedAt, &computeReason,
	); err != nil {
		t.Fatalf("read fallback terminal state: %v", err)
	}
	if sourceStatus != "failed" || snapshotStatus != "failed" || operationID.Valid {
		t.Fatalf("terminal state source=%s snapshot=%s operation=%v, want failed/failed/empty", sourceStatus, snapshotStatus, operationID)
	}
	if failureReason == nil || *failureReason != reason {
		t.Fatalf("snapshot failure reason = %v, want %q", failureReason, reason)
	}
	if !activeEndedAt.Valid || activeReason == nil || *activeReason != "failed" {
		t.Fatalf("active interval closure = (%v, %v), want ended/failed", activeEndedAt, activeReason)
	}
	if !computeEndedAt.Valid || computeReason == nil || *computeReason != "failed" {
		t.Fatalf("compute interval closure = (%v, %v), want ended/failed", computeEndedAt, computeReason)
	}
}
