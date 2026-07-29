//go:build integration

package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/superserve-ai/sandbox/internal/db"
)

type savedSnapshotFenceFixture struct {
	teamID    uuid.UUID
	sandboxID uuid.UUID
}

func seedSavedSnapshotFenceFixture(t *testing.T, name string) savedSnapshotFenceFixture {
	t.Helper()
	f := savedSnapshotFenceFixture{
		teamID:    uuid.New(),
		sandboxID: uuid.New(),
	}
	mustExec(t, srcPool, `
		INSERT INTO host (
			id, vmd_addr, proxy_addr, region, capacity_memory_mib, capacity_vcpus
		)
		VALUES ($1, '10.0.0.1:50051', '10.0.0.1:8080', 'use', 65536, 32)
		ON CONFLICT (id) DO NOTHING`, sourceHostID)
	mustExec(t, dstPool, `
		INSERT INTO host (
			id, vmd_addr, proxy_addr, region, capacity_memory_mib, capacity_vcpus
		)
		VALUES ($1, '10.1.0.1:50051', '10.1.0.1:8080', $2, 65536, 32)
		ON CONFLICT (id) DO NOTHING`, destHostID, destRegion)
	mustExec(t, srcPool, `
		INSERT INTO team (id, name, snapshot_storage_quota_bytes)
		VALUES ($1, $2, 1099511627776)`, f.teamID, name)
	mustExec(t, srcPool, `
		INSERT INTO team_feature_flag (team_id, key, enabled)
		VALUES ($1, 'sandbox_snapshots_v1', true)`, f.teamID)
	mustExec(t, srcPool, `
		INSERT INTO sandbox (
			id, team_id, name, status, vcpu_count, memory_mib, disk_mib, host_id
		)
		VALUES ($1, $2, 'snapshot-source', 'paused', 1, 1024, 4096, $3)`,
		f.sandboxID, f.teamID, sourceHostID)
	return f
}

func savedSnapshotBeginParams(f savedSnapshotFenceFixture) db.BeginSavedSnapshotParams {
	return db.BeginSavedSnapshotParams{
		SnapshotID: uuid.New(),
		Trigger:    "api",
		TeamID:     f.teamID,
		SandboxID:  f.sandboxID,
	}
}

func copyFenceConfig(f savedSnapshotFenceFixture) config {
	return copyFenceConfigForTeam(f.teamID)
}

func copyFenceConfigForTeam(teamID uuid.UUID) config {
	return config{
		teamID:     teamID,
		sourceURL:  srcURL,
		destURL:    dstURL,
		destHostID: destHostID,
		destRegion: destRegion,
		phase:      phaseCopy,
	}
}

func assertNoSavedSnapshotAdmissionWrites(t *testing.T, f savedSnapshotFenceFixture) {
	t.Helper()
	var operationIsNull bool
	var snapshots int64
	if err := srcPool.QueryRow(context.Background(), `
		SELECT snapshot_operation_id IS NULL,
		       (SELECT count(*) FROM snapshot
		        WHERE team_id = $2 AND kind = 'saved')
		FROM sandbox
		WHERE id = $1 AND team_id = $2`,
		f.sandboxID, f.teamID,
	).Scan(&operationIsNull, &snapshots); err != nil {
		t.Fatal(err)
	}
	if !operationIsNull || snapshots != 0 {
		t.Fatalf("fenced admission wrote source state: operation_is_null=%v snapshots=%d",
			operationIsNull, snapshots)
	}
}

func assertNoDestinationTeamWrites(t *testing.T, teamID uuid.UUID) {
	t.Helper()
	for _, spec := range migratedTables {
		var rows int64
		query := `SELECT count(*) FROM ` + spec.name + ` WHERE ` + spec.scope
		if err := dstPool.QueryRow(context.Background(), query, teamID).Scan(&rows); err != nil {
			t.Fatalf("count destination %s: %v", spec.name, err)
		}
		if rows != 0 {
			t.Errorf("refused migration wrote %d destination %s rows", rows, spec.name)
		}
	}
}

func acquireSavedSnapshotAdmissionFences(
	ctx context.Context,
	q *db.Queries,
	teamID uuid.UUID,
) (bool, error) {
	acquired, err := q.TryAcquireSavedSnapshotGlobalMigrationFence(ctx)
	if err != nil || !acquired {
		return acquired, err
	}
	return q.TryAcquireSavedSnapshotTeamMigrationFence(ctx, teamID)
}

func waitForMigrationFenceContention(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		tx, err := srcPool.Begin(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		acquired, lockErr := db.New(tx).TryAcquireSavedSnapshotGlobalMigrationFence(context.Background())
		_ = tx.Rollback(context.Background())
		if lockErr != nil {
			t.Fatal(lockErr)
		}
		if !acquired {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("migration did not acquire or queue on the global saved-snapshot fence")
}

func TestMigrationFenceWinsBeforeFirstSavedSnapshot(t *testing.T) {
	f := seedSavedSnapshotFenceFixture(t, "migration-fence-wins")

	// Stop copy at its first destination team-table access. This keeps the
	// migration phase (and therefore its source fence) open without permitting
	// a destination team write.
	dstTx, err := dstPool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer dstTx.Rollback(context.Background())
	if _, err := dstTx.Exec(context.Background(), `LOCK TABLE team IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}

	runCtx, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()
	runResult := make(chan error, 1)
	go func() {
		runResult <- run(runCtx, copyFenceConfig(f))
	}()

	waitForMigrationFenceContention(t)

	// The direct db.Queries path models Handlers without Pool. Its SQL-level
	// MATERIALIZED fence must reject before host/sandbox/team locks and leave
	// both the operation claim and snapshot intent untouched.
	admissionCtx, cancelAdmission := context.WithTimeout(context.Background(), time.Second)
	defer cancelAdmission()
	_, err = db.New(srcPool).BeginSavedSnapshot(admissionCtx, savedSnapshotBeginParams(f))
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("direct BeginSavedSnapshot under migration fence = %v, want pgx.ErrNoRows", err)
	}
	assertNoSavedSnapshotAdmissionWrites(t, f)

	cancelRun()
	select {
	case err := <-runResult:
		if err == nil {
			t.Fatal("cancelled migration unexpectedly succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("migration did not stop after cancellation")
	}
	if err := dstTx.Rollback(context.Background()); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		t.Fatal(err)
	}
	assertNoDestinationTeamWrites(t, f.teamID)
}

func TestFirstSavedSnapshotAdmissionWinsBeforeMigration(t *testing.T) {
	f := seedSavedSnapshotFenceFixture(t, "snapshot-admission-wins")
	params := savedSnapshotBeginParams(f)

	// Reproduce the API lock order exactly: global shared, then team shared.
	// Start the migration after both are held but before the sandbox-secret
	// advisory lock. An incorrectly ordered migration can deadlock here by
	// holding sandbox/team rows while waiting for our shared fences.
	admissionCtx, cancelAdmission := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelAdmission()
	tx, err := srcPool.Begin(admissionCtx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	q := db.New(tx)
	acquired, err := acquireSavedSnapshotAdmissionFences(admissionCtx, q, f.teamID)
	if err != nil {
		t.Fatal(err)
	}
	if !acquired {
		t.Fatal("first snapshot admission could not acquire uncontended shared fences")
	}

	runResult := make(chan error, 1)
	go func() {
		runResult <- run(context.Background(), copyFenceConfig(f))
	}()
	waitForMigrationFenceContention(t)

	if err := q.LockSandboxForSecretWrites(admissionCtx, f.sandboxID.String()); err != nil {
		t.Fatalf("sandbox secret lock deadlocked behind migration: %v", err)
	}
	saved, err := q.BeginSavedSnapshot(admissionCtx, params)
	if err != nil {
		t.Fatalf("BeginSavedSnapshot deadlocked or failed after owning shared fence: %v", err)
	}
	if err := tx.Commit(admissionCtx); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-runResult:
		if err == nil || !strings.Contains(err.Error(), "cannot replicate V1 host-local saved snapshots") {
			t.Fatalf("migration must observe the committed admission and refuse, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("migration remained blocked after saved-snapshot admission committed")
	}

	var operationID pgtype.UUID
	var snapshots int64
	if err := srcPool.QueryRow(context.Background(), `
		SELECT snapshot_operation_id,
		       (SELECT count(*) FROM snapshot
		        WHERE team_id = $2 AND kind = 'saved')
		FROM sandbox
		WHERE id = $1 AND team_id = $2`,
		f.sandboxID, f.teamID,
	).Scan(&operationID, &snapshots); err != nil {
		t.Fatal(err)
	}
	if !operationID.Valid || uuid.UUID(operationID.Bytes) != saved.ID || snapshots != 1 {
		t.Fatalf("admission state operation=%v snapshot=%s rows=%d",
			operationID, saved.ID, snapshots)
	}
	assertNoDestinationTeamWrites(t, f.teamID)
}

func TestCrossTeamSystemTemplateCaptureWinsBeforeOwnerMigration(t *testing.T) {
	consumer := seedSavedSnapshotFenceFixture(t, "system-template-consumer")
	templateOwnerID := uuid.New()
	templateID := uuid.New()
	mustExec(t, srcPool, `
		INSERT INTO team (id, name)
		VALUES ($1, 'system-template-owner')`, templateOwnerID)
	mustExec(t, srcPool, `
		INSERT INTO template (
			id, team_id, name, status, build_spec, vcpu, memory_mib, disk_mib,
			snapshot_path, built_at
		)
		VALUES (
			$1, $2, 'superserve/fence-system-base', 'ready', '{}',
			1, 1024, 4096, '/srv/templates/system/vmstate.snap', now()
		)`, templateID, templateOwnerID)
	mustExec(t, srcPool, `
		UPDATE sandbox
		SET template_id = $2,
		    snapshot_path = '/srv/sandboxes/system-consumer/vmstate.snap',
		    mem_path = '/srv/sandboxes/system-consumer/mem.snap',
		    base_path = '/srv/sandboxes/system-consumer/base.ext4',
		    delta_path = '/srv/sandboxes/system-consumer/delta.ext4'
		WHERE id = $1`, consumer.sandboxID, templateID)

	admissionCtx, cancelAdmission := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelAdmission()
	tx, err := srcPool.Begin(admissionCtx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	q := db.New(tx)
	acquired, err := acquireSavedSnapshotAdmissionFences(admissionCtx, q, consumer.teamID)
	if err != nil {
		t.Fatal(err)
	}
	if !acquired {
		t.Fatal("cross-team capture could not acquire uncontended global/team fences")
	}

	runResult := make(chan error, 1)
	go func() {
		runResult <- run(context.Background(), copyFenceConfigForTeam(templateOwnerID))
	}()
	waitForMigrationFenceContention(t)

	if err := q.LockSandboxForSecretWrites(admissionCtx, consumer.sandboxID.String()); err != nil {
		t.Fatalf("sandbox secret lock deadlocked behind template-owner migration: %v", err)
	}
	saved, err := q.BeginSavedSnapshot(admissionCtx, savedSnapshotBeginParams(consumer))
	if err != nil {
		t.Fatalf("cross-team system-template capture failed: %v", err)
	}
	if err := tx.Commit(admissionCtx); err != nil {
		t.Fatal(err)
	}
	if !saved.TemplateID.Valid || uuid.UUID(saved.TemplateID.Bytes) != templateID {
		t.Fatalf("saved snapshot template=%v, want owner template %s", saved.TemplateID, templateID)
	}

	select {
	case err := <-runResult:
		if err == nil ||
			!strings.Contains(err.Error(), "other teams' saved snapshots pinning this team's templates=1") {
			t.Fatalf("template-owner migration must observe cross-team snapshot dependency, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("template-owner migration remained blocked after cross-team capture committed")
	}

	var ownerRows, templateRows int64
	if err := srcPool.QueryRow(context.Background(), `
		SELECT
			(SELECT count(*) FROM team WHERE id = $1),
			(SELECT count(*) FROM template WHERE id = $2 AND team_id = $1)`,
		templateOwnerID, templateID,
	).Scan(&ownerRows, &templateRows); err != nil {
		t.Fatal(err)
	}
	if ownerRows != 1 || templateRows != 1 {
		t.Fatalf("refused owner migration changed source rows: team=%d template=%d",
			ownerRows, templateRows)
	}
	assertNoDestinationTeamWrites(t, templateOwnerID)
}
