//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/superserve-ai/sandbox/internal/db"
)

type savedSnapshotForkFixture struct {
	teamID     uuid.UUID
	snapshotID uuid.UUID
	forkID     uuid.UUID
}

// seedSavedSnapshotTestHost satisfies the same host-admission invariant as
// production: every sandbox that can mutate host-local snapshot artifacts must
// belong to an active host row. Keep this scoped to the snapshot fixtures so a
// synthetic host cannot affect unrelated scheduler tests.
func seedSavedSnapshotTestHost(t *testing.T) {
	t.Helper()
	if _, err := testPool.Exec(context.Background(), `
		INSERT INTO host (
			id, vmd_addr, proxy_addr, region,
			capacity_memory_mib, capacity_vcpus, status
		) VALUES (
			'snapshot-host', '127.0.0.1:1', '127.0.0.1:2', 'test',
			65536, 64, 'active'
		)
		ON CONFLICT (id) DO UPDATE
		SET status = 'active', updated_at = now()
	`); err != nil {
		t.Fatalf("seed snapshot test host: %v", err)
	}
}

func seedSavedSnapshotForkFixture(t *testing.T, destroyed bool) savedSnapshotForkFixture {
	t.Helper()
	seedSavedSnapshotTestHost(t)

	ctx := context.Background()
	team, err := testQueries.CreateTeam(ctx, "snapshot-db-safety-"+uuid.NewString())
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		UPDATE team
		SET snapshot_storage_quota_bytes = 1073741824
		WHERE id = $1
	`, team.ID); err != nil {
		t.Fatalf("provision snapshot storage quota: %v", err)
	}

	sourceID := uuid.New()
	snapshotID := uuid.New()
	forkID := uuid.New()
	if _, err := testPool.Exec(ctx, `
		INSERT INTO sandbox (
			id, team_id, name, status, host_id, vcpu_count, memory_mib, disk_mib
		) VALUES ($1, $2, $3, 'active', $4, 2, 2048, 8192)
	`, sourceID, team.ID, "snapshot-source-"+sourceID.String(), "snapshot-host"); err != nil {
		t.Fatalf("insert source sandbox: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO snapshot (
			id, sandbox_id, team_id, path, mem_path, size_bytes, trigger,
			kind, status, source_status, host_id, vcpu_count, memory_mib,
			disk_mib, manifest_path, manifest_digest
		) VALUES (
			$1, $2, $3, $4, $5, 0, 'manual', 'saved', 'ready', 'active',
			$6, 2, 2048, 8192, $7, repeat('a', 64)
		)
	`, snapshotID, sourceID, team.ID, "/saved/"+snapshotID.String()+"/disk",
		"/saved/"+snapshotID.String()+"/memory", "snapshot-host",
		"/saved/"+snapshotID.String()+"/manifest.json"); err != nil {
		t.Fatalf("insert saved snapshot: %v", err)
	}

	status := "starting"
	var destroyedAt any
	if destroyed {
		status = "deleted"
		destroyedAt = time.Now().Add(-time.Minute)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO sandbox (
			id, team_id, name, status, host_id, vcpu_count, memory_mib,
			disk_mib, base_path, source_snapshot_id, destroyed_at
		) VALUES ($1, $2, $3, $4, $5, 2, 2048, 8192, $6, $7, $8)
	`, forkID, team.ID, "snapshot-fork-"+forkID.String(), status,
		"snapshot-host", "/saved/base", snapshotID, destroyedAt); err != nil {
		t.Fatalf("insert snapshot fork: %v", err)
	}

	return savedSnapshotForkFixture{
		teamID:     team.ID,
		snapshotID: snapshotID,
		forkID:     forkID,
	}
}

func TestIntegration_DestroyedForkPinsSavedSnapshotUntilRelease(t *testing.T) {
	ctx := context.Background()
	fixture := seedSavedSnapshotForkFixture(t, true)

	deps, err := testQueries.GetSavedSnapshotDependencyCounts(ctx, db.GetSavedSnapshotDependencyCountsParams{
		SnapshotID: fixture.snapshotID,
		TeamID:     fixture.teamID,
	})
	if err != nil {
		t.Fatalf("GetSavedSnapshotDependencyCounts: %v", err)
	}
	if deps.ChildSandboxCount != 1 {
		t.Fatalf("child sandbox count = %d, want 1 while destroyed fork is pinned", deps.ChildSandboxCount)
	}

	childIDs, err := testQueries.ListSavedSnapshotChildSandboxIDs(ctx, db.ListSavedSnapshotChildSandboxIDsParams{
		SnapshotID: pgtype.UUID{Bytes: fixture.snapshotID, Valid: true},
		TeamID:     fixture.teamID,
	})
	if err != nil {
		t.Fatalf("ListSavedSnapshotChildSandboxIDs: %v", err)
	}
	if len(childIDs) != 1 || childIDs[0] != fixture.forkID {
		t.Fatalf("child sandbox IDs = %v, want [%s]", childIDs, fixture.forkID)
	}

	if _, err := testQueries.ClaimDeleteSavedSnapshotIfLeaf(ctx, db.ClaimDeleteSavedSnapshotIfLeafParams{
		SnapshotID: fixture.snapshotID,
		TeamID:     fixture.teamID,
	}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("delete claim with pending fork teardown error = %v, want pgx.ErrNoRows", err)
	}

	pending, err := testQueries.ListDestroyedSnapshotForksPendingPinRelease(ctx, 100)
	if err != nil {
		t.Fatalf("ListDestroyedSnapshotForksPendingPinRelease: %v", err)
	}
	var queued *db.ListDestroyedSnapshotForksPendingPinReleaseRow
	for i := range pending {
		if pending[i].ID == fixture.forkID {
			queued = &pending[i]
			break
		}
	}
	if queued == nil {
		t.Fatalf("destroyed fork %s missing from pending pin-release queue", fixture.forkID)
	}
	if queued.TeamID != fixture.teamID || queued.HostID != "snapshot-host" ||
		queued.BasePath == nil || *queued.BasePath != "/saved/base" ||
		!queued.SourceSnapshotID.Valid || queued.SourceSnapshotID.Bytes != fixture.snapshotID {
		t.Fatalf("pending teardown row = %+v, want exact host and snapshot lineage", *queued)
	}

	otherTeam, err := testQueries.CreateTeam(ctx, "snapshot-db-other-"+uuid.NewString())
	if err != nil {
		t.Fatalf("CreateTeam(other): %v", err)
	}
	if _, err := testQueries.ReleaseDestroyedSandboxSnapshotPin(ctx, db.ReleaseDestroyedSandboxSnapshotPinParams{
		SandboxID:        fixture.forkID,
		TeamID:           otherTeam.ID,
		SourceSnapshotID: queued.SourceSnapshotID,
	}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("cross-team pin release error = %v, want pgx.ErrNoRows", err)
	}

	if releasedID, err := testQueries.ReleaseDestroyedSandboxSnapshotPin(ctx, db.ReleaseDestroyedSandboxSnapshotPinParams{
		SandboxID:        fixture.forkID,
		TeamID:           fixture.teamID,
		SourceSnapshotID: queued.SourceSnapshotID,
	}); err != nil {
		t.Fatalf("ReleaseDestroyedSandboxSnapshotPin: %v", err)
	} else if releasedID != fixture.forkID {
		t.Fatalf("released sandbox ID = %s, want %s", releasedID, fixture.forkID)
	}

	deps, err = testQueries.GetSavedSnapshotDependencyCounts(ctx, db.GetSavedSnapshotDependencyCountsParams{
		SnapshotID: fixture.snapshotID,
		TeamID:     fixture.teamID,
	})
	if err != nil {
		t.Fatalf("GetSavedSnapshotDependencyCounts after release: %v", err)
	}
	if deps.ChildSandboxCount != 0 {
		t.Fatalf("child sandbox count after release = %d, want 0", deps.ChildSandboxCount)
	}
	if _, err := testQueries.ClaimDeleteSavedSnapshotIfLeaf(ctx, db.ClaimDeleteSavedSnapshotIfLeafParams{
		SnapshotID: fixture.snapshotID,
		TeamID:     fixture.teamID,
	}); err != nil {
		t.Fatalf("leaf delete claim after host teardown release: %v", err)
	}
}

func TestIntegration_LiveForkCannotRewriteSnapshotLineage(t *testing.T) {
	ctx := context.Background()
	fixture := seedSavedSnapshotForkFixture(t, false)

	_, err := testPool.Exec(ctx, `
		UPDATE sandbox
		SET source_snapshot_id = NULL, updated_at = now()
		WHERE id = $1 AND team_id = $2
	`, fixture.forkID, fixture.teamID)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
		t.Fatalf("live lineage rewrite error = %v, want PostgreSQL code 23514", err)
	}

	var sourceSnapshotID pgtype.UUID
	if err := testPool.QueryRow(ctx, `
		SELECT source_snapshot_id FROM sandbox
		WHERE id = $1 AND team_id = $2
	`, fixture.forkID, fixture.teamID).Scan(&sourceSnapshotID); err != nil {
		t.Fatalf("read fork lineage after rejected rewrite: %v", err)
	}
	if !sourceSnapshotID.Valid || sourceSnapshotID.Bytes != fixture.snapshotID {
		t.Fatalf("source_snapshot_id = %v, want %s", sourceSnapshotID, fixture.snapshotID)
	}
}

func TestIntegration_SnapshotForkActivationSkipsLegacyStorageInterval(t *testing.T) {
	ctx := context.Background()
	fixture := seedSavedSnapshotForkFixture(t, false)
	normalID := uuid.New()
	if _, err := testPool.Exec(ctx, `
		INSERT INTO sandbox (
			id, team_id, name, status, host_id, vcpu_count, memory_mib, disk_mib
		) VALUES ($1, $2, $3, 'starting', $4, 1, 1024, 4096)
	`, normalID, fixture.teamID, "normal-sandbox-"+normalID.String(), "snapshot-host"); err != nil {
		t.Fatalf("insert normal sandbox: %v", err)
	}

	for _, sandboxID := range []uuid.UUID{fixture.forkID, normalID} {
		if err := testQueries.ActivateSandbox(ctx, db.ActivateSandboxParams{
			ID:        sandboxID,
			VcpuCount: 2,
			MemoryMib: 2048,
			TeamID:    fixture.teamID,
			ActorID:   pgtype.UUID{},
		}); err != nil {
			t.Fatalf("ActivateSandbox(%s): %v", sandboxID, err)
		}
	}

	if open := countOpenComputeBillingIntervals(t, ctx, fixture.forkID); open != 1 {
		t.Fatalf("fork compute billing intervals = %d, want 1", open)
	}
	if open := countOpenStorageIntervals(t, ctx, fixture.forkID); open != 0 {
		t.Fatalf("fork legacy full-disk storage intervals = %d, want 0", open)
	}
	if open := countOpenStorageIntervals(t, ctx, normalID); open != 1 {
		t.Fatalf("normal sandbox storage intervals = %d, want 1", open)
	}

	if _, err := testQueries.ReleaseDestroyedSandboxSnapshotPin(ctx, db.ReleaseDestroyedSandboxSnapshotPinParams{
		SandboxID: fixture.forkID,
		TeamID:    fixture.teamID,
		SourceSnapshotID: pgtype.UUID{
			Bytes: fixture.snapshotID,
			Valid: true,
		},
	}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("live fork pin release error = %v, want pgx.ErrNoRows", err)
	}
}

func TestIntegration_BeginSavedSnapshotRejectsExhaustedStorageQuota(t *testing.T) {
	seedSavedSnapshotTestHost(t)
	ctx := context.Background()
	team, err := testQueries.CreateTeam(ctx, "snapshot-quota-full-"+uuid.NewString())
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		UPDATE team
		SET snapshot_storage_quota_bytes = 4096,
		    snapshot_storage_bytes = 4096
		WHERE id = $1
	`, team.ID); err != nil {
		t.Fatalf("configure exhausted snapshot quota: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_feature_flag (team_id, key, enabled)
		VALUES ($1, 'sandbox_snapshots_v1', true)
	`, team.ID); err != nil {
		t.Fatalf("enable saved snapshots: %v", err)
	}

	sourceID := uuid.New()
	if _, err := testPool.Exec(ctx, `
		INSERT INTO sandbox (id, team_id, name, status, host_id)
		VALUES ($1, $2, $3, 'active', $4)
	`, sourceID, team.ID, "quota-source-"+sourceID.String(), "snapshot-host"); err != nil {
		t.Fatalf("insert source sandbox: %v", err)
	}

	snapshotID := uuid.New()
	_, err = testQueries.BeginSavedSnapshot(ctx, db.BeginSavedSnapshotParams{
		SnapshotID: snapshotID,
		Trigger:    "manual",
		SandboxID:  sourceID,
		TeamID:     team.ID,
	})
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "SS005" {
		t.Fatalf("BeginSavedSnapshot error = %v, want PostgreSQL code SS005", err)
	}

	var operationID pgtype.UUID
	if err := testPool.QueryRow(ctx, `
		SELECT snapshot_operation_id FROM sandbox WHERE id = $1
	`, sourceID).Scan(&operationID); err != nil {
		t.Fatalf("read source operation claim: %v", err)
	}
	if operationID.Valid {
		t.Fatalf("source operation claim survived rejected admission: %s", operationID.Bytes)
	}
	var snapshotCount int
	if err := testPool.QueryRow(ctx, `
		SELECT count(*) FROM snapshot WHERE id = $1
	`, snapshotID).Scan(&snapshotCount); err != nil {
		t.Fatalf("count rejected snapshot: %v", err)
	}
	if snapshotCount != 0 {
		t.Fatalf("saved snapshot rows after rejected admission = %d, want 0", snapshotCount)
	}
}

func TestIntegration_LockActiveTeamSecretIDsFiltersAndOrders(t *testing.T) {
	ctx := context.Background()
	team, err := testQueries.CreateTeam(ctx, "snapshot-secret-lock-"+uuid.NewString())
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	otherTeam, err := testQueries.CreateTeam(ctx, "snapshot-secret-lock-other-"+uuid.NewString())
	if err != nil {
		t.Fatalf("CreateTeam(other): %v", err)
	}

	activeIDs := []uuid.UUID{uuid.New(), uuid.New()}
	deletedID := uuid.New()
	otherTeamID := uuid.New()
	for _, fixture := range []struct {
		id        uuid.UUID
		teamID    uuid.UUID
		name      string
		deletedAt any
	}{
		{id: activeIDs[0], teamID: team.ID, name: "active-a"},
		{id: activeIDs[1], teamID: team.ID, name: "active-b"},
		{id: deletedID, teamID: team.ID, name: "deleted", deletedAt: time.Now()},
		{id: otherTeamID, teamID: otherTeam.ID, name: "other-team"},
	} {
		if _, err := testPool.Exec(ctx, `
			INSERT INTO secret (
				id, team_id, name, auth_type, hosts, ciphertext,
				encrypted_dek, kek_id, deleted_at
			) VALUES (
				$1, $2, $3, 'bearer', ARRAY['api.example.test'],
				decode('01', 'hex'), decode('02', 'hex'), 'test-kek', $4
			)
		`, fixture.id, fixture.teamID, fixture.name, fixture.deletedAt); err != nil {
			t.Fatalf("insert secret %s: %v", fixture.name, err)
		}
	}

	candidates := []uuid.UUID{otherTeamID, activeIDs[1], deletedID, activeIDs[0]}
	locked, err := testQueries.LockActiveTeamSecretIDs(ctx, db.LockActiveTeamSecretIDsParams{
		TeamID:    team.ID,
		SecretIds: candidates,
	})
	if err != nil {
		t.Fatalf("LockActiveTeamSecretIDs: %v", err)
	}
	sort.Slice(activeIDs, func(i, j int) bool {
		return activeIDs[i].String() < activeIDs[j].String()
	})
	if len(locked) != len(activeIDs) {
		t.Fatalf("locked secret IDs = %v, want %v", locked, activeIDs)
	}
	for i := range activeIDs {
		if locked[i] != activeIDs[i] {
			t.Fatalf("locked secret IDs = %v, want ordered %v", locked, activeIDs)
		}
	}
}

func TestIntegration_UpsertSandboxRevocationNeverShortensExpiry(t *testing.T) {
	ctx := context.Background()
	sandboxID := uuid.New()
	longExpiry := time.Now().UTC().Truncate(time.Microsecond).Add(2 * time.Hour)
	shortExpiry := longExpiry.Add(-time.Hour)

	for _, expiresAt := range []time.Time{longExpiry, shortExpiry} {
		if err := testQueries.UpsertSandboxRevocation(ctx, db.UpsertSandboxRevocationParams{
			SandboxID: sandboxID,
			ExpiresAt: expiresAt,
		}); err != nil {
			t.Fatalf("UpsertSandboxRevocation(%s): %v", expiresAt, err)
		}
	}
	var stored time.Time
	if err := testPool.QueryRow(ctx, `
		SELECT expires_at FROM sandbox_revocation WHERE sandbox_id = $1
	`, sandboxID).Scan(&stored); err != nil {
		t.Fatalf("read sandbox revocation: %v", err)
	}
	if !stored.Equal(longExpiry) {
		t.Fatalf("revocation expiry after older retry = %s, want %s", stored, longExpiry)
	}

	laterExpiry := longExpiry.Add(time.Hour)
	if err := testQueries.UpsertSandboxRevocation(ctx, db.UpsertSandboxRevocationParams{
		SandboxID: sandboxID,
		ExpiresAt: laterExpiry,
	}); err != nil {
		t.Fatalf("UpsertSandboxRevocation(later): %v", err)
	}
	if err := testPool.QueryRow(ctx, `
		SELECT expires_at FROM sandbox_revocation WHERE sandbox_id = $1
	`, sandboxID).Scan(&stored); err != nil {
		t.Fatalf("read extended sandbox revocation: %v", err)
	}
	if !stored.Equal(laterExpiry) {
		t.Fatalf("extended revocation expiry = %s, want %s", stored, laterExpiry)
	}
}

func TestIntegration_FailSavedSnapshotAndSourcePersistsRevocationAtomically(t *testing.T) {
	seedSavedSnapshotTestHost(t)
	ctx := context.Background()
	team, err := testQueries.CreateTeam(ctx, "snapshot-source-failure-"+uuid.NewString())
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE team SET snapshot_storage_quota_bytes = 1073741824 WHERE id = $1`, team.ID); err != nil {
		t.Fatalf("configure snapshot quota: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_feature_flag (team_id, key, enabled)
		VALUES ($1, 'sandbox_snapshots_v1', true)
	`, team.ID); err != nil {
		t.Fatalf("enable snapshot feature: %v", err)
	}

	sourceID, snapshotID := uuid.New(), uuid.New()
	if _, err := testPool.Exec(ctx, `
		INSERT INTO sandbox (
			id, team_id, name, status, host_id, vcpu_count, memory_mib, disk_mib
		) VALUES ($1, $2, $3, 'active', 'snapshot-host', 2, 2048, 8192)
	`, sourceID, team.ID, "source-"+sourceID.String()); err != nil {
		t.Fatalf("insert source sandbox: %v", err)
	}
	if _, err := testQueries.BeginSavedSnapshot(ctx, db.BeginSavedSnapshotParams{
		SnapshotID: snapshotID,
		SandboxID:  sourceID,
		TeamID:     team.ID,
		Trigger:    "manual",
	}); err != nil {
		t.Fatalf("BeginSavedSnapshot: %v", err)
	}

	expiresAt := time.Now().UTC().Truncate(time.Microsecond).Add(90 * 24 * time.Hour)
	reason := "source_resume_failed"
	if _, err := testQueries.FailSavedSnapshotAndSource(ctx, db.FailSavedSnapshotAndSourceParams{
		SnapshotID:          snapshotID,
		TeamID:              team.ID,
		RevocationExpiresAt: expiresAt,
		FailureReason:       &reason,
	}); err != nil {
		t.Fatalf("FailSavedSnapshotAndSource: %v", err)
	}

	var sourceStatus, snapshotStatus string
	var operationID pgtype.UUID
	var storedExpiry time.Time
	if err := testPool.QueryRow(ctx, `
		SELECT source.status, source.snapshot_operation_id, snap.status, revoke.expires_at
		FROM sandbox source
		JOIN snapshot snap ON snap.id = $2 AND snap.sandbox_id = source.id
		JOIN sandbox_revocation revoke ON revoke.sandbox_id = source.id
		WHERE source.id = $1
	`, sourceID, snapshotID).Scan(&sourceStatus, &operationID, &snapshotStatus, &storedExpiry); err != nil {
		t.Fatalf("read terminal state: %v", err)
	}
	if sourceStatus != "failed" || snapshotStatus != "failed" || operationID.Valid || !storedExpiry.Equal(expiresAt) {
		t.Fatalf("terminal state source=%s snapshot=%s operation=%v expiry=%s, want failed/failed/empty/%s",
			sourceStatus, snapshotStatus, operationID, storedExpiry, expiresAt)
	}
}

func TestIntegration_FinalizeSavedSnapshotEnforcesActualLayerQuotaAtomically(t *testing.T) {
	seedSavedSnapshotTestHost(t)
	ctx := context.Background()
	team, err := testQueries.CreateTeam(ctx, "snapshot-finalize-quota-"+uuid.NewString())
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		UPDATE team SET snapshot_storage_quota_bytes = 149 WHERE id = $1
	`, team.ID); err != nil {
		t.Fatalf("configure snapshot quota: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_feature_flag (team_id, key, enabled)
		VALUES ($1, 'sandbox_snapshots_v1', true)
	`, team.ID); err != nil {
		t.Fatalf("enable snapshot feature: %v", err)
	}

	sourceID, snapshotID := uuid.New(), uuid.New()
	if _, err := testPool.Exec(ctx, `
		INSERT INTO sandbox (
			id, team_id, name, status, host_id, vcpu_count, memory_mib, disk_mib
		) VALUES ($1, $2, $3, 'active', $4, 2, 2048, 8192)
	`, sourceID, team.ID, "finalize-quota-source-"+sourceID.String(), "snapshot-host"); err != nil {
		t.Fatalf("insert source sandbox: %v", err)
	}
	if _, err := testQueries.BeginSavedSnapshot(ctx, db.BeginSavedSnapshotParams{
		SnapshotID: snapshotID,
		SandboxID:  sourceID,
		TeamID:     team.ID,
		Trigger:    "manual",
	}); err != nil {
		t.Fatalf("BeginSavedSnapshot: %v", err)
	}

	digest := "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	_, err = testQueries.FinalizeSavedSnapshot(ctx, db.FinalizeSavedSnapshotParams{
		SnapshotID:         snapshotID,
		TeamID:             team.ID,
		Path:               "/saved/disk",
		MemPath:            "/saved/memory",
		LogicalSizeBytes:   1000,
		ManifestPath:       "/saved/manifest.json",
		ManifestDigest:     &digest,
		ArtifactMetadata:   []byte(`{"schema_version":1,"source_logical_size_bytes":500,"source_exclusive_size_bytes":50}`),
		ExclusiveSizeBytes: 100,
	})
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "SS005" {
		t.Fatalf("FinalizeSavedSnapshot error = %v, want PostgreSQL code SS005", err)
	}

	usage, err := testQueries.GetTeamSnapshotLayerUsage(ctx, team.ID)
	if err != nil {
		t.Fatalf("GetTeamSnapshotLayerUsage: %v", err)
	}
	if usage.ExclusiveSizeBytes != 0 || usage.ActiveLayerCount != 0 {
		t.Fatalf("rolled-back layer usage = %+v, want zero", usage)
	}
	var counter int64
	var status string
	if err := testPool.QueryRow(ctx, `
		SELECT t.snapshot_storage_bytes, s.status
		FROM team t
		JOIN snapshot s ON s.team_id = t.id AND s.id = $2
		WHERE t.id = $1
	`, team.ID, snapshotID).Scan(&counter, &status); err != nil {
		t.Fatalf("read rolled-back quota state: %v", err)
	}
	if counter != 0 || status != "creating" {
		t.Fatalf("rolled-back quota state counter=%d status=%s, want 0/creating", counter, status)
	}
}

func TestIntegration_SavedSnapshotForkAdmissionSerializesHostCapacity(t *testing.T) {
	ctx := context.Background()
	team, err := testQueries.CreateTeam(ctx, "snapshot-host-capacity-"+uuid.NewString())
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	hostID := "snapshot-capacity-" + uuid.NewString()
	if _, err := testPool.Exec(ctx, `UPDATE team SET snapshot_storage_quota_bytes = 1073741824 WHERE id = $1`, team.ID); err != nil {
		t.Fatalf("configure snapshot quota: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO host (id, vmd_addr, proxy_addr, region, capacity_memory_mib, capacity_vcpus)
		VALUES ($1, '127.0.0.1:1', '127.0.0.1:2', 'test', 2048, 2)
	`, hostID); err != nil {
		t.Fatalf("configure capacity host: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_feature_flag (team_id, key, enabled)
		VALUES ($1, 'sandbox_snapshots_v1', true)
	`, team.ID); err != nil {
		t.Fatalf("enable snapshot feature: %v", err)
	}
	sourceID, snapshotID := uuid.New(), uuid.New()
	if _, err := testPool.Exec(ctx, `
		INSERT INTO sandbox (id, team_id, name, status, host_id, vcpu_count, memory_mib, disk_mib)
		VALUES ($1, $2, $3, 'paused', $4, 2, 2048, 8192)
	`, sourceID, team.ID, "source-"+sourceID.String(), hostID); err != nil {
		t.Fatalf("seed capacity source: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO snapshot (
			id, sandbox_id, team_id, path, mem_path, size_bytes, trigger,
			kind, status, source_status, host_id, vcpu_count, memory_mib,
			disk_mib, manifest_path, manifest_digest
		) VALUES ($1, $2, $3, '/saved/disk', '/saved/memory', 0, 'manual',
			'saved', 'ready', 'paused', $4, 2, 2048, 8192, '/saved/manifest.json', repeat('b', 64))
	`, snapshotID, sourceID, team.ID, hostID); err != nil {
		t.Fatalf("seed capacity snapshot: %v", err)
	}

	create := func(id uuid.UUID) error {
		_, err := testQueries.CreateSandboxFromSnapshot(ctx, db.CreateSandboxFromSnapshotParams{
			ID:                       id,
			TeamID:                   team.ID,
			Name:                     "fork-" + id.String(),
			Status:                   db.SandboxStatusStarting,
			InheritTimeoutSeconds:    true,
			Metadata:                 []byte(`{}`),
			InheritAutoDeleteSeconds: true,
			InheritNetworkConfig:     true,
			SourceSnapshotID:         snapshotID,
		})
		return err
	}
	if err := create(uuid.New()); err != nil {
		t.Fatalf("first capacity admission: %v", err)
	}
	err = create(uuid.New())
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "SS006" {
		t.Fatalf("second capacity admission error = %v, want SS006", err)
	}
}

func TestIntegration_SavedSnapshotLayerLedgerCountsSharedLayersOnce(t *testing.T) {
	ctx := context.Background()
	team, err := testQueries.CreateTeam(ctx, "snapshot-layer-ledger-"+uuid.NewString())
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	hostID := "snapshot-layer-ledger-" + uuid.NewString()
	if _, err := testPool.Exec(ctx, `
		UPDATE team SET snapshot_storage_quota_bytes = 1073741824 WHERE id = $1
	`, team.ID); err != nil {
		t.Fatalf("configure layer-ledger team: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_feature_flag (team_id, key, enabled)
		VALUES ($1, 'sandbox_snapshots_v1', true)
	`, team.ID); err != nil {
		t.Fatalf("enable layer-ledger feature: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO host (
			id, vmd_addr, proxy_addr, region,
			capacity_memory_mib, capacity_vcpus
		) VALUES ($1, '127.0.0.1:1', '127.0.0.1:2', 'test', 65536, 64)
	`, hostID); err != nil {
		t.Fatalf("configure layer-ledger fixture: %v", err)
	}

	sourceID, snapshotID := uuid.New(), uuid.New()
	if _, err := testPool.Exec(ctx, `
		INSERT INTO sandbox (
			id, team_id, name, status, host_id,
			vcpu_count, memory_mib, disk_mib
		) VALUES ($1, $2, $3, 'active', $4, 2, 2048, 8192)
	`, sourceID, team.ID, "layer-source-"+sourceID.String(), hostID); err != nil {
		t.Fatalf("insert source: %v", err)
	}
	if _, err := testQueries.BeginSavedSnapshot(ctx, db.BeginSavedSnapshotParams{
		SnapshotID: snapshotID,
		SandboxID:  sourceID,
		TeamID:     team.ID,
		Trigger:    "manual",
	}); err != nil {
		t.Fatalf("BeginSavedSnapshot: %v", err)
	}
	digest := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	if _, err := testQueries.FinalizeSavedSnapshot(ctx, db.FinalizeSavedSnapshotParams{
		SnapshotID:         snapshotID,
		TeamID:             team.ID,
		Path:               "/saved/disk",
		MemPath:            "/saved/memory",
		LogicalSizeBytes:   1000,
		ManifestPath:       "/saved/manifest.json",
		ManifestDigest:     &digest,
		ArtifactMetadata:   []byte(`{"schema_version":1,"source_logical_size_bytes":500,"source_exclusive_size_bytes":50}`),
		ExclusiveSizeBytes: 100,
	}); err != nil {
		t.Fatalf("FinalizeSavedSnapshot: %v", err)
	}

	assertUsage := func(wantLogical, wantExclusive, wantLayers int64) {
		t.Helper()
		usage, err := testQueries.GetTeamSnapshotLayerUsage(ctx, team.ID)
		if err != nil {
			t.Fatalf("GetTeamSnapshotLayerUsage: %v", err)
		}
		if usage.LogicalSizeBytes != wantLogical || usage.ExclusiveSizeBytes != wantExclusive || usage.ActiveLayerCount != wantLayers {
			t.Fatalf("layer usage = %+v, want logical=%d exclusive=%d layers=%d", usage, wantLogical, wantExclusive, wantLayers)
		}
		var counter int64
		if err := testPool.QueryRow(ctx, `SELECT snapshot_storage_bytes FROM team WHERE id = $1`, team.ID).Scan(&counter); err != nil {
			t.Fatalf("read team shadow counter: %v", err)
		}
		if counter != wantExclusive {
			t.Fatalf("team shadow counter = %d, want %d", counter, wantExclusive)
		}
	}
	assertUsage(1500, 150, 3)

	// The source's measured current layer includes both bytes a future capture
	// can retain by reflink and source-only bytes such as copied sidecars.
	if _, err := testQueries.RecordSandboxWritableLayerUsage(ctx, db.RecordSandboxWritableLayerUsageParams{
		LogicalSizeBytes:   300,
		ExclusiveSizeBytes: 75,
		SandboxID:          sourceID,
		TeamID:             team.ID,
	}); err != nil {
		t.Fatalf("RecordSandboxWritableLayerUsage(source): %v", err)
	}
	assertUsage(1800, 225, 3)

	secondSnapshotID := uuid.New()
	if _, err := testQueries.BeginSavedSnapshot(ctx, db.BeginSavedSnapshotParams{
		SnapshotID: secondSnapshotID,
		SandboxID:  sourceID,
		TeamID:     team.ID,
		Trigger:    "manual",
	}); err != nil {
		t.Fatalf("BeginSavedSnapshot(second): %v", err)
	}
	secondDigest := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	if _, err := testQueries.FinalizeSavedSnapshot(ctx, db.FinalizeSavedSnapshotParams{
		SnapshotID:         secondSnapshotID,
		TeamID:             team.ID,
		Path:               "/saved/disk-2",
		MemPath:            "/saved/memory-2",
		LogicalSizeBytes:   100,
		ManifestPath:       "/saved/manifest-2.json",
		ManifestDigest:     &secondDigest,
		ArtifactMetadata:   []byte(`{"schema_version":1,"source_logical_size_bytes":200,"source_exclusive_size_bytes":50}`),
		ExclusiveSizeBytes: 10,
	}); err != nil {
		t.Fatalf("FinalizeSavedSnapshot(second): %v", err)
	}
	// The second capture seals 200/50, retains the 100/25 source-only
	// remainder in a fresh current row, and adds its own 100/10 layer.
	assertUsage(1900, 235, 5)

	forkIDs := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
	for _, forkID := range forkIDs {
		if _, err := testQueries.CreateSandboxFromSnapshot(ctx, db.CreateSandboxFromSnapshotParams{
			ID:                       forkID,
			TeamID:                   team.ID,
			Name:                     "layer-fork-" + forkID.String(),
			Status:                   db.SandboxStatusStarting,
			InheritTimeoutSeconds:    true,
			Metadata:                 []byte(`{}`),
			InheritAutoDeleteSeconds: true,
			InheritNetworkConfig:     true,
			SourceSnapshotID:         snapshotID,
		}); err != nil {
			t.Fatalf("CreateSandboxFromSnapshot(%s): %v", forkID, err)
		}
	}
	assertUsage(1900, 235, 8)

	layers, err := testQueries.ListSnapshotStorageLayersForTeam(ctx, team.ID)
	if err != nil {
		t.Fatalf("ListSnapshotStorageLayersForTeam: %v", err)
	}
	var snapshotLayerID, sourceCurrentLayerID int64
	var sourceGenerationCount int
	for _, layer := range layers {
		if layer.Kind == db.SnapshotStorageLayerKindSavedSnapshot && layer.OwnerSnapshotID.Valid && layer.OwnerSnapshotID.Bytes == snapshotID {
			snapshotLayerID = layer.ID
		}
		if layer.OwnerSandboxID.Valid && layer.OwnerSandboxID.Bytes == sourceID {
			switch layer.Kind {
			case db.SnapshotStorageLayerKindSandboxGeneration:
				sourceGenerationCount++
			case db.SnapshotStorageLayerKindSandboxWritable:
				sourceCurrentLayerID = layer.ID
				if layer.CurrentLogicalSizeBytes != 100 || layer.CurrentExclusiveSizeBytes != 25 {
					t.Fatalf("replacement source current layer = %+v, want current logical=100 exclusive=25", layer)
				}
			}
		}
	}
	if snapshotLayerID == 0 {
		t.Fatal("saved-snapshot layer was not created")
	}
	if sourceGenerationCount != 2 || sourceCurrentLayerID == 0 {
		t.Fatalf("source layers generation_count=%d current=%d, want 2 generations and one current", sourceGenerationCount, sourceCurrentLayerID)
	}
	refs, err := testQueries.GetSnapshotStorageReferenceCounts(ctx, db.GetSnapshotStorageReferenceCountsParams{
		LayerID: snapshotLayerID,
		TeamID:  team.ID,
	})
	if err != nil {
		t.Fatalf("GetSnapshotStorageReferenceCounts: %v", err)
	}
	if refs.SnapshotReferenceCount != 1 || refs.SandboxReferenceCount != 3 {
		t.Fatalf("snapshot layer refs = %+v, want snapshot=1 sandbox=3", refs)
	}
	currentRefs, err := testQueries.GetSnapshotStorageReferenceCounts(ctx, db.GetSnapshotStorageReferenceCountsParams{
		LayerID: sourceCurrentLayerID,
		TeamID:  team.ID,
	})
	if err != nil {
		t.Fatalf("GetSnapshotStorageReferenceCounts(source current): %v", err)
	}
	if currentRefs.SnapshotReferenceCount != 0 || currentRefs.SandboxReferenceCount != 1 {
		t.Fatalf("source current refs = %+v, want snapshot=0 sandbox=1", currentRefs)
	}

	if _, err := testQueries.RecordSandboxWritableLayerUsage(ctx, db.RecordSandboxWritableLayerUsageParams{
		LogicalSizeBytes:   250,
		ExclusiveSizeBytes: 25,
		SandboxID:          forkIDs[0],
		TeamID:             team.ID,
	}); err != nil {
		t.Fatalf("RecordSandboxWritableLayerUsage: %v", err)
	}
	assertUsage(2150, 260, 8)

	for _, forkID := range forkIDs {
		if _, err := testPool.Exec(ctx, `
			UPDATE sandbox
			SET status = 'deleted', destroyed_at = now(), updated_at = now()
			WHERE id = $1 AND team_id = $2
		`, forkID, team.ID); err != nil {
			t.Fatalf("soft-delete fork %s: %v", forkID, err)
		}
		if _, err := testQueries.ReleaseDestroyedSandboxSnapshotPin(ctx, db.ReleaseDestroyedSandboxSnapshotPinParams{
			SandboxID: forkID,
			TeamID:    team.ID,
			SourceSnapshotID: pgtype.UUID{
				Bytes: snapshotID,
				Valid: true,
			},
		}); err != nil {
			t.Fatalf("ReleaseDestroyedSandboxSnapshotPin(%s): %v", forkID, err)
		}
	}
	assertUsage(1900, 235, 5)

	// Source-only remainder lives only in the replacement mutable generation.
	// Releasing the source must drop those 25 exclusive bytes even while older
	// snapshots still pin both sealed generations.
	if _, err := testPool.Exec(ctx, `
		UPDATE sandbox
		SET status = 'deleted', destroyed_at = now(), updated_at = now()
		WHERE id = $1 AND team_id = $2
	`, sourceID, team.ID); err != nil {
		t.Fatalf("soft-delete source: %v", err)
	}
	assertUsage(1800, 210, 4)

	if _, err := testQueries.ClaimDeleteSavedSnapshotIfLeaf(ctx, db.ClaimDeleteSavedSnapshotIfLeafParams{
		SnapshotID: snapshotID,
		TeamID:     team.ID,
	}); err != nil {
		t.Fatalf("ClaimDeleteSavedSnapshotIfLeaf: %v", err)
	}
	if _, err := testQueries.FinalizeSavedSnapshotDelete(ctx, db.FinalizeSavedSnapshotDeleteParams{
		SnapshotID: snapshotID,
		TeamID:     team.ID,
	}); err != nil {
		t.Fatalf("FinalizeSavedSnapshotDelete: %v", err)
	}
	// The second snapshot still pins both source generations, but not the first
	// snapshot's own artifact layer.
	assertUsage(800, 110, 3)

	if _, err := testQueries.ClaimDeleteSavedSnapshotIfLeaf(ctx, db.ClaimDeleteSavedSnapshotIfLeafParams{
		SnapshotID: secondSnapshotID,
		TeamID:     team.ID,
	}); err != nil {
		t.Fatalf("ClaimDeleteSavedSnapshotIfLeaf(second): %v", err)
	}
	if _, err := testQueries.FinalizeSavedSnapshotDelete(ctx, db.FinalizeSavedSnapshotDeleteParams{
		SnapshotID: secondSnapshotID,
		TeamID:     team.ID,
	}); err != nil {
		t.Fatalf("FinalizeSavedSnapshotDelete(second): %v", err)
	}
	assertUsage(0, 0, 0)
}

func TestIntegration_WritableMeasurementCollapsesOwnerOnlySourceGenerations(t *testing.T) {
	seedSavedSnapshotTestHost(t)
	ctx := context.Background()
	team, err := testQueries.CreateTeam(ctx, "snapshot-generation-collapse-"+uuid.NewString())
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		UPDATE team SET snapshot_storage_quota_bytes = 1073741824 WHERE id = $1
	`, team.ID); err != nil {
		t.Fatalf("configure snapshot quota: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_feature_flag (team_id, key, enabled)
		VALUES ($1, 'sandbox_snapshots_v1', true)
	`, team.ID); err != nil {
		t.Fatalf("enable snapshot feature: %v", err)
	}

	sourceID := uuid.New()
	if _, err := testPool.Exec(ctx, `
		INSERT INTO sandbox (
			id, team_id, name, status, host_id,
			vcpu_count, memory_mib, disk_mib
		) VALUES ($1, $2, $3, 'paused', 'snapshot-host', 2, 2048, 8192)
	`, sourceID, team.ID, "generation-collapse-source-"+sourceID.String()); err != nil {
		t.Fatalf("insert source: %v", err)
	}

	finalize := func(snapshotID uuid.UUID, logical, exclusive, sourceLogical, sourceExclusive int64, digest string) {
		t.Helper()
		if _, err := testQueries.BeginSavedSnapshot(ctx, db.BeginSavedSnapshotParams{
			SnapshotID: snapshotID,
			SandboxID:  sourceID,
			TeamID:     team.ID,
			Trigger:    "manual",
		}); err != nil {
			t.Fatalf("BeginSavedSnapshot(%s): %v", snapshotID, err)
		}
		metadata := []byte(fmt.Sprintf(
			`{"schema_version":1,"source_logical_size_bytes":%d,"source_exclusive_size_bytes":%d}`,
			sourceLogical, sourceExclusive,
		))
		if _, err := testQueries.FinalizeSavedSnapshot(ctx, db.FinalizeSavedSnapshotParams{
			SnapshotID:         snapshotID,
			TeamID:             team.ID,
			Path:               "/saved/" + snapshotID.String() + "/disk",
			MemPath:            "/saved/" + snapshotID.String() + "/memory",
			LogicalSizeBytes:   logical,
			ManifestPath:       "/saved/" + snapshotID.String() + "/manifest.json",
			ManifestDigest:     &digest,
			ArtifactMetadata:   metadata,
			ExclusiveSizeBytes: exclusive,
		}); err != nil {
			t.Fatalf("FinalizeSavedSnapshot(%s): %v", snapshotID, err)
		}
	}
	remove := func(snapshotID uuid.UUID) {
		t.Helper()
		if _, err := testQueries.ClaimDeleteSavedSnapshotIfLeaf(ctx, db.ClaimDeleteSavedSnapshotIfLeafParams{
			SnapshotID: snapshotID,
			TeamID:     team.ID,
		}); err != nil {
			t.Fatalf("ClaimDeleteSavedSnapshotIfLeaf(%s): %v", snapshotID, err)
		}
		if _, err := testQueries.FinalizeSavedSnapshotDelete(ctx, db.FinalizeSavedSnapshotDeleteParams{
			SnapshotID: snapshotID,
			TeamID:     team.ID,
		}); err != nil {
			t.Fatalf("FinalizeSavedSnapshotDelete(%s): %v", snapshotID, err)
		}
	}
	assertUsage := func(wantLogical, wantExclusive, wantLayers int64) {
		t.Helper()
		usage, err := testQueries.GetTeamSnapshotLayerUsage(ctx, team.ID)
		if err != nil {
			t.Fatalf("GetTeamSnapshotLayerUsage: %v", err)
		}
		if usage.LogicalSizeBytes != wantLogical || usage.ExclusiveSizeBytes != wantExclusive || usage.ActiveLayerCount != wantLayers {
			t.Fatalf("layer usage = %+v, want logical=%d exclusive=%d layers=%d", usage, wantLogical, wantExclusive, wantLayers)
		}
		var counter int64
		if err := testPool.QueryRow(ctx, `SELECT snapshot_storage_bytes FROM team WHERE id = $1`, team.ID).Scan(&counter); err != nil {
			t.Fatalf("read team shadow counter: %v", err)
		}
		if counter != wantExclusive {
			t.Fatalf("team shadow counter = %d, want %d", counter, wantExclusive)
		}
	}

	firstSnapshotID := uuid.New()
	finalize(firstSnapshotID, 100, 10, 400, 40, strings.Repeat("a", 64))
	if _, err := testQueries.RecordSandboxWritableLayerUsage(ctx, db.RecordSandboxWritableLayerUsageParams{
		LogicalSizeBytes:   200,
		ExclusiveSizeBytes: 20,
		SandboxID:          sourceID,
		TeamID:             team.ID,
	}); err != nil {
		t.Fatalf("RecordSandboxWritableLayerUsage(initial): %v", err)
	}

	secondSnapshotID := uuid.New()
	finalize(secondSnapshotID, 70, 7, 150, 15, strings.Repeat("b", 64))
	assertUsage(770, 77, 5)

	// Removing one clone must not collapse either source generation: the second
	// snapshot still references both, so its physical reflinks still exclude
	// those extents from VMD's writable measurement.
	remove(firstSnapshotID)
	if _, err := testQueries.RecordSandboxWritableLayerUsage(ctx, db.RecordSandboxWritableLayerUsageParams{
		LogicalSizeBytes:   50,
		ExclusiveSizeBytes: 5,
		SandboxID:          sourceID,
		TeamID:             team.ID,
	}); err != nil {
		t.Fatalf("RecordSandboxWritableLayerUsage(shared generations): %v", err)
	}
	assertUsage(670, 67, 4)

	// Once the final clone is removed, both sealed generations have only their
	// owner-source references. The deletion transaction folds their 55 retained
	// bytes into the current row and retires both rows without changing the team
	// total. This closes the window in which an immediate recapture could seal R
	// a second time before another pause measurement.
	remove(secondSnapshotID)
	assertUsage(600, 60, 1)

	thirdSnapshotID := uuid.New()
	finalize(thirdSnapshotID, 20, 2, 600, 60, strings.Repeat("c", 64))
	assertUsage(620, 62, 3)
	remove(thirdSnapshotID)
	assertUsage(600, 60, 1)

	// Simulate an owner-only generation left by an older control-plane writer.
	// Pause reconciliation is the defensive repair: it first folds the stale
	// generation transactionally, then replaces current with VMD's authoritative
	// full-inode result. The intermediate fold cannot leak into the team counter.
	var legacyGenerationID int64
	if err := testPool.QueryRow(ctx, `
		INSERT INTO snapshot_storage_layer (
			team_id, kind, owner_sandbox_id,
			retained_logical_size_bytes, retained_exclusive_size_bytes
		) VALUES ($1, 'sandbox_generation', $2, 100, 10)
		RETURNING id
	`, team.ID, sourceID).Scan(&legacyGenerationID); err != nil {
		t.Fatalf("insert legacy owner-only generation: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO snapshot_storage_reference (layer_id, team_id, sandbox_id)
		VALUES ($1, $2, $3)
	`, legacyGenerationID, team.ID, sourceID); err != nil {
		t.Fatalf("insert legacy owner-only reference: %v", err)
	}
	assertUsage(700, 70, 2)
	if _, err := testQueries.RecordSandboxWritableLayerUsage(ctx, db.RecordSandboxWritableLayerUsageParams{
		LogicalSizeBytes:   600,
		ExclusiveSizeBytes: 60,
		SandboxID:          sourceID,
		TeamID:             team.ID,
	}); err != nil {
		t.Fatalf("RecordSandboxWritableLayerUsage(legacy owner-only generation): %v", err)
	}
	assertUsage(600, 60, 1)

	var activeGenerations, activeGenerationRefs int64
	if err := testPool.QueryRow(ctx, `
		SELECT
			count(DISTINCT layer.id) FILTER (WHERE layer.ended_at IS NULL),
			count(ref.id) FILTER (WHERE ref.released_at IS NULL)
		FROM snapshot_storage_layer layer
		LEFT JOIN snapshot_storage_reference ref ON ref.layer_id = layer.id
		WHERE layer.team_id = $1
		  AND layer.owner_sandbox_id = $2
		  AND layer.kind = 'sandbox_generation'
	`, team.ID, sourceID).Scan(&activeGenerations, &activeGenerationRefs); err != nil {
		t.Fatalf("read collapsed generations: %v", err)
	}
	if activeGenerations != 0 || activeGenerationRefs != 0 {
		t.Fatalf("active generations=%d active refs=%d, want 0/0", activeGenerations, activeGenerationRefs)
	}

	if _, err := testPool.Exec(ctx, `
		UPDATE sandbox
		SET status = 'deleted', destroyed_at = now(), updated_at = now()
		WHERE id = $1 AND team_id = $2
	`, sourceID, team.ID); err != nil {
		t.Fatalf("delete reconciled source: %v", err)
	}
	assertUsage(0, 0, 0)
}

func TestIntegration_SavedSnapshotForkResumeSerializesHostCapacity(t *testing.T) {
	ctx := context.Background()
	team, err := testQueries.CreateTeam(ctx, "snapshot-resume-capacity-"+uuid.NewString())
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	hostID := "snapshot-resume-capacity-" + uuid.NewString()
	if _, err := testPool.Exec(ctx, `
		UPDATE team SET snapshot_storage_quota_bytes = 1073741824 WHERE id = $1
	`, team.ID); err != nil {
		t.Fatalf("configure resume-capacity team: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO host (id, vmd_addr, proxy_addr, region, capacity_memory_mib, capacity_vcpus)
		VALUES ($1, '127.0.0.1:1', '127.0.0.1:2', 'test', 2048, 2)
	`, hostID); err != nil {
		t.Fatalf("configure resume-capacity fixture: %v", err)
	}

	sourceID, snapshotID := uuid.New(), uuid.New()
	if _, err := testPool.Exec(ctx, `
		INSERT INTO sandbox (id, team_id, name, status, host_id, vcpu_count, memory_mib, disk_mib)
		VALUES ($1, $2, $3, 'paused', $4, 2, 2048, 8192)
	`, sourceID, team.ID, "resume-source-"+sourceID.String(), hostID); err != nil {
		t.Fatalf("seed resume source: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO snapshot (
			id, sandbox_id, team_id, path, mem_path, size_bytes, trigger,
			kind, status, source_status, host_id, vcpu_count, memory_mib,
			disk_mib, manifest_path, manifest_digest
		) VALUES ($1, $2, $3, '/saved/disk', '/saved/memory', 0, 'manual',
			'saved', 'ready', 'paused', $4, 2, 2048, 8192,
			'/saved/manifest.json', repeat('d', 64))
	`, snapshotID, sourceID, team.ID, hostID); err != nil {
		t.Fatalf("seed resume snapshot: %v", err)
	}

	forkIDs := []uuid.UUID{uuid.New(), uuid.New()}
	for _, forkID := range forkIDs {
		if _, err := testPool.Exec(ctx, `
			INSERT INTO sandbox (
				id, team_id, name, status, host_id, vcpu_count,
				memory_mib, disk_mib, source_snapshot_id
			) VALUES ($1, $2, $3, 'paused', $4, 2, 2048, 8192, $5)
		`, forkID, team.ID, "resume-fork-"+forkID.String(), hostID, snapshotID); err != nil {
			t.Fatalf("seed paused fork: %v", err)
		}
	}
	if _, err := testQueries.BeginResume(ctx, db.BeginResumeParams{ID: forkIDs[0], TeamID: team.ID}); err != nil {
		t.Fatalf("first BeginResume: %v", err)
	}
	_, err = testQueries.BeginResume(ctx, db.BeginResumeParams{ID: forkIDs[1], TeamID: team.ID})
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "SS006" {
		t.Fatalf("second BeginResume error = %v, want SS006", err)
	}
	if err := testQueries.RevertResumeToPaused(ctx, db.RevertResumeToPausedParams{ID: forkIDs[0], TeamID: team.ID}); err != nil {
		t.Fatalf("RevertResumeToPaused: %v", err)
	}
	if _, err := testQueries.BeginResume(ctx, db.BeginResumeParams{ID: forkIDs[1], TeamID: team.ID}); err != nil {
		t.Fatalf("BeginResume after capacity release: %v", err)
	}
	if err := testQueries.RevertResumeToPaused(ctx, db.RevertResumeToPausedParams{ID: forkIDs[1], TeamID: team.ID}); err != nil {
		t.Fatalf("RevertResumeToPaused(second): %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		UPDATE sandbox SET status = 'failed', updated_at = now()
		WHERE id = $1 AND team_id = $2 AND destroyed_at IS NULL
	`, forkIDs[0], team.ID); err != nil {
		t.Fatalf("mark ambiguous live fork failed: %v", err)
	}
	_, err = testQueries.BeginResume(ctx, db.BeginResumeParams{ID: forkIDs[1], TeamID: team.ID})
	if !errors.As(err, &pgErr) || pgErr.Code != "SS006" {
		t.Fatalf("resume beside live failed fork error = %v, want SS006", err)
	}
}
