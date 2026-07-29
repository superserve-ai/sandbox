package supervisor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/rs/zerolog"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

type fakeSavedSnapshotStore struct {
	creating []db.Snapshot
	deleting []db.Snapshot

	listCreatingParams db.ListStaleCreatingSavedSnapshotsParams
	listDeletingParams db.ListDeletingSavedSnapshotsParams
	listCreatingErr    error
	listDeletingErr    error
	dynamicQueues      bool
	deferParams        []db.DeferSavedSnapshotReconciliationParams
	deferErr           error

	getSnapshot          db.Snapshot
	getSnapshotErr       error
	getSnapshotParams    []db.GetSavedSnapshotParams
	finalizeParams       []db.FinalizeSavedSnapshotParams
	finalizeErr          error
	queueCleanupParams   []db.QueueSavedSnapshotCleanupParams
	queueCleanupErr      error
	failParams           []db.FailSavedSnapshotParams
	failErr              error
	failSourceParams     []db.FailSavedSnapshotAndSourceParams
	failSourceErr        error
	fallbackSourceParams []db.FailSavedSnapshotSourceAfterRevocationParams
	fallbackSourceErr    error
	upsertRevocation     []db.UpsertSandboxRevocationParams
	upsertRevocationErr  error
	finalizeDeleteParams []db.FinalizeSavedSnapshotDeleteParams
	finalizeDeleteErr    error
}

func (f *fakeSavedSnapshotStore) FailSavedSnapshotAndSource(_ context.Context, p db.FailSavedSnapshotAndSourceParams) (db.FailSavedSnapshotAndSourceRow, error) {
	f.failSourceParams = append(f.failSourceParams, p)
	return db.FailSavedSnapshotAndSourceRow{}, f.failSourceErr
}

func (f *fakeSavedSnapshotStore) FailSavedSnapshotSourceAfterRevocation(_ context.Context, p db.FailSavedSnapshotSourceAfterRevocationParams) (uuid.UUID, error) {
	f.fallbackSourceParams = append(f.fallbackSourceParams, p)
	return uuid.New(), f.fallbackSourceErr
}

func (f *fakeSavedSnapshotStore) UpsertSandboxRevocation(_ context.Context, p db.UpsertSandboxRevocationParams) error {
	f.upsertRevocation = append(f.upsertRevocation, p)
	return f.upsertRevocationErr
}

func (f *fakeSavedSnapshotStore) ListStaleCreatingSavedSnapshots(_ context.Context, p db.ListStaleCreatingSavedSnapshotsParams) ([]db.Snapshot, error) {
	f.listCreatingParams = p
	if f.dynamicQueues {
		return staleSavedSnapshotRows(f.creating, db.SnapshotStatusCreating, p.StaleBefore, p.RowLimit), f.listCreatingErr
	}
	return f.creating, f.listCreatingErr
}

func (f *fakeSavedSnapshotStore) ListDeletingSavedSnapshots(_ context.Context, p db.ListDeletingSavedSnapshotsParams) ([]db.Snapshot, error) {
	f.listDeletingParams = p
	if f.dynamicQueues {
		return staleSavedSnapshotRows(f.deleting, db.SnapshotStatusDeleting, p.StaleBefore, p.RowLimit), f.listDeletingErr
	}
	return f.deleting, f.listDeletingErr
}

func staleSavedSnapshotRows(rows []db.Snapshot, status db.SnapshotStatus, staleBefore time.Time, rowLimit int32) []db.Snapshot {
	stale := make([]db.Snapshot, 0, len(rows))
	for _, row := range rows {
		if row.Kind == db.SnapshotKindSaved &&
			row.Status == status &&
			!row.DeletedAt.Valid &&
			row.UpdatedAt.Before(staleBefore) {
			stale = append(stale, row)
		}
	}
	sort.Slice(stale, func(i, j int) bool {
		if stale[i].UpdatedAt.Equal(stale[j].UpdatedAt) {
			return stale[i].ID.String() < stale[j].ID.String()
		}
		return stale[i].UpdatedAt.Before(stale[j].UpdatedAt)
	})
	if int32(len(stale)) > rowLimit {
		stale = stale[:rowLimit]
	}
	return stale
}

func (f *fakeSavedSnapshotStore) DeferSavedSnapshotReconciliation(_ context.Context, p db.DeferSavedSnapshotReconciliationParams) (int64, error) {
	f.deferParams = append(f.deferParams, p)
	if f.deferErr != nil {
		return 0, f.deferErr
	}
	if !f.dynamicQueues {
		return 1, nil
	}
	for _, rows := range []*[]db.Snapshot{&f.creating, &f.deleting} {
		for i := range *rows {
			row := &(*rows)[i]
			if row.ID == p.SnapshotID &&
				row.TeamID == p.TeamID &&
				row.Status == p.ExpectedStatus &&
				row.UpdatedAt.Equal(p.ObservedUpdatedAt) {
				row.UpdatedAt = time.Now()
				return 1, nil
			}
		}
	}
	return 0, nil
}

func (f *fakeSavedSnapshotStore) GetSavedSnapshot(_ context.Context, p db.GetSavedSnapshotParams) (db.Snapshot, error) {
	f.getSnapshotParams = append(f.getSnapshotParams, p)
	return f.getSnapshot, f.getSnapshotErr
}

func (f *fakeSavedSnapshotStore) FinalizeSavedSnapshot(_ context.Context, p db.FinalizeSavedSnapshotParams) (db.FinalizeSavedSnapshotRow, error) {
	f.finalizeParams = append(f.finalizeParams, p)
	return db.FinalizeSavedSnapshotRow{}, f.finalizeErr
}

func (f *fakeSavedSnapshotStore) QueueSavedSnapshotCleanup(_ context.Context, p db.QueueSavedSnapshotCleanupParams) (db.QueueSavedSnapshotCleanupRow, error) {
	f.queueCleanupParams = append(f.queueCleanupParams, p)
	return db.QueueSavedSnapshotCleanupRow{}, f.queueCleanupErr
}

func (f *fakeSavedSnapshotStore) FailSavedSnapshot(_ context.Context, p db.FailSavedSnapshotParams) (db.FailSavedSnapshotRow, error) {
	f.failParams = append(f.failParams, p)
	return db.FailSavedSnapshotRow{}, f.failErr
}

func (f *fakeSavedSnapshotStore) FinalizeSavedSnapshotDelete(_ context.Context, p db.FinalizeSavedSnapshotDeleteParams) (db.Snapshot, error) {
	f.finalizeDeleteParams = append(f.finalizeDeleteParams, p)
	return db.Snapshot{}, f.finalizeDeleteErr
}

type fakeSavedSnapshotClient struct {
	checkErr        error
	checkCalls      int
	createArtifacts vmdclient.SavedSnapshotArtifacts
	createErr       error
	createCalls     [][2]string
	deleteErr       error
	deleteCalls     [][2]string
	containCalls    []string
	revokeErr       error
	destroyErr      error
}

func (f *fakeSavedSnapshotClient) CheckSavedSnapshotSupport(context.Context) error {
	f.checkCalls++
	return f.checkErr
}

func (f *fakeSavedSnapshotClient) CreateSavedSnapshot(_ context.Context, sourceID, snapshotID string) (vmdclient.SavedSnapshotArtifacts, error) {
	f.createCalls = append(f.createCalls, [2]string{sourceID, snapshotID})
	return f.createArtifacts, f.createErr
}

func (f *fakeSavedSnapshotClient) RestoreSavedSnapshot(context.Context, string, string, string, string, string, vmdclient.SavedSnapshotNetwork, []string, string, map[int32]vmdclient.PortPolicy, int64) (string, uint32, uint32, error) {
	return "", 0, 0, errors.New("unexpected restore")
}

func (f *fakeSavedSnapshotClient) DeleteSavedSnapshot(_ context.Context, sourceID, snapshotID string) error {
	f.deleteCalls = append(f.deleteCalls, [2]string{sourceID, snapshotID})
	return f.deleteErr
}

func (f *fakeSavedSnapshotClient) MeasureSandboxWritableLayer(context.Context, string) (int64, int64, error) {
	return 0, 0, errors.New("unexpected writable-layer measurement")
}

func (f *fakeSavedSnapshotClient) RevokeSandbox(_ context.Context, sandboxID string) error {
	f.containCalls = append(f.containCalls, "revoke:"+sandboxID)
	return f.revokeErr
}

func (f *fakeSavedSnapshotClient) DestroyInstance(_ context.Context, sandboxID string, _ bool) error {
	f.containCalls = append(f.containCalls, "destroy:"+sandboxID)
	return f.destroyErr
}

func savedSnapshotFixture() db.Snapshot {
	host := "host-a"
	vcpu, memory, disk := int32(2), int32(2048), int32(8192)
	return db.Snapshot{
		ID:        uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		SandboxID: uuid.MustParse("22222222-2222-4222-8222-222222222222"),
		TeamID:    uuid.MustParse("33333333-3333-4333-8333-333333333333"),
		Kind:      db.SnapshotKindSaved,
		Status:    db.SnapshotStatusCreating,
		HostID:    &host,
		VcpuCount: &vcpu,
		MemoryMib: &memory,
		DiskMib:   &disk,
		SourceStatus: db.NullSandboxStatus{
			SandboxStatus: db.SandboxStatusActive,
			Valid:         true,
		},
	}
}

func savedSnapshotArtifactsFixture() vmdclient.SavedSnapshotArtifacts {
	return vmdclient.SavedSnapshotArtifacts{
		SchemaVersion:            1,
		ManifestPath:             "/var/lib/sandbox/snapshots/saved/source/snapshot/manifest.json",
		ManifestDigest:           strings.Repeat("a", 64),
		SnapshotPath:             "/var/lib/sandbox/snapshots/saved/source/snapshot/vmstate.snap",
		MemPath:                  "/var/lib/sandbox/snapshots/saved/source/snapshot/mem.snap",
		DiskFullPath:             "/var/lib/sandbox/snapshots/saved/source/snapshot/rootfs.ext4",
		VCPU:                     2,
		MemoryMiB:                2048,
		DiskMiB:                  8192,
		LogicalSizeBytes:         4096,
		ExclusiveSizeBytes:       3072,
		SourceLogicalSizeBytes:   8192,
		SourceExclusiveSizeBytes: 2048,
		SourceState:              "running",
	}
}

func testSavedSnapshotSupervisor(store SavedSnapshotStore, client vmdclient.SavedSnapshotClient, resolvedHosts *[]string) *SavedSnapshotSupervisor {
	cfg := DefaultSavedSnapshotSupervisorConfig()
	cfg.OperationTimeout = time.Second
	return NewSavedSnapshotSupervisor(cfg, store, func(_ context.Context, hostID string) (vmdclient.SavedSnapshotClient, error) {
		*resolvedHosts = append(*resolvedHosts, hostID)
		return client, nil
	})
}

func TestSavedSnapshotSupervisorFinalizesStaleCapture(t *testing.T) {
	row := savedSnapshotFixture()
	store := &fakeSavedSnapshotStore{creating: []db.Snapshot{row}}
	client := &fakeSavedSnapshotClient{createArtifacts: savedSnapshotArtifactsFixture()}
	var hosts []string
	s := testSavedSnapshotSupervisor(store, client, &hosts)

	started := time.Now()
	s.tick(context.Background())

	if len(hosts) != 1 || hosts[0] != "host-a" {
		t.Fatalf("resolved hosts = %v, want exact host-a", hosts)
	}
	if len(client.createCalls) != 1 || client.createCalls[0] != [2]string{row.SandboxID.String(), row.ID.String()} {
		t.Fatalf("create calls = %v", client.createCalls)
	}
	if len(store.finalizeParams) != 1 {
		t.Fatalf("finalize calls = %d, want 1", len(store.finalizeParams))
	}
	got := store.finalizeParams[0]
	if got.ManifestPath != client.createArtifacts.ManifestPath || got.ExclusiveSizeBytes != 3072 || len(got.ArtifactMetadata) == 0 {
		t.Fatalf("finalize params missing artifact data: %+v", got)
	}
	var metadata reconciledArtifactMetadata
	if err := json.Unmarshal(got.ArtifactMetadata, &metadata); err != nil {
		t.Fatalf("decode reconciled artifact metadata: %v", err)
	}
	if metadata.SourceLogicalSizeBytes != client.createArtifacts.SourceLogicalSizeBytes ||
		metadata.SourceExclusiveSizeBytes != client.createArtifacts.SourceExclusiveSizeBytes {
		t.Fatalf("reconciled source accounting = %+v, want logical=%d exclusive=%d", metadata,
			client.createArtifacts.SourceLogicalSizeBytes, client.createArtifacts.SourceExclusiveSizeBytes)
	}
	if len(store.failParams) != 0 || len(client.deleteCalls) != 0 {
		t.Fatalf("unexpected fail/delete: failures=%d deletes=%d", len(store.failParams), len(client.deleteCalls))
	}
	if store.listCreatingParams.StaleBefore.After(started.Add(-s.cfg.StaleCaptureAfter + time.Second)) {
		t.Fatalf("capture stale cutoff is too new: %s", store.listCreatingParams.StaleBefore)
	}
	if store.listDeletingParams.StaleBefore.After(started.Add(-s.cfg.StaleDeleteAfter + time.Second)) {
		t.Fatalf("delete stale cutoff is too new: %s", store.listDeletingParams.StaleBefore)
	}
}

func TestSavedSnapshotSupervisorLeavesTransientCaptureForRetry(t *testing.T) {
	row := savedSnapshotFixture()
	store := &fakeSavedSnapshotStore{creating: []db.Snapshot{row}}
	client := &fakeSavedSnapshotClient{createErr: status.Error(codes.Unavailable, "host restarting")}
	var hosts []string
	testSavedSnapshotSupervisor(store, client, &hosts).tick(context.Background())

	if len(store.finalizeParams) != 0 || len(store.failParams) != 0 || len(client.deleteCalls) != 0 {
		t.Fatalf("transient capture changed durable state: finalize=%d fail=%d delete=%d", len(store.finalizeParams), len(store.failParams), len(client.deleteCalls))
	}
	assertDeferredSnapshot(t, store.deferParams, row, db.SnapshotStatusCreating)
}

func TestSavedSnapshotSupervisorLogsDoNotExposeHostArtifactPaths(t *testing.T) {
	const hostPath = "/var/lib/superserve/private/snapshots/source/snapshot/rootfs.ext4"
	row := savedSnapshotFixture()
	store := &fakeSavedSnapshotStore{creating: []db.Snapshot{row}}
	client := &fakeSavedSnapshotClient{
		createErr: status.Error(codes.Unavailable, "open "+hostPath+": input/output error"),
	}
	var hosts []string
	s := testSavedSnapshotSupervisor(store, client, &hosts)
	var output bytes.Buffer
	s.log = zerolog.New(&output)

	s.tick(context.Background())

	if strings.Contains(output.String(), hostPath) {
		t.Fatalf("supervisor log exposed host artifact path: %s", output.String())
	}
	if !strings.Contains(output.String(), "saved snapshot capture failed") {
		t.Fatalf("supervisor log lost safe operation context: %s", output.String())
	}
}

func TestSavedSnapshotSupervisorAtomicallyFailsSourceWhenCaptureCannotResume(t *testing.T) {
	row := savedSnapshotFixture()
	st, err := status.New(codes.Internal, "source failed to resume").WithDetails(&errdetails.ErrorInfo{
		Reason: vmdclient.SavedSnapshotSourceResumeFailureReason,
	})
	if err != nil {
		t.Fatalf("attach source resume reason: %v", err)
	}
	store := &fakeSavedSnapshotStore{creating: []db.Snapshot{row}}
	client := &fakeSavedSnapshotClient{createErr: st.Err()}
	var hosts []string
	testSavedSnapshotSupervisor(store, client, &hosts).tick(context.Background())

	if len(store.failSourceParams) != 1 {
		t.Fatalf("atomic source failures = %d, want 1", len(store.failSourceParams))
	}
	got := store.failSourceParams[0]
	if got.SnapshotID != row.ID || got.TeamID != row.TeamID || got.FailureReason == nil || *got.FailureReason != "source_resume_failed" {
		t.Fatalf("atomic source failure params = %+v", got)
	}
	if len(store.failParams) != 0 || len(client.deleteCalls) != 0 {
		t.Fatalf("source resume failure used split cleanup path: fail=%+v delete=%+v", store.failParams, client.deleteCalls)
	}
	wantContainment := []string{"revoke:" + row.SandboxID.String(), "destroy:" + row.SandboxID.String()}
	if !reflect.DeepEqual(client.containCalls, wantContainment) {
		t.Fatalf("source containment calls = %v, want %v", client.containCalls, wantContainment)
	}
}

func TestSavedSnapshotSupervisorFailsPausedSourceWithCorruptCheckpoint(t *testing.T) {
	row := savedSnapshotFixture()
	row.SourceStatus = db.NullSandboxStatus{SandboxStatus: db.SandboxStatusPaused, Valid: true}
	store := &fakeSavedSnapshotStore{creating: []db.Snapshot{row}}
	client := &fakeSavedSnapshotClient{createErr: status.Error(codes.DataLoss, "checkpoint digest mismatch")}
	var hosts []string
	testSavedSnapshotSupervisor(store, client, &hosts).tick(context.Background())

	if len(store.failSourceParams) != 1 || store.failSourceParams[0].FailureReason == nil ||
		*store.failSourceParams[0].FailureReason != "source_artifacts_missing" {
		t.Fatalf("paused source failure params = %+v", store.failSourceParams)
	}
	wantContainment := []string{"revoke:" + row.SandboxID.String(), "destroy:" + row.SandboxID.String()}
	if !reflect.DeepEqual(client.containCalls, wantContainment) {
		t.Fatalf("paused source containment calls = %v, want %v", client.containCalls, wantContainment)
	}
}

func TestSavedSnapshotSupervisorUsesRevokedFallbackAfterConcurrentCaptureCancellation(t *testing.T) {
	row := savedSnapshotFixture()
	st, err := status.New(codes.Internal, "source failed to resume").WithDetails(&errdetails.ErrorInfo{
		Reason: vmdclient.SavedSnapshotSourceResumeFailureReason,
	})
	if err != nil {
		t.Fatalf("attach source resume reason: %v", err)
	}
	store := &fakeSavedSnapshotStore{
		creating:      []db.Snapshot{row},
		failSourceErr: pgx.ErrNoRows,
	}
	client := &fakeSavedSnapshotClient{createErr: st.Err()}
	var hosts []string
	testSavedSnapshotSupervisor(store, client, &hosts).tick(context.Background())

	if len(store.fallbackSourceParams) != 1 {
		t.Fatalf("fallback source failures = %d, want 1", len(store.fallbackSourceParams))
	}
	got := store.fallbackSourceParams[0]
	if got.SnapshotID != row.ID || got.TeamID != row.TeamID || got.FailureReason == nil || *got.FailureReason != "source_resume_failed" {
		t.Fatalf("fallback source failure params = %+v", got)
	}
	wantContainment := []string{"revoke:" + row.SandboxID.String(), "destroy:" + row.SandboxID.String()}
	if !reflect.DeepEqual(client.containCalls, wantContainment) {
		t.Fatalf("source containment calls = %v, want %v", client.containCalls, wantContainment)
	}
}

func TestSavedSnapshotSupervisorRetainsSourceWhenFallbackTransitionIsUnproven(t *testing.T) {
	row := savedSnapshotFixture()
	st, err := status.New(codes.Internal, "source failed to resume").WithDetails(&errdetails.ErrorInfo{
		Reason: vmdclient.SavedSnapshotSourceResumeFailureReason,
	})
	if err != nil {
		t.Fatalf("attach source resume reason: %v", err)
	}
	store := &fakeSavedSnapshotStore{
		creating:          []db.Snapshot{row},
		failSourceErr:     pgx.ErrNoRows,
		fallbackSourceErr: pgx.ErrNoRows,
	}
	client := &fakeSavedSnapshotClient{createErr: st.Err()}
	var hosts []string
	testSavedSnapshotSupervisor(store, client, &hosts).tick(context.Background())

	if len(store.upsertRevocation) != 1 || len(store.fallbackSourceParams) != 1 {
		t.Fatalf("fallback writes = revocations:%d transitions:%d, want 1 each", len(store.upsertRevocation), len(store.fallbackSourceParams))
	}
	wantContainment := []string{"revoke:" + row.SandboxID.String()}
	if !reflect.DeepEqual(client.containCalls, wantContainment) {
		t.Fatalf("source containment calls = %v, want %v", client.containCalls, wantContainment)
	}
}

func TestSavedSnapshotSupervisorDoesNotCallOldVMDCapture(t *testing.T) {
	row := savedSnapshotFixture()
	store := &fakeSavedSnapshotStore{creating: []db.Snapshot{row}}
	client := &fakeSavedSnapshotClient{checkErr: status.Error(codes.Unimplemented, "unknown method GetCapabilities")}
	var hosts []string
	testSavedSnapshotSupervisor(store, client, &hosts).tick(context.Background())

	if client.checkCalls != 1 {
		t.Fatalf("capability checks = %d, want 1", client.checkCalls)
	}
	if len(client.createCalls) != 0 || len(store.finalizeParams) != 0 || len(store.failParams) != 0 {
		t.Fatalf("old VMD changed capture state: create=%d finalize=%d fail=%d", len(client.createCalls), len(store.finalizeParams), len(store.failParams))
	}
	assertDeferredSnapshot(t, store.deferParams, row, db.SnapshotStatusCreating)
}

func TestSavedSnapshotSupervisorFailsDeterministicCaptureAndCleansArtifacts(t *testing.T) {
	row := savedSnapshotFixture()
	store := &fakeSavedSnapshotStore{creating: []db.Snapshot{row}}
	client := &fakeSavedSnapshotClient{createErr: status.Error(codes.DataLoss, "corrupt source")}
	var hosts []string
	testSavedSnapshotSupervisor(store, client, &hosts).tick(context.Background())

	if len(client.deleteCalls) != 1 {
		t.Fatalf("cleanup delete calls = %d, want 1", len(client.deleteCalls))
	}
	if len(store.failParams) != 1 || store.failParams[0].FailureReason == nil || *store.failParams[0].FailureReason != "source_artifacts_missing" {
		t.Fatalf("failure params = %+v", store.failParams)
	}
}

func TestSavedSnapshotSupervisorQuotaFailureCleansCommittedArtifacts(t *testing.T) {
	row := savedSnapshotFixture()
	store := &fakeSavedSnapshotStore{
		creating:    []db.Snapshot{row},
		finalizeErr: &pgconn.PgError{Code: "SS005", Message: "quota exceeded"},
	}
	client := &fakeSavedSnapshotClient{createArtifacts: savedSnapshotArtifactsFixture()}
	var hosts []string
	testSavedSnapshotSupervisor(store, client, &hosts).tick(context.Background())

	if len(client.deleteCalls) != 1 {
		t.Fatalf("cleanup delete calls = %d, want 1", len(client.deleteCalls))
	}
	if len(store.failParams) != 1 || store.failParams[0].FailureReason == nil || *store.failParams[0].FailureReason != "snapshot_storage_quota_exceeded" {
		t.Fatalf("failure params = %+v", store.failParams)
	}
}

func TestSavedSnapshotSupervisorQueuesCleanupWhenImmediateDeleteFails(t *testing.T) {
	row := savedSnapshotFixture()
	artifacts := savedSnapshotArtifactsFixture()
	store := &fakeSavedSnapshotStore{
		creating:    []db.Snapshot{row},
		finalizeErr: &pgconn.PgError{Code: "SS005", Message: "quota exceeded"},
	}
	client := &fakeSavedSnapshotClient{
		createArtifacts: artifacts,
		deleteErr:       status.Error(codes.Unavailable, "host cleanup unavailable"),
	}
	var hosts []string
	testSavedSnapshotSupervisor(store, client, &hosts).tick(context.Background())

	if len(client.deleteCalls) != 1 {
		t.Fatalf("cleanup delete calls = %d, want 1", len(client.deleteCalls))
	}
	if len(store.failParams) != 0 {
		t.Fatalf("capture was terminalized before artifact deletion: %+v", store.failParams)
	}
	if len(store.queueCleanupParams) != 1 {
		t.Fatalf("cleanup queue calls = %d, want 1", len(store.queueCleanupParams))
	}
	got := store.queueCleanupParams[0]
	if got.SnapshotID != row.ID || got.TeamID != row.TeamID || got.Path != artifacts.SnapshotPath || got.ManifestPath != artifacts.ManifestPath {
		t.Fatalf("cleanup queue identity/artifacts = %+v", got)
	}
	if got.ExclusiveSizeBytes != artifacts.ExclusiveSizeBytes || got.FailureReason == nil || *got.FailureReason != "snapshot_storage_quota_exceeded" {
		t.Fatalf("cleanup queue accounting/reason = %+v", got)
	}
	if len(got.ArtifactMetadata) == 0 {
		t.Fatal("cleanup queue omitted artifact metadata")
	}
}

func TestSavedSnapshotSupervisorQueuesPermanentAndInvalidCapturesWhenDeleteFails(t *testing.T) {
	invalidArtifacts := savedSnapshotArtifactsFixture()
	invalidArtifacts.VCPU++
	invalidSourceAccounting := savedSnapshotArtifactsFixture()
	invalidSourceAccounting.SourceExclusiveSizeBytes = -1
	invalidManifestDigest := savedSnapshotArtifactsFixture()
	invalidManifestDigest.ManifestDigest = strings.Repeat("z", 64)
	uppercaseManifestDigest := savedSnapshotArtifactsFixture()
	uppercaseManifestDigest.ManifestDigest = strings.Repeat("A", 64)
	tests := []struct {
		name       string
		artifacts  vmdclient.SavedSnapshotArtifacts
		createErr  error
		wantReason string
	}{
		{
			name:       "permanent capture error",
			artifacts:  savedSnapshotArtifactsFixture(),
			createErr:  status.Error(codes.DataLoss, "corrupt source"),
			wantReason: "source_artifacts_missing",
		},
		{
			name:       "artifact validation error",
			artifacts:  invalidArtifacts,
			wantReason: "artifact_validation_failed",
		},
		{
			name:       "negative source accounting",
			artifacts:  invalidSourceAccounting,
			wantReason: "artifact_validation_failed",
		},
		{
			name:       "non-hex manifest digest",
			artifacts:  invalidManifestDigest,
			wantReason: "artifact_validation_failed",
		},
		{
			name:       "non-canonical manifest digest",
			artifacts:  uppercaseManifestDigest,
			wantReason: "artifact_validation_failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			row := savedSnapshotFixture()
			store := &fakeSavedSnapshotStore{creating: []db.Snapshot{row}}
			client := &fakeSavedSnapshotClient{
				createArtifacts: tt.artifacts,
				createErr:       tt.createErr,
				deleteErr:       status.Error(codes.Unavailable, "host cleanup unavailable"),
			}
			var hosts []string
			testSavedSnapshotSupervisor(store, client, &hosts).tick(context.Background())

			if len(store.failParams) != 0 {
				t.Fatalf("capture was terminalized before artifact deletion: %+v", store.failParams)
			}
			if len(store.queueCleanupParams) != 1 {
				t.Fatalf("cleanup queue calls = %d, want 1", len(store.queueCleanupParams))
			}
			queued := store.queueCleanupParams[0]
			if queued.FailureReason == nil || *queued.FailureReason != tt.wantReason {
				t.Fatalf("cleanup failure reason = %v, want %q", queued.FailureReason, tt.wantReason)
			}
			if queued.Path != tt.artifacts.SnapshotPath || queued.ExclusiveSizeBytes != tt.artifacts.ExclusiveSizeBytes || len(queued.ArtifactMetadata) == 0 {
				t.Fatalf("cleanup artifact metadata = %+v", queued)
			}
		})
	}
}

func TestSavedSnapshotSupervisorFinalizeRacePreservesWinningReadyArtifact(t *testing.T) {
	row := savedSnapshotFixture()
	winner := row
	winner.Status = db.SnapshotStatusReady
	store := &fakeSavedSnapshotStore{
		creating:       []db.Snapshot{row},
		finalizeErr:    pgx.ErrNoRows,
		getSnapshot:    winner,
		getSnapshotErr: nil,
	}
	client := &fakeSavedSnapshotClient{createArtifacts: savedSnapshotArtifactsFixture()}
	var hosts []string
	testSavedSnapshotSupervisor(store, client, &hosts).tick(context.Background())

	if len(store.getSnapshotParams) != 1 || store.getSnapshotParams[0].SnapshotID != row.ID {
		t.Fatalf("post-race reads = %+v", store.getSnapshotParams)
	}
	if len(client.deleteCalls) != 0 {
		t.Fatalf("winning ready artifact was deleted: %+v", client.deleteCalls)
	}
	if len(store.failParams) != 0 || len(store.queueCleanupParams) != 0 {
		t.Fatalf("winning row was changed: fail=%+v queue=%+v", store.failParams, store.queueCleanupParams)
	}
}

func TestSavedSnapshotSupervisorRetriesAndFinalizesDelete(t *testing.T) {
	row := savedSnapshotFixture()
	row.Status = db.SnapshotStatusDeleting
	store := &fakeSavedSnapshotStore{deleting: []db.Snapshot{row}}
	client := &fakeSavedSnapshotClient{}
	var hosts []string
	testSavedSnapshotSupervisor(store, client, &hosts).tick(context.Background())

	if len(client.deleteCalls) != 1 || client.deleteCalls[0] != [2]string{row.SandboxID.String(), row.ID.String()} {
		t.Fatalf("delete calls = %v", client.deleteCalls)
	}
	if len(store.finalizeDeleteParams) != 1 || store.finalizeDeleteParams[0].SnapshotID != row.ID {
		t.Fatalf("finalize delete params = %+v", store.finalizeDeleteParams)
	}
}

func TestSavedSnapshotSupervisorLeavesTransientDeleteForRetry(t *testing.T) {
	row := savedSnapshotFixture()
	row.Status = db.SnapshotStatusDeleting
	store := &fakeSavedSnapshotStore{deleting: []db.Snapshot{row}}
	client := &fakeSavedSnapshotClient{deleteErr: status.Error(codes.DeadlineExceeded, "slow host")}
	var hosts []string
	testSavedSnapshotSupervisor(store, client, &hosts).tick(context.Background())

	if len(store.finalizeDeleteParams) != 0 {
		t.Fatalf("transient delete was finalized: %+v", store.finalizeDeleteParams)
	}
	assertDeferredSnapshot(t, store.deferParams, row, db.SnapshotStatusDeleting)
}

func TestSavedSnapshotSupervisorDeleteIgnoresWriterCapabilityRollback(t *testing.T) {
	row := savedSnapshotFixture()
	row.Status = db.SnapshotStatusDeleting
	store := &fakeSavedSnapshotStore{deleting: []db.Snapshot{row}}
	client := &fakeSavedSnapshotClient{checkErr: status.Error(codes.Unimplemented, "unknown method GetCapabilities")}
	var hosts []string
	testSavedSnapshotSupervisor(store, client, &hosts).tick(context.Background())

	if client.checkCalls != 0 {
		t.Fatalf("delete performed writer capability checks = %d, want 0", client.checkCalls)
	}
	if len(client.deleteCalls) != 1 || len(store.finalizeDeleteParams) != 1 {
		t.Fatalf("cleanup did not converge after capability rollback: delete=%d finalize=%d", len(client.deleteCalls), len(store.finalizeDeleteParams))
	}
}

func TestSavedSnapshotSupervisorReleasesHostlessCaptureButNotDelete(t *testing.T) {
	creating := savedSnapshotFixture()
	creating.HostID = nil
	deleting := creating
	deleting.ID = uuid.MustParse("44444444-4444-4444-8444-444444444444")
	deleting.Status = db.SnapshotStatusDeleting
	store := &fakeSavedSnapshotStore{creating: []db.Snapshot{creating}, deleting: []db.Snapshot{deleting}}
	client := &fakeSavedSnapshotClient{}
	var hosts []string
	testSavedSnapshotSupervisor(store, client, &hosts).tick(context.Background())

	if len(store.failParams) != 1 || store.failParams[0].SnapshotID != creating.ID {
		t.Fatalf("hostless capture failure params = %+v", store.failParams)
	}
	if len(store.finalizeDeleteParams) != 0 {
		t.Fatalf("hostless delete must not finalize: %+v", store.finalizeDeleteParams)
	}
	if len(hosts) != 0 {
		t.Fatalf("hostless rows unexpectedly resolved hosts: %v", hosts)
	}
	assertDeferredSnapshot(t, store.deferParams, deleting, db.SnapshotStatusDeleting)
}

func TestSavedSnapshotSupervisorDefersNilCaptureAndDeleteClients(t *testing.T) {
	creating := savedSnapshotFixture()
	deleting := savedSnapshotFixture()
	deleting.ID = uuid.MustParse("44444444-4444-4444-8444-444444444444")
	deleting.Status = db.SnapshotStatusDeleting
	store := &fakeSavedSnapshotStore{
		creating: []db.Snapshot{creating},
		deleting: []db.Snapshot{deleting},
	}
	cfg := DefaultSavedSnapshotSupervisorConfig()
	s := NewSavedSnapshotSupervisor(cfg, store, func(context.Context, string) (vmdclient.SavedSnapshotClient, error) {
		return nil, nil
	})

	s.tick(context.Background())

	if len(store.deferParams) != 2 {
		t.Fatalf("deferred rows = %+v, want creating and deleting", store.deferParams)
	}
	assertDeferredSnapshot(t, store.deferParams[:1], deleting, db.SnapshotStatusDeleting)
	assertDeferredSnapshot(t, store.deferParams[1:], creating, db.SnapshotStatusCreating)
}

func TestSavedSnapshotSupervisorDefersFinalizeDatabaseFailures(t *testing.T) {
	t.Run("capture", func(t *testing.T) {
		row := savedSnapshotFixture()
		store := &fakeSavedSnapshotStore{
			creating:    []db.Snapshot{row},
			finalizeErr: errors.New("database unavailable"),
		}
		client := &fakeSavedSnapshotClient{createArtifacts: savedSnapshotArtifactsFixture()}
		var hosts []string

		testSavedSnapshotSupervisor(store, client, &hosts).tick(context.Background())

		assertDeferredSnapshot(t, store.deferParams, row, db.SnapshotStatusCreating)
	})

	t.Run("delete", func(t *testing.T) {
		row := savedSnapshotFixture()
		row.Status = db.SnapshotStatusDeleting
		store := &fakeSavedSnapshotStore{
			deleting:          []db.Snapshot{row},
			finalizeDeleteErr: errors.New("database unavailable"),
		}
		client := &fakeSavedSnapshotClient{}
		var hosts []string

		testSavedSnapshotSupervisor(store, client, &hosts).tick(context.Background())

		assertDeferredSnapshot(t, store.deferParams, row, db.SnapshotStatusDeleting)
	})
}

func TestSavedSnapshotSupervisorCaptureFailuresDoNotStarveLaterRows(t *testing.T) {
	rows := savedSnapshotFairnessFixtures(db.SnapshotStatusCreating)
	store := &fakeSavedSnapshotStore{
		creating:      rows,
		dynamicQueues: true,
	}
	healthyClient := &fakeSavedSnapshotClient{createArtifacts: savedSnapshotArtifactsFixture()}
	cfg := DefaultSavedSnapshotSupervisorConfig()
	cfg.BatchSize = 2
	cfg.StaleCaptureAfter = time.Hour
	s := NewSavedSnapshotSupervisor(cfg, store, func(_ context.Context, hostID string) (vmdclient.SavedSnapshotClient, error) {
		if hostID == "host-bad" {
			return nil, errors.New("host permanently unreachable")
		}
		return healthyClient, nil
	})

	s.tick(context.Background())
	if len(store.finalizeParams) != 0 {
		t.Fatalf("healthy capture reached in first fixed batch: %+v", store.finalizeParams)
	}
	s.tick(context.Background())

	healthy := rows[len(rows)-1]
	if len(store.finalizeParams) != 1 || store.finalizeParams[0].SnapshotID != healthy.ID {
		t.Fatalf("healthy capture was starved: finalize=%+v, want snapshot %s", store.finalizeParams, healthy.ID)
	}
	if len(store.deferParams) != 3 {
		t.Fatalf("capture deferrals = %d, want one for each permanently failing row", len(store.deferParams))
	}
}

func TestSavedSnapshotSupervisorDeleteFailuresDoNotStarveLaterRows(t *testing.T) {
	rows := savedSnapshotFairnessFixtures(db.SnapshotStatusDeleting)
	store := &fakeSavedSnapshotStore{
		deleting:      rows,
		dynamicQueues: true,
	}
	failingClient := &fakeSavedSnapshotClient{deleteErr: status.Error(codes.PermissionDenied, "permanent host rejection")}
	healthyClient := &fakeSavedSnapshotClient{}
	cfg := DefaultSavedSnapshotSupervisorConfig()
	cfg.BatchSize = 2
	cfg.StaleDeleteAfter = time.Hour
	s := NewSavedSnapshotSupervisor(cfg, store, func(_ context.Context, hostID string) (vmdclient.SavedSnapshotClient, error) {
		if hostID == "host-bad" {
			return failingClient, nil
		}
		return healthyClient, nil
	})

	s.tick(context.Background())
	if len(store.finalizeDeleteParams) != 0 {
		t.Fatalf("healthy delete reached in first fixed batch: %+v", store.finalizeDeleteParams)
	}
	s.tick(context.Background())

	healthy := rows[len(rows)-1]
	if len(store.finalizeDeleteParams) != 1 || store.finalizeDeleteParams[0].SnapshotID != healthy.ID {
		t.Fatalf("healthy delete was starved: finalize=%+v, want snapshot %s", store.finalizeDeleteParams, healthy.ID)
	}
	if len(store.deferParams) != 3 {
		t.Fatalf("delete deferrals = %d, want one for each permanently failing row", len(store.deferParams))
	}
}

func assertDeferredSnapshot(
	t *testing.T,
	params []db.DeferSavedSnapshotReconciliationParams,
	snapshot db.Snapshot,
	status db.SnapshotStatus,
) {
	t.Helper()
	if len(params) != 1 {
		t.Fatalf("defer calls = %+v, want exactly one", params)
	}
	got := params[0]
	if got.SnapshotID != snapshot.ID ||
		got.TeamID != snapshot.TeamID ||
		got.ExpectedStatus != status ||
		!got.ObservedUpdatedAt.Equal(snapshot.UpdatedAt) {
		t.Fatalf("defer params = %+v, want snapshot=%s team=%s status=%s updated_at=%s",
			got, snapshot.ID, snapshot.TeamID, status, snapshot.UpdatedAt)
	}
}

func savedSnapshotFairnessFixtures(status db.SnapshotStatus) []db.Snapshot {
	ids := []uuid.UUID{
		uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1"),
		uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2"),
		uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa3"),
		uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa4"),
	}
	oldest := time.Now().Add(-2 * time.Hour)
	rows := make([]db.Snapshot, 0, len(ids))
	for i, id := range ids {
		row := savedSnapshotFixture()
		row.ID = id
		row.Status = status
		row.UpdatedAt = oldest.Add(time.Duration(i) * time.Second)
		hostID := "host-bad"
		if i == len(ids)-1 {
			hostID = "host-healthy"
		}
		row.HostID = &hostID
		rows = append(rows, row)
	}
	return rows
}
