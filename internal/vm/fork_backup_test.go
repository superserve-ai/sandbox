package vm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/backup"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
	"github.com/superserve-ai/sandbox/proto/vmdpb"
)

func TestSavedSnapshotFilesMissing(t *testing.T) {
	_, man, _, _ := savedBackupFixture(t)
	if savedSnapshotFilesMissing(man) {
		t.Fatal("a snapshot with every file must not read as missing")
	}
	for _, file := range []func(*SavedSnapshotManifest) string{
		func(s *SavedSnapshotManifest) string { return s.BasePath },
		func(s *SavedSnapshotManifest) string { return s.MemPath },
	} {
		m, man, _, _ := savedBackupFixture(t)
		path := file(man)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if !savedSnapshotFilesMissing(man) {
			t.Fatalf("a snapshot without %s must read as missing", filepath.Base(path))
		}
		// The fork's own read of the snapshot asks for the backup.
		m.SetBackupRestore(&slowEmptyStore{}, &slowEmptyStore{}, filepath.Join(t.TempDir(), ".restore"), BackupRestoreOptions{Concurrency: 1})
		cfg := VMConfig{SavedSnapshotID: man.SnapshotID}
		if _, _, _, err := m.forkSource("fork-1", &cfg, "", ""); !vmdclient.IsSavedSnapshotMissing(err) {
			t.Fatalf("fork without %s: err = %v, want the saved-snapshot-missing refusal", filepath.Base(path), err)
		}
	}
}

// A fork of a snapshot the host lost asks for its backup, and with one
// fetches the snapshot's own generation, never a sandbox's.
func TestForkOfAMissingSnapshotUsesItsBackup(t *testing.T) {
	m := newSavedTestManager(t)
	m.SetBackupRestore(&slowEmptyStore{}, &slowEmptyStore{}, filepath.Join(t.TempDir(), ".restore"), BackupRestoreOptions{Concurrency: 1})
	a := &GRPCAdapter{mgr: m}
	snapshotID := "5f0c2a9e-1b7d-4c3e-8a6f-0d9e2b4c7a13"
	req := &vmdpb.RestoreSnapshotRequest{VmId: "fork-1", SavedSnapshotId: snapshotID, ResourceLimits: &vmdpb.ResourceLimits{VcpuCount: 1, MemoryMib: 512}}

	if _, err := a.RestoreSnapshot(context.Background(), req); !vmdclient.IsSavedSnapshotMissing(err) {
		t.Fatalf("err = %v, want the saved-snapshot-missing refusal", err)
	}

	var owner string
	orig := fetchBackupGeneration
	fetchBackupGeneration = func(_ context.Context, _ backup.BlobReader, o, _, _ string, _ backup.ProgressFunc) (backup.Restored, error) {
		owner = o
		return backup.Restored{}, backup.ErrNoMatchingBackup
	}
	defer func() { fetchBackupGeneration = orig }()
	req.BackupGeneration = "gen-1"
	if _, err := a.RestoreSnapshot(context.Background(), req); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v, want FailedPrecondition for a backup the bucket lacks", err)
	}
	if owner != backup.SnapshotOwner(snapshotID) {
		t.Fatalf("fetched owner %q, want the snapshot's", owner)
	}
}

// Without backup restore on, a lost snapshot fails as it always has.
func TestForkOfAMissingSnapshotWithoutBackupRestore(t *testing.T) {
	a := &GRPCAdapter{mgr: newSavedTestManager(t)}
	req := &vmdpb.RestoreSnapshotRequest{VmId: "fork-1", SavedSnapshotId: "5f0c2a9e-1b7d-4c3e-8a6f-0d9e2b4c7a13"}
	if _, err := a.RestoreSnapshot(context.Background(), req); status.Code(err) != codes.NotFound || vmdclient.IsSavedSnapshotMissing(err) {
		t.Fatalf("err = %v, want plain NotFound", err)
	}
}

// A destroy that completes while the backup downloads wins: nothing boots.
func TestForkFromBackupYieldsToADestroyDuringTheDownload(t *testing.T) {
	m := newSavedTestManager(t)
	m.SetBackupRestore(&slowEmptyStore{}, &slowEmptyStore{}, filepath.Join(t.TempDir(), ".restore"), BackupRestoreOptions{Concurrency: 1})
	disk := touch(t, filepath.Join(t.TempDir(), "rootfs.ext4"))
	orig := fetchBackupGeneration
	fetchBackupGeneration = func(context.Context, backup.BlobReader, string, string, string, backup.ProgressFunc) (backup.Restored, error) {
		m.bumpDestroyEpoch("fork-1")
		return backup.Restored{Disk: disk, Standalone: true}, nil
	}
	defer func() { fetchBackupGeneration = orig }()
	cfg := VMConfig{VCPU: 1, MemoryMiB: 512, SavedSnapshotID: "5f0c2a9e-1b7d-4c3e-8a6f-0d9e2b4c7a13"}
	if _, err := m.forkFromBackup(context.Background(), "fork-1", "gen-1", cfg, "team", "", "", nil, 0); status.Code(err) != codes.Aborted {
		t.Fatalf("err = %v, want Aborted", err)
	}
	if _, ok := m.vms["fork-1"]; ok {
		t.Fatal("a destroyed fork was booted")
	}
}

// A run dir no record accounts for may hold a live Firecracker on the disk
// the boot would replace: until its stop is confirmed, nothing is fetched.
func TestForkFromBackupStopsALeftoverLifeFirst(t *testing.T) {
	m := newSavedTestManager(t)
	m.SetBackupRestore(&slowEmptyStore{}, &slowEmptyStore{}, filepath.Join(t.TempDir(), ".restore"), BackupRestoreOptions{Concurrency: 1})
	overlay := touch(t, filepath.Join(m.cfg.RunDir, "fork-1", "overlay.ext4"))
	m.stopVMHook = func(context.Context, string, Supervision) error { return errors.New("unit still active") }
	orig := fetchBackupGeneration
	fetchBackupGeneration = func(context.Context, backup.BlobReader, string, string, string, backup.ProgressFunc) (backup.Restored, error) {
		t.Fatal("fetched over a life that was not stopped")
		return backup.Restored{}, nil
	}
	defer func() { fetchBackupGeneration = orig }()
	cfg := VMConfig{VCPU: 1, MemoryMiB: 512, SavedSnapshotID: "5f0c2a9e-1b7d-4c3e-8a6f-0d9e2b4c7a13"}
	if _, err := m.forkFromBackup(context.Background(), "fork-1", "gen-1", cfg, "team", "", "", nil, 0); status.Code(err) != codes.Unavailable {
		t.Fatalf("err = %v, want Unavailable", err)
	}
	if _, err := os.Stat(overlay); err != nil {
		t.Fatalf("the leftover's disk was touched: %v", err)
	}
}

// A stop that returns while the life may still run releases nothing, and a
// destroy that lands during the cleanup wins.
func TestForkFromBackupCleanupYieldsToAnUnconfirmedStopOrADestroy(t *testing.T) {
	cfg := VMConfig{VCPU: 1, MemoryMiB: 512, SavedSnapshotID: "5f0c2a9e-1b7d-4c3e-8a6f-0d9e2b4c7a13"}
	orig := fetchBackupGeneration
	fetchBackupGeneration = func(context.Context, backup.BlobReader, string, string, string, backup.ProgressFunc) (backup.Restored, error) {
		t.Fatal("fetched past a cleanup that should have stopped the fork")
		return backup.Restored{}, nil
	}
	defer func() { fetchBackupGeneration = orig }()
	for name, tc := range map[string]struct {
		stop   func(*Manager) func(context.Context, string, Supervision) error
		atRest bool
		want   codes.Code
	}{
		"still_deactivating": {func(*Manager) func(context.Context, string, Supervision) error {
			return func(context.Context, string, Supervision) error { return nil }
		}, false, codes.Unavailable},
		"destroyed_meanwhile": {func(m *Manager) func(context.Context, string, Supervision) error {
			return func(_ context.Context, id string, _ Supervision) error { m.bumpDestroyEpoch(id); return nil }
		}, true, codes.Aborted},
	} {
		t.Run(name, func(t *testing.T) {
			m := newSavedTestManager(t)
			m.netMgr = &fakeNetMgr{}
			m.SetBackupRestore(&slowEmptyStore{}, &slowEmptyStore{}, filepath.Join(t.TempDir(), ".restore"), BackupRestoreOptions{Concurrency: 1})
			overlay := touch(t, filepath.Join(m.cfg.RunDir, "fork-1", "overlay.ext4"))
			m.stopVMHook = tc.stop(m)
			m.unitDead = func(context.Context, string) bool { return tc.atRest }
			if _, err := m.forkFromBackup(context.Background(), "fork-1", "gen-1", cfg, "team", "", "", nil, 0); status.Code(err) != tc.want {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if _, err := os.Stat(overlay); tc.want == codes.Unavailable && err != nil {
				t.Fatalf("the leftover's disk was released: %v", err)
			}
		})
	}
}

// A retry adopts only once the attempt it repeats has committed.
func TestBackupForkRetryWaitsForTheBootItAdopts(t *testing.T) {
	m := newSavedTestManager(t)
	snapshotID := "5f0c2a9e-1b7d-4c3e-8a6f-0d9e2b4c7a13"
	m.vms["fork-1"] = &VMInstance{ID: "fork-1", Status: StatusRunning, SourceSnapshotID: snapshotID, BackupGeneration: "gen-1"}
	orig := vmDeadForRetry
	vmDeadForRetry = func(*Manager, string) bool { return false }
	defer func() { vmDeadForRetry = orig }()
	unlock, err := m.lockVMOp(context.Background(), "fork-1")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		req := &vmdpb.RestoreSnapshotRequest{VmId: "fork-1", SavedSnapshotId: snapshotID, BackupGeneration: "gen-1"}
		_, err := (&GRPCAdapter{mgr: m}).RestoreSnapshot(context.Background(), req)
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("adopted while the boot still held the VM: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	unlock()
	if err := <-done; err != nil {
		t.Fatalf("retry after the commit: %v", err)
	}
}

// A retry that does not name the backup is told to, even with restore off,
// once this host booted the fork from it.
func TestBackupForkRetryWithoutAGenerationIsSentBack(t *testing.T) {
	m := newSavedTestManager(t)
	snapshotID := "5f0c2a9e-1b7d-4c3e-8a6f-0d9e2b4c7a13"
	m.vms["fork-1"] = &VMInstance{ID: "fork-1", Status: StatusRunning, SourceSnapshotID: snapshotID, BackupGeneration: "gen-1"}
	req := &vmdpb.RestoreSnapshotRequest{VmId: "fork-1", SavedSnapshotId: snapshotID, ResourceLimits: &vmdpb.ResourceLimits{VcpuCount: 1, MemoryMib: 512}}
	if _, err := (&GRPCAdapter{mgr: m}).RestoreSnapshot(context.Background(), req); !vmdclient.IsSavedSnapshotMissing(err) {
		t.Fatalf("err = %v, want the saved-snapshot-missing refusal", err)
	}
}

// A fork booted from backup is adopted by its retry even once backup
// restore is off.
func TestBackupForkRetryIsAdoptedWithBackupRestoreOff(t *testing.T) {
	m := newSavedTestManager(t)
	snapshotID := "5f0c2a9e-1b7d-4c3e-8a6f-0d9e2b4c7a13"
	m.vms["fork-1"] = &VMInstance{ID: "fork-1", Status: StatusRunning, SourceSnapshotID: snapshotID, BackupGeneration: "gen-1"}
	orig := vmDeadForRetry
	vmDeadForRetry = func(*Manager, string) bool { return false }
	defer func() { vmDeadForRetry = orig }()
	a := &GRPCAdapter{mgr: m}
	req := &vmdpb.RestoreSnapshotRequest{VmId: "fork-1", SavedSnapshotId: snapshotID, BackupGeneration: "gen-1", ResourceLimits: &vmdpb.ResourceLimits{VcpuCount: 1, MemoryMib: 512}}
	if resp, err := a.RestoreSnapshot(context.Background(), req); err != nil || resp.GetVmId() != "fork-1" {
		t.Fatalf("retry: %v, %v", resp, err)
	}
}
