package vm

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/backup"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
	"github.com/superserve-ai/sandbox/proto/vmdpb"
)

func TestSavedSnapshotFilesMissing(t *testing.T) {
	m, man, _, _ := savedBackupFixture(t)
	if m.savedSnapshotFilesMissing(man.SnapshotID) {
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
		if !m.savedSnapshotFilesMissing(man.SnapshotID) {
			t.Fatalf("a snapshot without %s must read as missing", filepath.Base(path))
		}
	}
	if !m.savedSnapshotFilesMissing("5f0c2a9e-1b7d-4c3e-8a6f-0d9e2b4c7a13") {
		t.Fatal("a snapshot the host never had must read as missing")
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
