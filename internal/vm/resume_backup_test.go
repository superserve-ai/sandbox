package vm

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/backup"
)

func touch(t *testing.T, path string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPausedDiskPath(t *testing.T) {
	if got := pausedDiskPath("/run", "vm-1", "/rec/disk.ext4", "", ""); got != "/rec/disk.ext4" {
		t.Fatalf("recorded disk wins, got %s", got)
	}
	if got := pausedDiskPath("/run", "vm-1", "", "", ""); got != "/run/vm-1/rootfs.ext4" {
		t.Fatalf("plain rootfs, got %s", got)
	}
	if got := pausedDiskPath("/run", "vm-1", "", "rd-9", "/tpl/base.ext4"); got != "/run/rd-9/overlay.ext4" {
		t.Fatalf("overlay under the run dir id, got %s", got)
	}
}

func TestPauseArtifactsMissing(t *testing.T) {
	dir := t.TempDir()
	snap := touch(t, filepath.Join(dir, "snap", "vmstate.snap"))
	mem := touch(t, filepath.Join(dir, "snap", "mem.snap"))
	touch(t, filepath.Join(dir, "run", "vm-1", "rootfs.ext4"))
	mgr := &Manager{
		log: zerolog.Nop(),
		cfg: ManagerConfig{RunDir: filepath.Join(dir, "run")},
		vms: map[string]*VMInstance{"vm-1": {ID: "vm-1", Status: StatusPaused}},
	}
	if mgr.pauseArtifactsMissing("vm-1", snap, mem) {
		t.Fatal("every artifact present must not read as missing")
	}
	if err := os.Remove(mem); err != nil {
		t.Fatal(err)
	}
	if !mgr.pauseArtifactsMissing("vm-1", snap, mem) {
		t.Fatal("a missing memory file must read as missing")
	}
	mgr.vms["vm-1"].Status = StatusRunning
	if mgr.pauseArtifactsMissing("vm-1", snap, mem) {
		t.Fatal("only paused records qualify")
	}
	if mgr.pauseArtifactsMissing("vm-2", snap, mem) {
		t.Fatal("an unknown vm must not qualify")
	}
}

type slowEmptyStore struct {
	delay time.Duration
	lists atomic.Int32
}

func (s *slowEmptyStore) NewReader(context.Context, string) (io.ReadCloser, error) {
	return nil, backup.ErrObjectNotFound
}

func (s *slowEmptyStore) List(ctx context.Context, _ string) ([]backup.ObjectInfo, error) {
	s.lists.Add(1)
	select {
	case <-time.After(s.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return nil, nil
}

func newBackupTestManager(t *testing.T, store *slowEmptyStore) *Manager {
	t.Helper()
	dir := t.TempDir()
	mgr := &Manager{
		log: zerolog.Nop(),
		cfg: ManagerConfig{RunDir: filepath.Join(dir, "run")},
		vms: map[string]*VMInstance{"vm-1": {ID: "vm-1", Status: StatusPaused, TeamID: "team"}},
	}
	mgr.SetBackupRestore(store, store, filepath.Join(dir, ".restore"), BackupRestoreOptions{Concurrency: 1})
	return mgr
}

func TestResumeFromBackupFailsClosedWithoutAnchor(t *testing.T) {
	mgr := newBackupTestManager(t, &slowEmptyStore{})
	_, err := mgr.resumeFromBackupLocked(context.Background(), "vm-1", nil, nil)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v, want FailedPrecondition", err)
	}
}

func TestResumeFromBackupOutlivesTheCallerAndIsJoinedByTheRetry(t *testing.T) {
	store := &slowEmptyStore{delay: 300 * time.Millisecond}
	mgr := newBackupTestManager(t, store)
	anchor := backup.CaptureAnchor{"vmstate.snap": "abc"}

	short, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := mgr.resumeFromBackupLocked(short, "vm-1", anchor, nil)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("first attempt: err = %v, want Unavailable while the fetch continues", err)
	}
	if _, err := mgr.resumeFromBackupLocked(context.Background(), "vm-1", backup.CaptureAnchor{"vmstate.snap": "other"}, nil); status.Code(err) != codes.Aborted {
		t.Fatalf("different pause mid-flight: err = %v, want Aborted", err)
	}
	_, err = mgr.resumeFromBackupLocked(context.Background(), "vm-1", anchor, nil)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("retry: err = %v, want FailedPrecondition from the joined fetch finding no backup", err)
	}
	if n := store.lists.Load(); n != 1 {
		t.Fatalf("bucket listed %d times, want one shared fetch", n)
	}
	mgr.backupFlightsMu.Lock()
	left := len(mgr.backupFlights)
	mgr.backupFlightsMu.Unlock()
	if left != 0 {
		t.Fatal("finished flight must be released")
	}
}

func TestBackupRevivedTargetAdoptsTheSamePauseOnly(t *testing.T) {
	orig := vmDeadForRetry
	vmDeadForRetry = func(*Manager, string) bool { return false }
	defer func() { vmDeadForRetry = orig }()
	live := &VMInstance{ID: "vm-1", Status: StatusRunning, BackupAnchor: "vmstate.snap=abc"}
	mgr := &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{"vm-1": live}}
	if mgr.backupRevivedTarget("vm-1", "vmstate.snap=abc") != live {
		t.Fatal("a retry of the same recorded pause must adopt the revived VM")
	}
	if mgr.backupRevivedTarget("vm-1", "vmstate.snap=other") != nil {
		t.Fatal("a different pause must not adopt it")
	}
	if mgr.backupRevivedTarget("vm-1", "") != nil {
		t.Fatal("no anchor must not adopt it")
	}
	live.Unverified = true
	if mgr.backupRevivedTarget("vm-1", "vmstate.snap=abc") != nil {
		t.Fatal("an unverified VM must not be adopted")
	}
}
