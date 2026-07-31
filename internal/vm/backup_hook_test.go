package vm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/backup"
)

// A pause whose RPC deadline left no hashing budget must still reach the
// journal: the synchronous attempt is skipped, and the async rehash
// (which carries its own budget) enqueues the generation.
func TestBackupPauseRetriesAsynchronouslyWhenBudgetExhausted(t *testing.T) {
	dir := t.TempDir()
	snap := filepath.Join(dir, "vmstate.snap")
	disk := filepath.Join(dir, "rootfs.ext4")
	if err := os.WriteFile(snap, []byte("vm state"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(disk, []byte("disk bytes"), 0o644); err != nil {
		t.Fatal(err)
	}

	tasks := make(chan backup.Task, 1)
	m := &Manager{vms: map[string]*VMInstance{
		"vm-1": {Status: StatusPaused, SnapshotPath: snap},
	}}
	m.SetBackupEnqueue(func(task backup.Task) error { tasks <- task; return nil })

	ctx, cancel := context.WithDeadline(context.Background(), time.Now())
	defer cancel()
	manifest := m.backupPause(ctx, "vm-1", snap, disk, "", zerolog.Nop())
	if len(manifest) != 0 {
		t.Fatalf("synchronous manifest = %v, want none under an expired deadline", manifest)
	}

	select {
	case task := <-tasks:
		names := make(map[string]bool, len(task.Files))
		for _, f := range task.Files {
			names[f.Name] = true
		}
		if !names["vmstate.snap"] || !names["rootfs.ext4"] {
			t.Fatalf("async task files = %v, want vmstate.snap and rootfs.ext4", names)
		}
		if task.SandboxID != "vm-1" || task.Generation == "" {
			t.Fatalf("task = %+v, want owner vm-1 with a generation key", task)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("async rehash never enqueued the pause")
	}
}

// A rehash that still cannot produce a disk digest (artifact gone) drops
// the pause with an error log but never enqueues a partial generation.
func TestBackupPauseNeverEnqueuesWithoutDiskDigest(t *testing.T) {
	dir := t.TempDir()
	snap := filepath.Join(dir, "vmstate.snap")
	if err := os.WriteFile(snap, []byte("vm state"), 0o644); err != nil {
		t.Fatal(err)
	}

	tasks := make(chan backup.Task, 1)
	m := &Manager{vms: map[string]*VMInstance{
		"vm-1": {Status: StatusPaused, SnapshotPath: snap},
	}}
	m.SetBackupEnqueue(func(task backup.Task) error { tasks <- task; return nil })

	m.backupPause(context.Background(), "vm-1", snap, filepath.Join(dir, "missing.ext4"), "", zerolog.Nop())

	select {
	case task := <-tasks:
		t.Fatalf("enqueued %+v despite a missing disk digest", task)
	case <-time.After(500 * time.Millisecond):
	}
}

// A sandbox that resumed (or vanished) by the time the rehash runs must
// not have its live disk digested: the rehash only trusts bytes proven
// at rest, so a non-paused instance drops the retry entirely.
func TestBackupPauseDropsRehashWhenSandboxNotAtRest(t *testing.T) {
	dir := t.TempDir()
	snap := filepath.Join(dir, "vmstate.snap")
	disk := filepath.Join(dir, "rootfs.ext4")
	for _, p := range []string{snap, disk} {
		if err := os.WriteFile(p, []byte("bytes"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	tasks := make(chan backup.Task, 1)
	m := &Manager{vms: map[string]*VMInstance{
		"vm-1": {Status: StatusRunning, SnapshotPath: snap},
	}}
	m.SetBackupEnqueue(func(task backup.Task) error { tasks <- task; return nil })

	ctx, cancel := context.WithDeadline(context.Background(), time.Now())
	defer cancel()
	if got := m.backupPause(ctx, "vm-1", snap, disk, "", zerolog.Nop()); len(got) != 0 {
		t.Fatalf("synchronous manifest = %v, want none", got)
	}

	select {
	case task := <-tasks:
		t.Fatalf("rehash enqueued %+v for a running sandbox", task)
	case <-time.After(500 * time.Millisecond):
	}
}

// A journal write that fails must count as not-enqueued so the async
// retry runs; success was previously reported on a logged-and-dropped
// error, leaving the pause uncovered with no retry at all.
func TestBackupPauseRetriesWhenJournalWriteFails(t *testing.T) {
	dir := t.TempDir()
	snap := filepath.Join(dir, "vmstate.snap")
	disk := filepath.Join(dir, "rootfs.ext4")
	for _, p := range []string{snap, disk} {
		if err := os.WriteFile(p, []byte("bytes"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	var calls atomic.Int32
	m := &Manager{vms: map[string]*VMInstance{
		"vm-1": {Status: StatusPaused, SnapshotPath: snap},
	}}
	m.SetBackupEnqueue(func(task backup.Task) error {
		calls.Add(1)
		return errors.New("no space left on device")
	})

	m.backupPause(context.Background(), "vm-1", snap, disk, "", zerolog.Nop())

	deadline := time.Now().Add(10 * time.Second)
	for calls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := calls.Load(); got < 2 {
		t.Fatalf("enqueue attempts = %d, want the sync attempt plus the async retry", got)
	}
}
