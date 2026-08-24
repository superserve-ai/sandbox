package vm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	bolt "go.etcd.io/bbolt"

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
	m := &Manager{
		vms:      map[string]*VMInstance{"vm-1": {Status: StatusPaused, SnapshotPath: snap}},
		unitDead: func(context.Context, string) bool { return true },
	}
	m.SetBackupEnqueue(func(task backup.Task) error { tasks <- task; return nil })

	ctx, cancel := context.WithDeadline(context.Background(), time.Now())
	defer cancel()
	manifest := m.backupPause(ctx, "vm-1", snap, disk, "", "tok-test", zerolog.Nop())
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
	m := &Manager{
		vms:      map[string]*VMInstance{"vm-1": {Status: StatusPaused, SnapshotPath: snap}},
		unitDead: func(context.Context, string) bool { return true },
	}
	m.SetBackupEnqueue(func(task backup.Task) error { tasks <- task; return nil })

	m.backupPause(context.Background(), "vm-1", snap, filepath.Join(dir, "missing.ext4"), "", "tok-test", zerolog.Nop())

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
	m := &Manager{
		vms:      map[string]*VMInstance{"vm-1": {Status: StatusRunning, SnapshotPath: snap}},
		unitDead: func(context.Context, string) bool { return true },
	}
	m.SetBackupEnqueue(func(task backup.Task) error { tasks <- task; return nil })

	ctx, cancel := context.WithDeadline(context.Background(), time.Now())
	defer cancel()
	if got := m.backupPause(ctx, "vm-1", snap, disk, "", "tok-test", zerolog.Nop()); len(got) != 0 {
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
	m := &Manager{
		vms:      map[string]*VMInstance{"vm-1": {Status: StatusPaused, SnapshotPath: snap}},
		unitDead: func(context.Context, string) bool { return true },
	}
	m.SetBackupEnqueue(func(task backup.Task) error {
		calls.Add(1)
		return errors.New("no space left on device")
	})

	m.backupPause(context.Background(), "vm-1", snap, disk, "", "tok-test", zerolog.Nop())

	deadline := time.Now().Add(10 * time.Second)
	for calls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := calls.Load(); got < 2 {
		t.Fatalf("enqueue attempts = %d, want the sync attempt plus the async retry", got)
	}
}

// The pause RPC path pays no size-dependent cost: backupPause returns
// only the cheap vmstate entry immediately, and the detached worker
// hashes and enqueues the full pair under its own budget.
func TestBackupPauseReturnsVMStateOnlyAndEnqueuesAsync(t *testing.T) {
	dir := t.TempDir()
	snap := filepath.Join(dir, "vmstate.snap")
	disk := filepath.Join(dir, "rootfs.ext4")
	for _, p := range []string{snap, disk} {
		if err := os.WriteFile(p, []byte("bytes"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	tasks := make(chan backup.Task, 1)
	m := &Manager{
		vms:      map[string]*VMInstance{"vm-1": {Status: StatusPaused, SnapshotPath: snap}},
		unitDead: func(context.Context, string) bool { return true },
	}
	m.SetBackupEnqueue(func(task backup.Task) error { tasks <- task; return nil })

	manifest := m.backupPause(context.Background(), "vm-1", snap, disk, "", "tok-test", zerolog.Nop())
	if len(manifest) != 1 || manifest[0].FileName != "vmstate.snap" {
		t.Fatalf("synchronous manifest = %+v, want vmstate only", manifest)
	}
	select {
	case task := <-tasks:
		names := map[string]bool{}
		for _, f := range task.Files {
			names[f.Name] = true
		}
		if !names["rootfs.ext4"] || !names["vmstate.snap"] {
			t.Fatalf("async task files = %v, want the full pair", names)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("worker never enqueued the pause")
	}
}

// A manifest whose vmstate hash failed must not enqueue: restore needs
// the disk and vmstate pair, and a disk-only generation would publish a
// manifest describing an unrestorable set.
func TestBackupPauseNeverEnqueuesWithoutVMStateDigest(t *testing.T) {
	dir := t.TempDir()
	disk := filepath.Join(dir, "rootfs.ext4")
	if err := os.WriteFile(disk, []byte("disk bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	missingSnap := filepath.Join(dir, "vmstate.snap")

	tasks := make(chan backup.Task, 1)
	m := &Manager{
		vms:      map[string]*VMInstance{"vm-1": {Status: StatusPaused, SnapshotPath: missingSnap}},
		unitDead: func(context.Context, string) bool { return true },
	}
	m.SetBackupEnqueue(func(task backup.Task) error { tasks <- task; return nil })

	m.backupPause(context.Background(), "vm-1", missingSnap, disk, "", "tok-test", zerolog.Nop())

	select {
	case task := <-tasks:
		t.Fatalf("enqueued %+v despite a missing vmstate digest", task)
	case <-time.After(500 * time.Millisecond):
	}
}

// A transient journal failure after a successful rehash must get the
// same retries as the synchronous complete-manifest path: the rehash
// earned the manifest, one flaky write must not drop it.
func TestBackupPauseRetriesJournalWriteAfterRehash(t *testing.T) {
	dir := t.TempDir()
	snap := filepath.Join(dir, "vmstate.snap")
	disk := filepath.Join(dir, "rootfs.ext4")
	for _, p := range []string{snap, disk} {
		if err := os.WriteFile(p, []byte("bytes"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	var calls atomic.Int32
	tasks := make(chan backup.Task, 1)
	m := &Manager{
		vms:      map[string]*VMInstance{"vm-1": {Status: StatusPaused, SnapshotPath: snap}},
		unitDead: func(context.Context, string) bool { return true },
	}
	m.SetBackupEnqueue(func(task backup.Task) error {
		// First attempt is the rehash's own enqueue; fail it once.
		if calls.Add(1) == 1 {
			return errors.New("transient journal failure")
		}
		tasks <- task
		return nil
	})

	// Expired deadline: the synchronous path hashes nothing, so the first
	// enqueue attempt happens inside the rehash goroutine.
	ctx, cancel := context.WithDeadline(context.Background(), time.Now())
	defer cancel()
	if got := m.backupPause(ctx, "vm-1", snap, disk, "", "tok-test", zerolog.Nop()); len(got) != 0 {
		t.Fatalf("synchronous manifest = %v, want none", got)
	}

	select {
	case task := <-tasks:
		names := make(map[string]bool, len(task.Files))
		for _, f := range task.Files {
			names[f.Name] = true
		}
		if !names["rootfs.ext4"] || !names["vmstate.snap"] {
			t.Fatalf("retried task files = %v, want the full pair", names)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("journal retry after rehash never delivered the task")
	}
}

// A pause whose instance still reads paused but whose unit is not
// confirmed dead must not rehash: resume starts the unit before it
// flips the recorded status, so the status alone proves nothing.
func TestBackupPauseDropsRehashWhenUnitNotDead(t *testing.T) {
	dir := t.TempDir()
	snap := filepath.Join(dir, "vmstate.snap")
	disk := filepath.Join(dir, "rootfs.ext4")
	for _, p := range []string{snap, disk} {
		if err := os.WriteFile(p, []byte("bytes"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	tasks := make(chan backup.Task, 1)
	m := &Manager{
		vms:      map[string]*VMInstance{"vm-1": {Status: StatusPaused, SnapshotPath: snap}},
		unitDead: func(context.Context, string) bool { return false },
	}
	m.SetBackupEnqueue(func(task backup.Task) error { tasks <- task; return nil })

	ctx, cancel := context.WithDeadline(context.Background(), time.Now())
	defer cancel()
	m.backupPause(ctx, "vm-1", snap, disk, "", "tok-test", zerolog.Nop())

	select {
	case task := <-tasks:
		t.Fatalf("enqueued %+v while the unit was not confirmed dead", task)
	case <-time.After(500 * time.Millisecond):
	}
}

// A pause that exits before its rehash completes must survive as a
// durable pending record, and startup recovery must finish the enqueue
// and clear the record.
func TestRecoverPendingBackupsFinishesTheEnqueue(t *testing.T) {
	dir := t.TempDir()
	snap := filepath.Join(dir, "vmstate.snap")
	disk := filepath.Join(dir, "rootfs.ext4")
	for _, p := range []string{snap, disk} {
		if err := os.WriteFile(p, []byte("bytes"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	st, err := OpenStateStore(filepath.Join(dir, "vmd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	// The record a crashed process would have left behind.
	if err := st.PutPendingBackup(PendingBackup{VMID: "vm-1", SnapshotPath: snap, DiskPath: disk}); err != nil {
		t.Fatal(err)
	}

	tasks := make(chan backup.Task, 1)
	m := &Manager{
		state:    st,
		vms:      map[string]*VMInstance{"vm-1": {Status: StatusPaused, SnapshotPath: snap}},
		unitDead: func(context.Context, string) bool { return true },
	}
	m.SetBackupEnqueue(func(task backup.Task) error { tasks <- task; return nil })

	m.RecoverPendingBackups(context.Background(), zerolog.Nop())

	select {
	case task := <-tasks:
		if task.SandboxID != "vm-1" {
			t.Fatalf("recovered task owner = %q, want vm-1", task.SandboxID)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("recovery never enqueued the pending backup")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		pending, err := st.ListPendingBackups()
		if err != nil {
			t.Fatal(err)
		}
		if len(pending) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("pending record not cleared after recovery: %+v", pending)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A recovered record whose sandbox has resumed (or vanished) is
// superseded: recovery must clear it without enqueueing.
func TestRecoverPendingBackupsDropsSupersededRecords(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenStateStore(filepath.Join(dir, "vmd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.PutPendingBackup(PendingBackup{VMID: "vm-gone", SnapshotPath: "/x", DiskPath: "/y"}); err != nil {
		t.Fatal(err)
	}

	tasks := make(chan backup.Task, 1)
	m := &Manager{
		state:    st,
		vms:      map[string]*VMInstance{},
		unitDead: func(context.Context, string) bool { return true },
	}
	m.SetBackupEnqueue(func(task backup.Task) error { tasks <- task; return nil })

	m.RecoverPendingBackups(context.Background(), zerolog.Nop())

	deadline := time.Now().Add(5 * time.Second)
	for {
		pending, err := st.ListPendingBackups()
		if err != nil {
			t.Fatal(err)
		}
		if len(pending) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("superseded record not cleared: %+v", pending)
		}
		time.Sleep(10 * time.Millisecond)
	}
	select {
	case task := <-tasks:
		t.Fatalf("recovery enqueued %+v for a vanished sandbox", task)
	default:
	}
}

// An inconclusive at-rest proof (the liveness probe cannot confirm the
// unit dead) must keep the pending record: only a provably superseded
// pause may delete it, and a transient probe failure is not that.
func TestRehashKeepsRecordWhenProofInconclusive(t *testing.T) {
	dir := t.TempDir()
	snap := filepath.Join(dir, "vmstate.snap")
	disk := filepath.Join(dir, "rootfs.ext4")
	for _, p := range []string{snap, disk} {
		if err := os.WriteFile(p, []byte("bytes"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	st, err := OpenStateStore(filepath.Join(dir, "vmd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	m := &Manager{
		state:    st,
		vms:      map[string]*VMInstance{"vm-1": {Status: StatusPaused, SnapshotPath: snap}},
		unitDead: func(context.Context, string) bool { return false },
	}
	m.SetBackupEnqueue(func(task backup.Task) error { return nil })

	pb := PendingBackup{VMID: "vm-1", SnapshotPath: snap, DiskPath: disk, Token: newPendingToken()}
	if err := st.PutPendingBackup(pb); err != nil {
		t.Fatal(err)
	}
	m.rehashPendingBackup(context.Background(), pb, zerolog.Nop())

	pending, err := st.ListPendingBackups()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending records = %d, want the inconclusive record kept", len(pending))
	}
}

// An older pause's worker must not delete the record a newer pause has
// since written over the same VM-ID key.
func TestOlderWorkerCannotDeleteNewerPendingRecord(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenStateStore(filepath.Join(dir, "vmd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	older := PendingBackup{VMID: "vm-1", SnapshotPath: "/a", DiskPath: "/b", Token: newPendingToken()}
	newer := PendingBackup{VMID: "vm-1", SnapshotPath: "/c", DiskPath: "/d", Token: newPendingToken()}
	if err := st.PutPendingBackup(older); err != nil {
		t.Fatal(err)
	}
	if err := st.PutPendingBackup(newer); err != nil {
		t.Fatal(err)
	}
	if err := st.DeletePendingBackupIf(older.VMID, older.Token); err != nil {
		t.Fatal(err)
	}
	pending, err := st.ListPendingBackups()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Token != newer.Token {
		t.Fatalf("pending = %+v, want only the newer record", pending)
	}
	// The rightful owner still can.
	if err := st.DeletePendingBackupIf(newer.VMID, newer.Token); err != nil {
		t.Fatal(err)
	}
	pending, err = st.ListPendingBackups()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending = %+v, want empty after owner delete", pending)
	}
}

// An at-rest rehash whose hashing fails while the artifacts still exist
// is transient: the record must survive for the sweep. Simulated by
// making the disk path a directory, which stats fine but cannot hash.
func TestRehashKeepsRecordOnTransientHashFailure(t *testing.T) {
	dir := t.TempDir()
	snap := filepath.Join(dir, "vmstate.snap")
	if err := os.WriteFile(snap, []byte("vm state"), 0o644); err != nil {
		t.Fatal(err)
	}
	diskDir := filepath.Join(dir, "rootfs.ext4")
	if err := os.Mkdir(diskDir, 0o755); err != nil {
		t.Fatal(err)
	}
	st, err := OpenStateStore(filepath.Join(dir, "vmd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	m := &Manager{
		state:    st,
		vms:      map[string]*VMInstance{"vm-1": {Status: StatusPaused, SnapshotPath: snap}},
		unitDead: func(context.Context, string) bool { return true },
	}
	m.SetBackupEnqueue(func(task backup.Task) error { return nil })

	pb := PendingBackup{VMID: "vm-1", SnapshotPath: snap, DiskPath: diskDir, Token: newPendingToken()}
	if err := st.PutPendingBackup(pb); err != nil {
		t.Fatal(err)
	}
	m.rehashPendingBackup(context.Background(), pb, zerolog.Nop())

	pending, err := st.ListPendingBackups()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending = %d, want transient failure to keep the record", len(pending))
	}
}

// A record kept on an inconclusive proof must retry within this process
// via the periodic sweep, not only at the next restart.
func TestPendingSweepRetriesRetainedRecords(t *testing.T) {
	dir := t.TempDir()
	snap := filepath.Join(dir, "vmstate.snap")
	disk := filepath.Join(dir, "rootfs.ext4")
	for _, p := range []string{snap, disk} {
		if err := os.WriteFile(p, []byte("bytes"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	st, err := OpenStateStore(filepath.Join(dir, "vmd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// The probe is inconclusive at first, then confirms death: the sweep
	// must pick the record up once the world settles.
	var dead atomic.Bool
	tasks := make(chan backup.Task, 1)
	m := &Manager{
		state:                st,
		vms:                  map[string]*VMInstance{"vm-1": {Status: StatusPaused, SnapshotPath: snap}},
		unitDead:             func(context.Context, string) bool { return dead.Load() },
		pendingSweepInterval: 20 * time.Millisecond,
	}
	m.SetBackupEnqueue(func(task backup.Task) error { tasks <- task; return nil })

	if err := st.PutPendingBackup(PendingBackup{VMID: "vm-1", SnapshotPath: snap, DiskPath: disk, Token: newPendingToken()}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.RecoverPendingBackups(ctx, zerolog.Nop())
	time.Sleep(50 * time.Millisecond)
	dead.Store(true)

	select {
	case task := <-tasks:
		if task.SandboxID != "vm-1" {
			t.Fatalf("swept task owner = %q, want vm-1", task.SandboxID)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("sweep never retried the retained record")
	}
}

// A failed initial persist must self-heal: a worker keeping its record
// re-persists it, so the keep decision survives the process. Simulated
// by never writing the record before the worker runs.
func TestWorkerHealsMissingPendingRecord(t *testing.T) {
	dir := t.TempDir()
	snap := filepath.Join(dir, "vmstate.snap")
	disk := filepath.Join(dir, "rootfs.ext4")
	for _, p := range []string{snap, disk} {
		if err := os.WriteFile(p, []byte("bytes"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	st, err := OpenStateStore(filepath.Join(dir, "vmd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	m := &Manager{
		state:    st,
		vms:      map[string]*VMInstance{"vm-1": {Status: StatusPaused, SnapshotPath: snap}},
		unitDead: func(context.Context, string) bool { return false },
	}
	m.SetBackupEnqueue(func(task backup.Task) error { return nil })

	// The record's initial persist "failed": the store is empty.
	pb := PendingBackup{VMID: "vm-1", SnapshotPath: snap, DiskPath: disk, Token: newPendingToken()}
	m.rehashPendingBackup(context.Background(), pb, zerolog.Nop())

	pending, err := st.ListPendingBackups()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Token != pb.Token {
		t.Fatalf("pending = %+v, want the healed record", pending)
	}
}

// Healing must not clobber a newer pause's record.
func TestHealCannotClobberNewerRecord(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenStateStore(filepath.Join(dir, "vmd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	older := PendingBackup{VMID: "vm-1", SnapshotPath: "/a", DiskPath: "/b", Token: newPendingToken()}
	newer := PendingBackup{VMID: "vm-1", SnapshotPath: "/c", DiskPath: "/d", Token: newPendingToken()}
	if err := st.PutPendingBackup(newer); err != nil {
		t.Fatal(err)
	}
	if err := st.PutPendingBackupIfOwner(older); err != nil {
		t.Fatal(err)
	}
	pending, err := st.ListPendingBackups()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Token != newer.Token {
		t.Fatalf("pending = %+v, want the newer record untouched", pending)
	}
}

// A base replaced at the same path after the pause must not be adopted
// by the rehash: the marker's pause-time identity is the authority, and
// a mismatch drops the record rather than pairing the overlay with a
// stranger's bytes.
func TestRehashRefusesReplacedBase(t *testing.T) {
	dir := t.TempDir()
	snap := filepath.Join(dir, "vmstate.snap")
	disk := filepath.Join(dir, "overlay.ext4")
	base := filepath.Join(dir, "base.ext4")
	for p, data := range map[string]string{snap: "vm state", disk: "overlay", base: "base v1"} {
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	st, err := OpenStateStore(filepath.Join(dir, "vmd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	tasks := make(chan backup.Task, 1)
	m := &Manager{
		state:    st,
		vms:      map[string]*VMInstance{"vm-1": {Status: StatusPaused, SnapshotPath: snap}},
		unitDead: func(context.Context, string) bool { return true },
	}
	m.SetBackupEnqueue(func(task backup.Task) error { tasks <- task; return nil })

	pb := newPendingBackup("vm-1", snap, disk, base, "tok-test")
	if pb.BaseIdentity == "" {
		t.Fatal("marker did not capture the base identity")
	}
	if err := st.PutPendingBackup(pb); err != nil {
		t.Fatal(err)
	}

	// Replace the base in place after the pause.
	if err := os.WriteFile(base, []byte("rebuilt base bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(base, later, later); err != nil {
		t.Fatal(err)
	}

	m.rehashPendingBackup(context.Background(), pb, zerolog.Nop())

	select {
	case task := <-tasks:
		t.Fatalf("enqueued %+v against a replaced base", task)
	default:
	}
	pending, err := st.ListPendingBackups()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending = %+v, want the unrecoverable record dropped", pending)
	}
}

// A newer pause whose initial persist failed while an older worker holds
// the in-flight slot must still leave a durable marker: the heal runs
// before the busy guard and is newest-wins.
func TestBusyGuardStillPersistsNewerMarker(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenStateStore(filepath.Join(dir, "vmd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	m := &Manager{
		state:    st,
		unitDead: func(context.Context, string) bool { return true },
	}
	m.SetBackupEnqueue(func(task backup.Task) error { return nil })
	// An older worker holds the slot.
	m.pendingInFlight.Store("vm-1", struct{}{})

	pb := newPendingBackup("vm-1", "/snap", "/disk", "", "tok-test")
	m.rehashPendingBackup(context.Background(), pb, zerolog.Nop())

	pending, err := st.ListPendingBackups()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Token != pb.Token {
		t.Fatalf("pending = %+v, want the newer marker persisted despite the busy worker", pending)
	}
}

// Healing replaces an older pause's stale row but never a newer one.
func TestHealIsNewestWins(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenStateStore(filepath.Join(dir, "vmd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	older := newPendingBackup("vm-1", "/a", "/b", "", "tok-test")
	newer := newPendingBackup("vm-1", "/c", "/d", "", "tok-test")

	if err := st.PutPendingBackup(older); err != nil {
		t.Fatal(err)
	}
	if err := st.PutPendingBackupIfOwner(newer); err != nil {
		t.Fatal(err)
	}
	pending, _ := st.ListPendingBackups()
	if len(pending) != 1 || pending[0].Token != newer.Token {
		t.Fatalf("pending = %+v, want newer to replace older", pending)
	}
	if err := st.PutPendingBackupIfOwner(older); err != nil {
		t.Fatal(err)
	}
	pending, _ = st.ListPendingBackups()
	if len(pending) != 1 || pending[0].Token != newer.Token {
		t.Fatalf("pending = %+v, want older heal rejected", pending)
	}
}

// A paused VM the startup reattach has not loaded (empty instance map,
// durable record present) is NOT superseded: recovery must still finish
// its backup instead of deleting the marker.
func TestRecoveryTrustsDurableRecordWhenMapUnloaded(t *testing.T) {
	dir := t.TempDir()
	snap := filepath.Join(dir, "vmstate.snap")
	disk := filepath.Join(dir, "rootfs.ext4")
	for _, p := range []string{snap, disk} {
		if err := os.WriteFile(p, []byte("bytes"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	st, err := OpenStateStore(filepath.Join(dir, "vmd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	// The durable record says paused; the map has not been rebuilt.
	if err := st.Put(VMRecord{ID: "vm-1", Status: StatusPaused, SnapshotPath: snap}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutPendingBackup(newPendingBackup("vm-1", snap, disk, "", "tok-test")); err != nil {
		t.Fatal(err)
	}

	tasks := make(chan backup.Task, 1)
	m := &Manager{
		state:    st,
		vms:      map[string]*VMInstance{},
		unitDead: func(context.Context, string) bool { return true },
	}
	m.SetBackupEnqueue(func(task backup.Task) error { tasks <- task; return nil })

	m.RecoverPendingBackups(context.Background(), zerolog.Nop())

	select {
	case task := <-tasks:
		if task.SandboxID != "vm-1" {
			t.Fatalf("recovered task owner = %q", task.SandboxID)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("unloaded-but-paused record treated as superseded")
	}
}

// A resume winning the race against the worker means the pause's bytes
// cannot be proven at rest: nothing is enqueued (mutable-path uploads
// mostly abandoned anyway), and the marker survives for the sweep,
// which supersedes it once the sandbox's next pause covers current
// state.
func TestWorkerKeepsMarkerAndSkipsEnqueueWhenNotAtRest(t *testing.T) {
	dir := t.TempDir()
	snap := filepath.Join(dir, "vmstate.snap")
	disk := filepath.Join(dir, "rootfs.ext4")
	for _, p := range []string{snap, disk} {
		if err := os.WriteFile(p, []byte("bytes"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	st, err := OpenStateStore(filepath.Join(dir, "vmd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	tasks := make(chan backup.Task, 1)
	m := &Manager{
		state: st,
		vms:   map[string]*VMInstance{"vm-1": {Status: StatusPaused, SnapshotPath: snap}},
		// The unit never confirms down: the resume won.
		unitDead: func(context.Context, string) bool { return false },
	}
	m.SetBackupEnqueue(func(task backup.Task) error { tasks <- task; return nil })

	pb := newPendingBackup("vm-1", snap, disk, "", "tok-test")
	m.persistPendingBackup(pb, zerolog.Nop())
	m.rehashPendingBackup(context.Background(), pb, zerolog.Nop())

	select {
	case task := <-tasks:
		t.Fatalf("enqueued %+v while not at rest", task)
	default:
	}
	pending, err := st.ListPendingBackups()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending = %+v, want the marker kept for the sweep", pending)
	}
}

// The latency regression pin: pause-path backup work must not scale
// with disk size. An 8GB sparse overlay (the production shape) must not
// add meaningful synchronous latency; a reintroduced full hash would
// take seconds even sparse-aware and fail this bound.
func TestBackupPausePathIsDiskSizeIndependent(t *testing.T) {
	dir := t.TempDir()
	snap := filepath.Join(dir, "vmstate.snap")
	disk := filepath.Join(dir, "rootfs.ext4")
	if err := os.WriteFile(snap, []byte("vm state"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(disk)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(8 << 30); err != nil {
		f.Close()
		t.Skip("filesystem cannot create an 8GB sparse file")
	}
	f.Close()

	m := &Manager{
		vms:      map[string]*VMInstance{"vm-1": {Status: StatusPaused, SnapshotPath: snap}},
		unitDead: func(context.Context, string) bool { return false }, // worker holds off; only the sync path runs
	}
	m.backupStaging = filepath.Join(dir, "staging")
	m.SetBackupEnqueue(func(task backup.Task) error { return nil })
	awaitRehashWorkers(t, m, 1)

	start := time.Now()
	m.backupPause(context.Background(), "vm-1", snap, disk, "", "tok-test", zerolog.Nop())
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("pause-path backup work took %v against an 8GB overlay; the RPC path must be disk-size independent", elapsed)
	}
}

// An immediate resume must not cost the pause its backup: with staging
// enabled, the pause snapshots immutable copies inline under the VM
// operation lock, and the worker uploads them even though the sandbox
// is running again by the time it looks.
func TestFastResumeKeepsBackupViaInlineStaging(t *testing.T) {
	dir := t.TempDir()
	staging := filepath.Join(dir, "staging")
	snap := filepath.Join(dir, "vmstate.snap")
	disk := filepath.Join(dir, "rootfs.ext4")
	if err := os.WriteFile(snap, []byte("vm state"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(disk, []byte("pause-time disk bytes"), 0o644); err != nil {
		t.Fatal(err)
	}

	tasks := make(chan backup.Task, 1)
	m := &Manager{
		// The sandbox is ALREADY running again: the resume won the race
		// before the worker got its verdict.
		vms:      map[string]*VMInstance{"vm-1": {Status: StatusRunning}},
		unitDead: func(context.Context, string) bool { return false },
	}
	m.backupStaging = staging
	m.SetBackupEnqueue(func(task backup.Task) error { tasks <- task; return nil })
	awaitRehashWorkers(t, m, 1)

	m.backupPause(context.Background(), "vm-1", snap, disk, "", "tok-test", zerolog.Nop())
	// Mutate the originals immediately, as a resumed guest would.
	if err := os.WriteFile(disk, []byte("post-resume bytes!!!"), 0o644); err != nil {
		t.Fatal(err)
	}

	select {
	case task := <-tasks:
		var diskSHA string
		for _, f := range task.Files {
			if f.Name == "rootfs.ext4" {
				diskSHA = f.SHA256
			}
		}
		want := sha256.Sum256([]byte("pause-time disk bytes"))
		if diskSHA != hex.EncodeToString(want[:]) {
			t.Fatalf("task disk digest = %s, want the pause-time bytes", diskSHA)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("fast-resumed pause never enqueued from its staged copies")
	}
}

// A pin created at pause time keeps the base restorable past template
// GC: destroy plus base deletion after the pause must still upload the
// pause-time pair.
func TestBasePinSurvivesBaseDeletion(t *testing.T) {
	dir := t.TempDir()
	staging := filepath.Join(dir, "staging")
	snap := filepath.Join(dir, "vmstate.snap")
	disk := filepath.Join(dir, "overlay.ext4")
	base := filepath.Join(dir, "base.ext4")
	for p, data := range map[string]string{snap: "vm state", disk: "overlay", base: "base bytes"} {
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	tasks := make(chan backup.Task, 1)
	m := &Manager{
		vms:      map[string]*VMInstance{"vm-1": {Status: StatusRunning}},
		unitDead: func(context.Context, string) bool { return false },
	}
	m.backupStaging = staging
	awaitRehashWorkers(t, m, 1)
	// Hold the worker: enqueue blocks until the base is deleted.
	proceed := make(chan struct{})
	m.SetBackupEnqueue(func(task backup.Task) error {
		<-proceed
		tasks <- task
		return nil
	})

	m.backupPause(context.Background(), "vm-1", snap, disk, base, "tok-test", zerolog.Nop())
	// Template GC wins the race before the worker uploads.
	if err := os.Remove(base); err != nil {
		t.Fatal(err)
	}
	close(proceed)

	select {
	case task := <-tasks:
		want := sha256.Sum256([]byte("base bytes"))
		var got string
		for _, f := range task.Files {
			if f.BaseSHA256 != "" {
				got = f.BaseSHA256
			}
		}
		if got != hex.EncodeToString(want[:]) {
			t.Fatalf("base digest = %s, want the pinned pause-time bytes", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("pinned pause never uploaded after base deletion")
	}
}

// baseIdentity embeds the path string it's given, and the fallback base
// comparison in enqueueStagedPending always re-derives its "current"
// identity from diskBasePath. An identity captured via the pin's path
// (a different string, even though pin and diskBasePath share one
// inode) could never match that later comparison, so a perfectly
// unchanged base would read as replaced the moment the pin is lost
// (e.g. absorbed away by FinishPendingStage). The pause-time identity
// must be captured through diskBasePath itself.
// awaitRehashWorkers makes a test wait for the detached pending-backup workers
// backupPause spawns. Those workers outlive the call and keep writing under the
// staging tree, so a test whose staging lives in t.TempDir() otherwise races its
// own cleanup and fails with "directory not empty" on a loaded runner. Registered
// as a cleanup after t.TempDir(), so it runs before the directory is removed.
func awaitRehashWorkers(t *testing.T, m *Manager, n int) {
	t.Helper()
	done := make(chan struct{}, n)
	m.rehashDone = func() { done <- struct{}{} }
	t.Cleanup(func() {
		for i := 0; i < n; i++ {
			select {
			case <-done:
			case <-time.After(30 * time.Second):
				t.Error("pending-backup worker did not finish")
				return
			}
		}
	})
}

func TestBackupPauseCapturesBaseIdentityComparableToDiskBasePath(t *testing.T) {
	dir := t.TempDir()
	staging := filepath.Join(dir, "staging")
	snap := filepath.Join(dir, "vmstate.snap")
	disk := filepath.Join(dir, "overlay.ext4")
	base := filepath.Join(dir, "base.ext4")
	for p, data := range map[string]string{snap: "vm state", disk: "overlay", base: "base bytes"} {
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	st, err := OpenStateStore(filepath.Join(dir, "vmd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	m := &Manager{
		state:    st,
		vms:      map[string]*VMInstance{"vm-1": {Status: StatusPaused, SnapshotPath: snap}},
		unitDead: func(context.Context, string) bool { return false },
	}
	m.backupStaging = staging
	m.SetBackupEnqueue(func(task backup.Task) error { return nil })
	// The detached worker consumes the marker asserted on below, so park it at
	// its own per-VM busy guard: it heals the marker durably, then returns
	// without consuming it.
	m.pendingInFlight.Store("vm-1", struct{}{})
	awaitRehashWorkers(t, m, 1)

	m.backupPause(context.Background(), "vm-1", snap, disk, base, "tok-test", zerolog.Nop())

	pb, ok, err := st.GetPendingBackup("vm-1")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("no pending backup marker recorded")
	}
	want, err := baseIdentity(base)
	if err != nil {
		t.Fatal(err)
	}
	if pb.BaseIdentity != want {
		t.Fatalf("BaseIdentity = %q, want %q (comparable to a later baseIdentity(diskBasePath) call, not the pin's path)", pb.BaseIdentity, want)
	}
}

// An unpinned marker whose base is definitively gone must drop, not
// spin: ENOENT is terminal, unlike a transient stat failure.
func TestUnpinnedMissingBaseIsTerminal(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenStateStore(filepath.Join(dir, "vmd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	stagedDir := filepath.Join(dir, "staging", "vm-1", "pending-tok")
	if err := os.MkdirAll(stagedDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"vmstate.snap", "rootfs.ext4"} {
		if err := os.WriteFile(filepath.Join(stagedDir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	m := &Manager{state: st, unitDead: func(context.Context, string) bool { return false }}
	m.backupStaging = filepath.Join(dir, "staging")
	m.SetBackupEnqueue(func(task backup.Task) error { t.Fatal("must not enqueue"); return nil })

	pb := PendingBackup{
		VMID: "vm-1", Token: "tok", StagedDir: stagedDir,
		SnapshotPath: filepath.Join(stagedDir, "vmstate.snap"),
		DiskPath:     filepath.Join(stagedDir, "rootfs.ext4"),
		DiskBasePath: filepath.Join(dir, "deleted-base.ext4"),
		BaseIdentity: "stale",
	}
	if err := st.PutPendingBackup(pb); err != nil {
		t.Fatal(err)
	}
	m.rehashPendingBackup(context.Background(), pb, zerolog.Nop())
	pending, err := st.ListPendingBackups()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending = %+v, want terminal drop for a deleted unpinned base", pending)
	}
}

// Lost staged copies fall back to the at-rest flow over the recorded
// original paths when the sandbox is still paused on them.
func TestLostStagedCopiesFallBackToOriginals(t *testing.T) {
	dir := t.TempDir()
	snap := filepath.Join(dir, "vmstate.snap")
	disk := filepath.Join(dir, "rootfs.ext4")
	for _, p := range []string{snap, disk} {
		if err := os.WriteFile(p, []byte("original bytes"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	st, err := OpenStateStore(filepath.Join(dir, "vmd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	tasks := make(chan backup.Task, 1)
	m := &Manager{
		state:    st,
		vms:      map[string]*VMInstance{"vm-1": {Status: StatusPaused, SnapshotPath: snap}},
		unitDead: func(context.Context, string) bool { return true },
	}
	m.backupStaging = filepath.Join(dir, "staging")
	m.SetBackupEnqueue(func(task backup.Task) error { tasks <- task; return nil })

	gone := filepath.Join(dir, "staging", "vm-1", "pending-tok")
	pb := PendingBackup{
		VMID: "vm-1", Token: "tok", StagedDir: gone,
		SnapshotPath:     filepath.Join(gone, "vmstate.snap"),
		DiskPath:         filepath.Join(gone, "rootfs.ext4"),
		OrigSnapshotPath: snap, OrigDiskPath: disk,
	}
	if err := st.PutPendingBackup(pb); err != nil {
		t.Fatal(err)
	}
	m.rehashPendingBackup(context.Background(), pb, zerolog.Nop())
	select {
	case task := <-tasks:
		if task.SandboxID != "vm-1" {
			t.Fatalf("owner = %q", task.SandboxID)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("fallback over originals never enqueued")
	}
}

// A control-plane pause retry reuses the live marker instead of paying
// a second staging copy.
func TestRetryPauseReusesExistingStagedMarker(t *testing.T) {
	dir := t.TempDir()
	staging := filepath.Join(dir, "staging")
	snap := filepath.Join(dir, "vmstate.snap")
	disk := filepath.Join(dir, "rootfs.ext4")
	for _, p := range []string{snap, disk} {
		if err := os.WriteFile(p, []byte("bytes"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	st, err := OpenStateStore(filepath.Join(dir, "vmd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	m := &Manager{
		state:    st,
		vms:      map[string]*VMInstance{"vm-1": {Status: StatusPaused, SnapshotPath: snap}},
		unitDead: func(context.Context, string) bool { return false }, // workers stall; we inspect dirs
	}
	m.backupStaging = staging
	m.SetBackupEnqueue(func(task backup.Task) error { return nil })
	// Both pauses spawn a detached worker, and a worker that ran to completion
	// would clean up the very staged dirs counted below. Park them at the
	// per-VM busy guard and wait for both to return before cleanup.
	m.pendingInFlight.Store("vm-1", struct{}{})
	awaitRehashWorkers(t, m, 2)

	m.backupPause(context.Background(), "vm-1", snap, disk, "", "tok-test", zerolog.Nop())
	m.backupPause(context.Background(), "vm-1", snap, disk, "", "tok-test", zerolog.Nop())

	entries, err := os.ReadDir(filepath.Join(staging, "vm-1"))
	if err != nil {
		t.Fatal(err)
	}
	pendings := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "pending-") {
			pendings++
		}
	}
	if pendings != 1 {
		t.Fatalf("pending dirs = %d, want the retry to reuse the first copy", pendings)
	}
}

// A VM's snapshot path is fixed across pauses (always vmstate.snap under
// its snapshot dir), so a resume followed by a second pause reuses the
// exact same pathname as a still-pending marker from the first pause.
// Matching reuse on path alone would mistake the second pause for a
// retry of the first and skip staging its actual disk state, silently
// losing the newer pause. Only the snapshot file's identity (which
// changes when the second pause overwrites it) can tell them apart.
//
// Exercises reusablePendingBackup directly rather than through
// backupPause's full async path: the staged flow's worker needs no
// at-rest proof and can rename the pending directory away before a test
// gets to inspect it, so asserting on directory names on disk races the
// worker instead of testing the reuse decision itself.
func TestReusablePendingBackupRejectsDistinctPauseAtSamePath(t *testing.T) {
	dir := t.TempDir()
	snap := filepath.Join(dir, "vmstate.snap")
	stagedDisk := filepath.Join(dir, "staged-rootfs.ext4")
	if err := os.WriteFile(snap, []byte("first-pause-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stagedDisk, []byte("bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := OpenStateStore(filepath.Join(dir, "vmd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	firstIdentity, err := baseIdentity(snap)
	if err != nil {
		t.Fatal(err)
	}
	marker := PendingBackup{
		VMID:             "vm-1",
		StagedDir:        filepath.Join(dir, "pending-tok1"),
		OrigSnapshotPath: snap,
		DiskPath:         stagedDisk,
		SnapshotIdentity: firstIdentity,
	}
	if err := st.PutPendingBackup(marker); err != nil {
		t.Fatal(err)
	}

	m := &Manager{state: st}

	if _, ok := m.reusablePendingBackup("vm-1", snap); !ok {
		t.Fatal("an RPC retry of the same unchanged pause must reuse the existing marker")
	}

	// A resume followed by a genuinely new pause overwrites the fixed
	// vmstate.snap pathname with different bytes (different size, so
	// identity differs regardless of filesystem mtime resolution).
	if err := os.WriteFile(snap, []byte("second-pause-bytes-are-longer"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.reusablePendingBackup("vm-1", snap); ok {
		t.Fatal("a distinct second pause at the same path must not reuse the first pause's stale marker")
	}
}

// The startup staging sweep runs synchronously, ahead of reattach and
// therefore ahead of RecoverPendingBackups: a durable marker that
// outlived a vmd outage longer than the sweep's orphan horizon has had
// no worker to renew its staging directory's mtime, so without an
// explicit renewal pass the sweep reads it as an abandoned directory
// and deletes it out from under a still-live marker.
func TestRenewPendingStagingProtectsMarkerFromStartupSweep(t *testing.T) {
	dir := t.TempDir()
	staging := filepath.Join(dir, "staging")
	vmID := "vm-1"
	pendingDir := filepath.Join(staging, vmID, "pending-tok1")
	if err := os.MkdirAll(pendingDir, 0o700); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(pendingDir, old, old); err != nil {
		t.Fatal(err)
	}

	st, err := OpenStateStore(filepath.Join(dir, "vmd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.PutPendingBackup(PendingBackup{VMID: vmID, StagedDir: pendingDir, Token: "tok1"}); err != nil {
		t.Fatal(err)
	}

	m := &Manager{state: st}
	m.RenewPendingStaging(zerolog.Nop())

	jdb, err := bolt.Open(filepath.Join(dir, "journal.db"), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer jdb.Close()
	journal, err := backup.NewJournal(jdb)
	if err != nil {
		t.Fatal(err)
	}
	backup.SweepStaging(staging, journal, zerolog.Nop())

	if _, err := os.Stat(pendingDir); err != nil {
		t.Fatalf("pending dir removed by startup sweep despite a live durable marker: %v", err)
	}
}

// enqueueStagedPending persists the marker's final generation path
// BEFORE FinishPendingStage performs the rename that creates it: a
// crash in that window leaves a durable marker naming a directory that
// does not exist yet, while the staged bytes still live under the
// original pending-token directory. Renewing the marker's (nonexistent)
// final path touches nothing, so RenewPendingStaging must fall back to
// the pending-token directory the same way resolveStagedLocation does,
// or the sweep reaps the real artifacts as an untouched orphan.
func TestRenewPendingStagingResolvesPersistBeforeRenameWindow(t *testing.T) {
	dir := t.TempDir()
	staging := filepath.Join(dir, "staging")
	vmID := "vm-1"
	pendingDir := filepath.Join(staging, vmID, "pending-tok1")
	if err := os.MkdirAll(pendingDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pendingDir, "vmstate.snap"), []byte("bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pendingDir, "rootfs.ext4"), []byte("bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(pendingDir, old, old); err != nil {
		t.Fatal(err)
	}

	st, err := OpenStateStore(filepath.Join(dir, "vmd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	finalDir := filepath.Join(staging, vmID, "generation-abc")
	marker := PendingBackup{
		VMID:         vmID,
		Token:        "tok1",
		StagedDir:    finalDir,
		SnapshotPath: filepath.Join(finalDir, "vmstate.snap"),
		DiskPath:     filepath.Join(finalDir, "rootfs.ext4"),
	}
	if err := st.PutPendingBackup(marker); err != nil {
		t.Fatal(err)
	}

	m := &Manager{state: st}
	m.RenewPendingStaging(zerolog.Nop())

	jdb, err := bolt.Open(filepath.Join(dir, "journal.db"), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer jdb.Close()
	journal, err := backup.NewJournal(jdb)
	if err != nil {
		t.Fatal(err)
	}
	backup.SweepStaging(staging, journal, zerolog.Nop())

	if _, err := os.Stat(pendingDir); err != nil {
		t.Fatalf("pending-token dir removed by startup sweep despite a live durable marker resolvable through the persist-before-rename fallback: %v", err)
	}
}

// The at-rest oracle must see the cgroup side: a cgroup VM has no systemd
// unit, so the unit probe alone would read it vacuously dead and back up
// bytes still in flight. A populated group is NOT at rest; a conclusively-
// empty one is (with the unit side also quiet).
func TestVMConfirmedAtRestCgroupMode(t *testing.T) {
	shimSystemctlDown(t) // the unit side is quiet throughout
	dir := t.TempDir()
	tree := &cgroupTree{vms: dir}
	vmID := "vm-1"
	if err := os.MkdirAll(tree.vmCgroupDir(vmID), 0o755); err != nil {
		t.Fatal(err)
	}
	events := filepath.Join(tree.vmCgroupDir(vmID), "cgroup.events")

	m := &Manager{
		log:     zerolog.Nop(),
		cgroups: tree,
		vms:     map[string]*VMInstance{vmID: {ID: vmID, Supervision: SupervisionCgroup}},
	}

	if err := os.WriteFile(events, []byte("populated 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if m.vmConfirmedAtRest(context.Background(), vmID) {
		t.Fatal("a populated cgroup must not read as at-rest")
	}

	if err := os.WriteFile(events, []byte("populated 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !m.vmConfirmedAtRest(context.Background(), vmID) {
		t.Fatal("a conclusively-empty cgroup must read as at-rest")
	}

	// Unreadable events (a non-not-exist read error) is inconclusive, never
	// at-rest. A directory in the file's place forces that error.
	if err := os.Remove(events); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(events, 0o755); err != nil {
		t.Fatal(err)
	}
	if m.vmConfirmedAtRest(context.Background(), vmID) {
		t.Fatal("an unreadable cgroup must not read as at-rest")
	}
}

// shimSystemctlActive answers every unit query "active" — a live unit.
func shimSystemctlActive(t *testing.T) {
	t.Helper()
	shim := t.TempDir()
	script := "#!/bin/sh\ncase \"$1\" in\nshow) echo active ;;\nis-active) exit 0 ;;\nesac\nexit 0\n"
	if err := os.WriteFile(filepath.Join(shim, "systemctl"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shim+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// A crash between a launch and its persist leaves the record's mode behind
// reality: a scope-gone fallback starts a UNIT over a paused cgroup record;
// an armed resume starts a cgroup FC over a unit record. The at-rest proof
// must require BOTH supervisors quiet — the recorded mode's own oracle
// answers vacuously in exactly these windows, and hashing then backs up
// bytes the other supervisor's guest is still writing.
func TestVMConfirmedAtRest_RequiresBothSupervisorsQuiet(t *testing.T) {
	newMgr := func(tree *cgroupTree, sup Supervision) *Manager {
		return &Manager{
			log:     zerolog.Nop(),
			cgroups: tree,
			vms:     map[string]*VMInstance{"vm-1": {ID: "vm-1", Status: StatusPaused, Supervision: sup}},
		}
	}

	t.Run("live fallback unit vetoes a cgroup record", func(t *testing.T) {
		shimSystemctlActive(t)                // the fallback unit is alive
		tree := &cgroupTree{vms: t.TempDir()} // no group: the cgroup oracle reads empty
		if newMgr(tree, SupervisionCgroup).vmConfirmedAtRest(context.Background(), "vm-1") {
			t.Fatal("a live unit must veto at-rest even when the record says cgroup")
		}
	})

	t.Run("live cgroup vetoes a unit record", func(t *testing.T) {
		shimSystemctlDown(t) // no unit — vacuously down
		tree := &cgroupTree{vms: t.TempDir()}
		if err := os.MkdirAll(tree.vmCgroupDir("vm-1"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(tree.vmCgroupDir("vm-1"), "cgroup.events"), []byte("populated 1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if newMgr(tree, SupervisionUnit).vmConfirmedAtRest(context.Background(), "vm-1") {
			t.Fatal("a live cgroup must veto at-rest even when the record says unit")
		}
	})

	t.Run("both supervisors quiet reads at rest", func(t *testing.T) {
		shimSystemctlDown(t)
		tree := &cgroupTree{vms: t.TempDir()}
		if !newMgr(tree, SupervisionCgroup).vmConfirmedAtRest(context.Background(), "vm-1") {
			t.Fatal("no unit and no group must read at rest")
		}
	})
}

// The backfill mints coverage for a paused sandbox the uploader has
// never seen: a best-effort task with both durable artifacts reaches the
// journal, the marker clears on the successful handoff, and the ledger
// records the covered snapshot so the next pass skips it.
func TestBackfillCoversPausedSandboxAtBestEffort(t *testing.T) {
	dir := t.TempDir()
	snap := filepath.Join(dir, "vmstate.snap")
	disk := filepath.Join(dir, "rootfs.ext4")
	for _, p := range []string{snap, disk} {
		if err := os.WriteFile(p, []byte("bytes"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	st, err := OpenStateStore(filepath.Join(dir, "vmd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Put(VMRecord{ID: "vm-1", Status: StatusPaused, SnapshotPath: snap, DiskPath: disk}); err != nil {
		t.Fatal(err)
	}

	tasks := make(chan backup.Task, 2)
	m := &Manager{
		state:    st,
		vms:      map[string]*VMInstance{"vm-1": {Status: StatusPaused, SnapshotPath: snap}},
		unitDead: func(context.Context, string) bool { return true },
	}
	m.SetBackupEnqueue(func(task backup.Task) error { tasks <- task; return nil })

	m.BackfillPausedBackups(context.Background(), zerolog.Nop())

	select {
	case task := <-tasks:
		if task.SandboxID != "vm-1" || task.Generation == "" {
			t.Fatalf("task = %+v, want owner vm-1 with a generation key", task)
		}
		if task.Priority != backup.PriorityBestEffort {
			t.Fatalf("task priority = %d, want best-effort", task.Priority)
		}
		names := make(map[string]bool, len(task.Files))
		for _, f := range task.Files {
			names[f.Name] = true
		}
		if !names["vmstate.snap"] || !names["rootfs.ext4"] {
			t.Fatalf("task files = %v, want vmstate.snap and rootfs.ext4", names)
		}
	default:
		t.Fatal("backfill never enqueued the uncovered paused sandbox")
	}
	if pending, err := st.ListPendingBackups(); err != nil || len(pending) != 0 {
		t.Fatalf("pending markers after backfill = %v (err %v), want none", pending, err)
	}
	if _, _, ok, err := st.GetBackfillMark("vm-1"); err != nil || !ok {
		t.Fatalf("ledger mark missing after backfill (err %v)", err)
	}

	// A second pass over the unchanged snapshot mints nothing.
	m.BackfillPausedBackups(context.Background(), zerolog.Nop())
	select {
	case task := <-tasks:
		t.Fatalf("second pass re-enqueued %+v for an unchanged snapshot", task)
	default:
	}
}

// A snapshot whose identity changed since the ledger entry (the sandbox
// paused again with new bytes) is picked up again, converging on the
// pause's own generation via journal dedupe rather than being skipped.
func TestBackfillReenqueuesChangedSnapshot(t *testing.T) {
	dir := t.TempDir()
	snap := filepath.Join(dir, "vmstate.snap")
	disk := filepath.Join(dir, "rootfs.ext4")
	for _, p := range []string{snap, disk} {
		if err := os.WriteFile(p, []byte("bytes"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	st, err := OpenStateStore(filepath.Join(dir, "vmd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Put(VMRecord{ID: "vm-1", Status: StatusPaused, SnapshotPath: snap, DiskPath: disk}); err != nil {
		t.Fatal(err)
	}

	tasks := make(chan backup.Task, 2)
	m := &Manager{
		state:    st,
		vms:      map[string]*VMInstance{"vm-1": {Status: StatusPaused, SnapshotPath: snap}},
		unitDead: func(context.Context, string) bool { return true },
	}
	m.SetBackupEnqueue(func(task backup.Task) error { tasks <- task; return nil })

	m.BackfillPausedBackups(context.Background(), zerolog.Nop())
	first := <-tasks

	if err := os.WriteFile(snap, []byte("newer vm state"), 0o644); err != nil {
		t.Fatal(err)
	}
	m.BackfillPausedBackups(context.Background(), zerolog.Nop())
	select {
	case task := <-tasks:
		if task.Generation == first.Generation {
			t.Fatal("changed snapshot produced the first generation key")
		}
	default:
		t.Fatal("backfill skipped a snapshot whose identity changed")
	}
}

// An existing pending marker owns its VM's coverage: the backfill must
// neither replace it nor drain it (the sweep owns retained markers), and
// non-paused or incomplete records contribute nothing.
func TestBackfillLeavesExistingMarkersAndSkipsIneligible(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenStateStore(filepath.Join(dir, "vmd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	marked := PendingBackup{VMID: "vm-marked", SnapshotPath: "/snap", DiskPath: "/disk", Token: "t-1"}
	if err := st.PutPendingBackup(marked); err != nil {
		t.Fatal(err)
	}
	for _, rec := range []VMRecord{
		{ID: "vm-marked", Status: StatusPaused, SnapshotPath: "/snap", DiskPath: "/disk"},
		{ID: "vm-running", Status: StatusRunning, SnapshotPath: "/snap", DiskPath: "/disk"},
		{ID: "vm-no-snapshot", Status: StatusPaused, DiskPath: "/disk"},
	} {
		if err := st.Put(rec); err != nil {
			t.Fatal(err)
		}
	}

	tasks := make(chan backup.Task, 1)
	m := &Manager{
		state:    st,
		vms:      map[string]*VMInstance{},
		unitDead: func(context.Context, string) bool { return true },
	}
	m.SetBackupEnqueue(func(task backup.Task) error { tasks <- task; return nil })

	m.BackfillPausedBackups(context.Background(), zerolog.Nop())

	select {
	case task := <-tasks:
		t.Fatalf("backfill enqueued %+v, want nothing", task)
	default:
	}
	got, ok, err := st.GetPendingBackup("vm-marked")
	if err != nil || !ok || got.Token != "t-1" {
		t.Fatalf("existing marker = %+v ok=%v (err %v), want the original untouched", got, ok, err)
	}
}

// Ledger entries for VMs whose records are gone are pruned, so the
// ledger tracks the live fleet instead of growing forever.
func TestBackfillPrunesLedgerForDeletedVMs(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenStateStore(filepath.Join(dir, "vmd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.PutBackfillMark("vm-gone", "stale-identity", "gen-stale"); err != nil {
		t.Fatal(err)
	}

	m := &Manager{
		state:    st,
		vms:      map[string]*VMInstance{},
		unitDead: func(context.Context, string) bool { return true },
	}
	m.SetBackupEnqueue(func(task backup.Task) error { return nil })

	m.BackfillPausedBackups(context.Background(), zerolog.Nop())

	if _, _, ok, err := st.GetBackfillMark("vm-gone"); err != nil || ok {
		t.Fatalf("stale ledger entry survived the prune (ok=%v err=%v)", ok, err)
	}
}

// A ledger mark proves an enqueue happened, not that the upload survived:
// the retry ceiling can abandon the task after the mark was written, and
// a backfilled sandbox may never pause again to replace the loss. The
// skip path therefore holds only while the journal still shows the owner
// pending or completed; a stale mark re-mints, and probe errors keep the
// skip.
func TestBackfillRemintsAfterAbandonedTask(t *testing.T) {
	dir := t.TempDir()
	snap := filepath.Join(dir, "vmstate.snap")
	disk := filepath.Join(dir, "rootfs.ext4")
	for _, p := range []string{snap, disk} {
		if err := os.WriteFile(p, []byte("bytes"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	st, err := OpenStateStore(filepath.Join(dir, "vmd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Put(VMRecord{ID: "vm-1", Status: StatusPaused, SnapshotPath: snap, DiskPath: disk}); err != nil {
		t.Fatal(err)
	}

	tasks := make(chan backup.Task, 4)
	covered := true
	var probeErr error
	var probedGen string
	var mintedGen string
	m := &Manager{
		state:    st,
		vms:      map[string]*VMInstance{"vm-1": {Status: StatusPaused, SnapshotPath: snap}},
		unitDead: func(context.Context, string) bool { return true },
	}
	m.SetBackupEnqueue(func(task backup.Task) error { mintedGen = task.Generation; tasks <- task; return nil })
	m.SetBackupCovered(func(task backup.Task) (bool, error) { probedGen = task.Generation; return covered, probeErr })

	drain := func() int {
		n := 0
		for {
			select {
			case <-tasks:
				n++
			default:
				return n
			}
		}
	}

	m.BackfillPausedBackups(context.Background(), zerolog.Nop())
	if n := drain(); n != 1 {
		t.Fatalf("first pass enqueued %d tasks, want 1", n)
	}

	// Still covered: the mark skips, probing exactly the generation the
	// mint enqueued.
	m.BackfillPausedBackups(context.Background(), zerolog.Nop())
	if n := drain(); n != 0 {
		t.Fatalf("covered pass enqueued %d tasks, want 0", n)
	}
	if probedGen == "" || probedGen != mintedGen {
		t.Fatalf("probe generation = %q, want the minted generation %q", probedGen, mintedGen)
	}

	// The task was abandoned (no pending row, no completion): the mark is
	// stale and the snapshot re-mints.
	covered = false
	m.BackfillPausedBackups(context.Background(), zerolog.Nop())
	if n := drain(); n != 1 {
		t.Fatalf("post-abandon pass enqueued %d tasks, want a re-mint", n)
	}

	// A probe error keeps the skip: transient journal trouble must not
	// stampede the fleet into re-hashing.
	covered = false
	probeErr = errors.New("journal unavailable")
	m.BackfillPausedBackups(context.Background(), zerolog.Nop())
	if n := drain(); n != 0 {
		t.Fatalf("probe-error pass enqueued %d tasks, want 0", n)
	}
}

// An unchanged re-pause that reuses a live staged marker is a NEW logical
// pause: the reuse must rotate the marker's ownership token along with
// the pause token, so a still-running old worker's owner-guarded cleanup
// cannot delete the refreshed marker after enqueueing its stale identity.
func TestMarkerReuseRotatesOwnershipWithPauseToken(t *testing.T) {
	dir := t.TempDir()
	staging := filepath.Join(dir, "staging")
	snap := filepath.Join(dir, "vmstate.snap")
	disk := filepath.Join(dir, "rootfs.ext4")
	for _, p := range []string{snap, disk} {
		if err := os.WriteFile(p, []byte("bytes"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	st, err := OpenStateStore(filepath.Join(dir, "vmd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	m := &Manager{
		state:    st,
		vms:      map[string]*VMInstance{"vm-1": {Status: StatusPaused, SnapshotPath: snap}},
		unitDead: func(context.Context, string) bool { return false },
	}
	m.backupStaging = staging
	m.SetBackupEnqueue(func(task backup.Task) error { return nil })
	// Park the workers at the busy guard, as a still-running old worker
	// would hold it in production.
	m.pendingInFlight.Store("vm-1", struct{}{})
	awaitRehashWorkers(t, m, 2)

	m.backupPause(context.Background(), "vm-1", snap, disk, "", "tok-pause-1", zerolog.Nop())
	first, ok, err := m.state.GetPendingBackup("vm-1")
	if err != nil || !ok {
		t.Fatalf("first marker: ok=%v err=%v", ok, err)
	}
	if first.PauseToken != "tok-pause-1" {
		t.Fatalf("first marker pause token = %q", first.PauseToken)
	}

	// Re-pause on identical artifacts with a new control-plane token.
	m.backupPause(context.Background(), "vm-1", snap, disk, "", "tok-pause-2", zerolog.Nop())
	second, ok, err := m.state.GetPendingBackup("vm-1")
	if err != nil || !ok {
		t.Fatalf("second marker: ok=%v err=%v", ok, err)
	}
	if second.PauseToken != "tok-pause-2" {
		t.Fatalf("marker pause token = %q, want tok-pause-2", second.PauseToken)
	}
	if second.Token == first.Token {
		t.Fatal("ownership token not rotated: the old worker's cleanup could still delete the refreshed marker")
	}

	// The old worker's owner-guarded cleanup must no-op against it.
	if err := m.state.DeletePendingBackupIf("vm-1", first.Token); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := m.state.GetPendingBackup("vm-1"); !ok {
		t.Fatal("refreshed marker deleted by the old ownership token")
	}
}
