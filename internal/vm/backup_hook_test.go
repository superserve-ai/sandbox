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
	m := &Manager{
		vms:      map[string]*VMInstance{"vm-1": {Status: StatusPaused, SnapshotPath: snap}},
		unitDead: func(context.Context, string) bool { return true },
	}
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
	m := &Manager{
		vms:      map[string]*VMInstance{"vm-1": {Status: StatusPaused, SnapshotPath: snap}},
		unitDead: func(context.Context, string) bool { return true },
	}
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
	m := &Manager{
		vms:      map[string]*VMInstance{"vm-1": {Status: StatusRunning, SnapshotPath: snap}},
		unitDead: func(context.Context, string) bool { return true },
	}
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
	m := &Manager{
		vms:      map[string]*VMInstance{"vm-1": {Status: StatusPaused, SnapshotPath: snap}},
		unitDead: func(context.Context, string) bool { return true },
	}
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

// A complete manifest whose journal write failed is re-enqueued as-is:
// the retry must carry the pause-time digests, not rehash whatever the
// disk holds by then, and it must not require the sandbox to stay
// paused for the retry window.
func TestBackupPauseRetriesEnqueueWithoutRehashing(t *testing.T) {
	dir := t.TempDir()
	snap := filepath.Join(dir, "vmstate.snap")
	disk := filepath.Join(dir, "rootfs.ext4")
	for _, p := range []string{snap, disk} {
		if err := os.WriteFile(p, []byte("pause-time bytes"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	var calls atomic.Int32
	tasks := make(chan backup.Task, 1)
	// Deliberately NOT paused: the enqueue retry must not care.
	m := &Manager{
		vms:      map[string]*VMInstance{"vm-1": {Status: StatusRunning, SnapshotPath: snap}},
		unitDead: func(context.Context, string) bool { return true },
	}
	m.SetBackupEnqueue(func(task backup.Task) error {
		if calls.Add(1) == 1 {
			return errors.New("transient journal failure")
		}
		tasks <- task
		return nil
	})

	manifest := m.backupPause(context.Background(), "vm-1", snap, disk, "", zerolog.Nop())
	if !pauseManifestComplete(manifest) {
		t.Fatalf("synchronous manifest incomplete: %v", manifest)
	}
	var wantDisk string
	for _, e := range manifest {
		if e.FileName == "rootfs.ext4" {
			wantDisk = e.SHA256
		}
	}
	// Mutate the disk after the sync attempt: a rehash would pick these
	// bytes up, the enqueue retry must not.
	if err := os.WriteFile(disk, []byte("post-resume bytes"), 0o644); err != nil {
		t.Fatal(err)
	}

	select {
	case task := <-tasks:
		for _, f := range task.Files {
			if f.Name == "rootfs.ext4" && f.SHA256 != wantDisk {
				t.Fatalf("retried disk digest %s, want pause-time %s (manifest was rehashed)", f.SHA256, wantDisk)
			}
		}
	case <-time.After(10 * time.Second):
		t.Fatal("enqueue retry never delivered the task")
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

	m.backupPause(context.Background(), "vm-1", missingSnap, disk, "", zerolog.Nop())

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
	if got := m.backupPause(ctx, "vm-1", snap, disk, "", zerolog.Nop()); len(got) != 0 {
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
	m.backupPause(ctx, "vm-1", snap, disk, "", zerolog.Nop())

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

	pb := newPendingBackup("vm-1", snap, disk, base)
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

	pb := newPendingBackup("vm-1", "/snap", "/disk", "")
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
	older := newPendingBackup("vm-1", "/a", "/b", "")
	newer := newPendingBackup("vm-1", "/c", "/d", "")

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
	if err := st.PutPendingBackup(newPendingBackup("vm-1", snap, disk, "")); err != nil {
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

// A resume winning the race against the staging worker must not produce
// a staged snapshot of post-resume bytes: the proof fails, the task
// ships with its original paths, and the marker survives so a later
// sweep can upgrade the queued entry under a real at-rest proof.
func TestStagingFallsBackAndKeepsMarkerWhenNotAtRest(t *testing.T) {
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
		state:         st,
		backupStaging: filepath.Join(dir, "staging"),
		vms:           map[string]*VMInstance{"vm-1": {Status: StatusRunning, SnapshotPath: snap}},
		unitDead:      func(context.Context, string) bool { return false },
	}
	m.SetBackupEnqueue(func(task backup.Task) error { tasks <- task; return nil })

	m.backupPause(context.Background(), "vm-1", snap, disk, "", zerolog.Nop())

	select {
	case task := <-tasks:
		for _, f := range task.Files {
			if f.Name == "rootfs.ext4" && f.Path != disk {
				t.Fatalf("disk staged to %s despite a failed at-rest proof", f.Path)
			}
		}
	case <-time.After(10 * time.Second):
		t.Fatal("task never enqueued")
	}
	pending, err := st.ListPendingBackups()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending = %d, want the marker kept for a staging upgrade", len(pending))
	}
}
