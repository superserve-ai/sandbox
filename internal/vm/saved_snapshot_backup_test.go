package vm

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/backup"
)

// savedBackupFixture commits a mem+fs saved snapshot whose disk is an overlay
// over a template base, and wires a manager whose backup queue records tasks.
func savedBackupFixture(t *testing.T) (*Manager, *SavedSnapshotManifest, *[]backup.Task, map[string]bool) {
	t.Helper()
	m := newSavedTestManager(t)
	id := uuid.NewString()
	dir, err := m.savedSnapshotDir(id)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(t.TempDir(), "base.ext4")
	write := func(p, data string) {
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(base, "template-base")
	man := &SavedSnapshotManifest{
		Version: savedSnapshotVersion, SnapshotID: id, Kind: SavedSnapshotMemFS,
		BasePath: base, DiskPath: filepath.Join(dir, "overlay.ext4"),
		SnapshotPath: filepath.Join(dir, "vmstate.snap"), MemPath: filepath.Join(dir, "mem.diff"),
	}
	write(man.DiskPath, "overlay-blocks")
	write(man.SnapshotPath, "vmstate")
	write(overlayBlockMapPath(man.SnapshotPath), "block-map")
	write(man.MemPath, "memory")
	if err := writeSavedSnapshotManifest(dir, man); err != nil {
		t.Fatal(err)
	}

	var queued []backup.Task
	done := map[string]bool{}
	m.backupEnqueue = func(task backup.Task) error {
		queued = append(queued, task)
		return nil
	}
	m.backupCovered = func(task backup.Task) (bool, error) {
		return done[task.SnapshotID+"/"+task.Generation], nil
	}
	return m, man, &queued, done
}

// A committed snapshot queues its disk, as rootfs.ext4 over its template base,
// and the block map saved with it. Memory and vmstate stay on the host, and
// the queued generation is recorded beside the files.
func TestSavedSnapshotQueuesItsDiskButNotItsMemory(t *testing.T) {
	m, man, queued, _ := savedBackupFixture(t)
	if !m.backupSavedSnapshot(context.Background(), man, zerolog.Nop()) {
		t.Fatal("backup not queued")
	}
	if len(*queued) != 1 {
		t.Fatalf("queued %d tasks, want 1", len(*queued))
	}
	task := (*queued)[0]
	if task.SnapshotID != man.SnapshotID || task.SandboxID != "" || task.Priority != backup.PriorityCheckpoint {
		t.Fatalf("task owner/priority = %+v", task)
	}
	names := map[string]backup.TaskFile{}
	for _, f := range task.Files {
		names[f.Name] = f
	}
	disk, ok := names["rootfs.ext4"]
	if !ok || disk.Path != man.DiskPath || disk.BasePath != man.BasePath || disk.BaseSHA256 == "" {
		t.Fatalf("disk entry = %+v, want the overlay as rootfs.ext4 over its base", disk)
	}
	if _, ok := names[backup.BlockMapName]; !ok || len(task.Files) != 2 {
		t.Fatalf("files = %v, want exactly the disk and its block map", names)
	}
	marker, err := os.ReadFile(filepath.Join(filepath.Dir(man.DiskPath), savedSnapshotBackupMarker))
	if err != nil || string(marker) != task.Generation {
		t.Fatalf("marker = %q (err %v), want %s", marker, err, task.Generation)
	}
}

// A host without a backup bucket queues nothing and writes no marker.
func TestSavedSnapshotBackupIsOffWithoutABucket(t *testing.T) {
	m, man, _, _ := savedBackupFixture(t)
	m.backupEnqueue = nil
	if m.backupSavedSnapshot(context.Background(), man, zerolog.Nop()) {
		t.Fatal("queued with backup disabled")
	}
	m.RecoverSavedSnapshotBackups(context.Background(), zerolog.Nop())
	if _, err := os.Stat(filepath.Join(filepath.Dir(man.DiskPath), savedSnapshotBackupMarker)); !os.IsNotExist(err) {
		t.Fatalf("marker written with backup disabled: err = %v", err)
	}
}

// The sweep leaves a snapshot whose recorded generation is pending or done,
// queues one whose backup was lost, and skips staging and tombstones.
func TestSavedSnapshotSweepQueuesOnlyWhatIsNotBackedUp(t *testing.T) {
	m, man, queued, done := savedBackupFixture(t)
	root := filepath.Join(m.cfg.SnapshotDir, SavedSnapshotsDirName)
	for _, hidden := range []string{"." + man.SnapshotID + ".tmp-1", savedTombstonesDirName} {
		if err := os.MkdirAll(filepath.Join(root, hidden), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	m.RecoverSavedSnapshotBackups(context.Background(), zerolog.Nop())
	if len(*queued) != 1 {
		t.Fatalf("first sweep queued %d tasks, want the one unbacked snapshot", len(*queued))
	}
	gen := (*queued)[0].Generation

	done[man.SnapshotID+"/"+gen] = true
	m.RecoverSavedSnapshotBackups(context.Background(), zerolog.Nop())
	if len(*queued) != 1 {
		t.Fatal("sweep queued a snapshot whose backup is done")
	}

	// The journal lost the generation: the next sweep queues it again.
	done[man.SnapshotID+"/"+gen] = false
	m.RecoverSavedSnapshotBackups(context.Background(), zerolog.Nop())
	if len(*queued) != 2 || !strings.EqualFold((*queued)[1].Generation, gen) {
		t.Fatalf("queued = %d tasks, want the lost generation queued again", len(*queued))
	}
}

// A snapshot deleted while its disk was hashing gets no marker written into
// a directory that no longer exists.
func TestSavedSnapshotMarkerSkipsADeletedSnapshot(t *testing.T) {
	m, man, _, _ := savedBackupFixture(t)
	if err := m.DeleteSavedSnapshot(context.Background(), man.SnapshotID); err != nil {
		t.Fatal(err)
	}
	m.markSavedSnapshotBackup(context.Background(), man.SnapshotID, "gen", zerolog.Nop())
	if _, err := os.Stat(filepath.Dir(man.DiskPath)); !os.IsNotExist(err) {
		t.Fatalf("snapshot directory recreated: err = %v", err)
	}
}
