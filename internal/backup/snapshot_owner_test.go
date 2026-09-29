package backup

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A saved snapshot is its own owner: it enqueues alone, never alongside
// another owner, and keeps a queue identity distinct from a sandbox or
// template sharing its generation.
func TestJournalAcceptsASnapshotOwner(t *testing.T) {
	j, _ := testJournal(t)
	snap := Task{SnapshotID: "snap-1", Generation: "shared-gen", Priority: PriorityCheckpoint}
	if err := j.Enqueue(snap); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []Task{
		{SnapshotID: "snap-1", SandboxID: "sb", Generation: "g"},
		{SnapshotID: "snap-1", TemplateID: "tpl", BuildID: "b", Generation: "g"},
	} {
		if err := j.Enqueue(bad); err == nil {
			t.Fatalf("enqueue with two owners accepted: %+v", bad)
		}
	}
	sandbox := Task{SandboxID: "snap-1", Generation: "shared-gen", Priority: PriorityCheckpoint}
	if string(snap.indexKey()) == string(sandbox.indexKey()) {
		t.Fatal("a snapshot and a sandbox with the same id and generation share a queue identity")
	}
	if err := j.Enqueue(sandbox); err != nil {
		t.Fatal(err)
	}
	if counts, _ := j.Pending(); counts[PriorityCheckpoint] != 2 {
		t.Fatalf("pending = %v, want both owners queued", counts)
	}
}

// A completion seeded back into the outbox keeps its snapshot owner, so the
// control plane records it against the snapshot rather than a sandbox.
func TestSeededCompletionKeepsTheSnapshotOwner(t *testing.T) {
	j, _ := testJournal(t)
	task := Task{SnapshotID: "snap-1", Generation: "gen-1", EnqueuedAt: time.Unix(1, 0)}
	if err := j.Enqueue(task); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Ack(task, "bucket-a", false); err != nil {
		t.Fatal(err)
	}
	if _, err := j.SeedOutboxFromCompletions(); err != nil {
		t.Fatal(err)
	}
	pending, err := j.PendingNotifications(0)
	if err != nil || len(pending) != 1 {
		t.Fatalf("outbox = %d entries, err %v", len(pending), err)
	}
	if got := pending[0]; got.SnapshotID != "snap-1" || got.SandboxID != "" || got.Generation != "gen-1" {
		t.Fatalf("seeded entry = %+v, want the snapshot owner", got)
	}
}

// After a snapshot's upload the uploader drops the snapshot's own files from
// the page cache, never the shared base other generations read.
func TestSnapshotUploadDropsItsFilesFromThePageCache(t *testing.T) {
	var dropped []string
	prev := dropStagingPages
	dropStagingPages = func(path string) error {
		dropped = append(dropped, path)
		return nil
	}
	t.Cleanup(func() { dropStagingPages = prev })

	dir := t.TempDir()
	baseData := bytes.Repeat([]byte{0x11}, 64<<10)
	basePath := filepath.Join(dir, "base.ext4")
	diskData := bytes.Repeat([]byte{0x22}, 32<<10)
	disk := filepath.Join(dir, "overlay.ext4")
	for p, d := range map[string][]byte{basePath: baseData, disk: diskData} {
		if err := os.WriteFile(p, d, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	task := Task{
		SnapshotID: "5b9c2e1a-0000-4000-8000-000000000002",
		Priority:   PriorityCheckpoint,
		Files: []TaskFile{{
			Name: "rootfs.ext4", Path: disk, SHA256: digestOf(diskData), Size: int64(len(diskData)),
			BasePath: basePath, BaseSHA256: digestOf(baseData),
		}},
	}
	task.Generation = GenerationKey(task.Files)
	j, _ := testJournal(t)
	if err := j.Enqueue(task); err != nil {
		t.Fatal(err)
	}
	u := &Uploader{Journal: j, Store: newMemBlobs()}
	if _, err := u.drainOne(context.Background(), time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(dropped) != 1 || dropped[0] != disk {
		t.Fatalf("dropped %v, want only the snapshot's disk", dropped)
	}
}

// A snapshot's disk uploads under its own prefix, with its overlay base as a
// shared object, and a purge removes the generation but leaves the base.
func TestSnapshotGenerationUploadsAndPurgesUnderItsOwnPrefix(t *testing.T) {
	store := newMemBlobs()
	dir := t.TempDir()
	baseData := bytes.Repeat([]byte{0x11}, 64<<10)
	basePath := filepath.Join(dir, "base.ext4")
	if err := os.WriteFile(basePath, baseData, 0o644); err != nil {
		t.Fatal(err)
	}
	diskData := bytes.Repeat([]byte{0x22}, 32<<10)
	disk := filepath.Join(dir, "overlay.ext4")
	if err := os.WriteFile(disk, diskData, 0o644); err != nil {
		t.Fatal(err)
	}
	task := Task{
		SnapshotID: "5b9c2e1a-0000-4000-8000-000000000001",
		Priority:   PriorityCheckpoint,
		Files: []TaskFile{{
			Name: "rootfs.ext4", Path: disk, SHA256: digestOf(diskData), Size: int64(len(diskData)),
			BasePath: basePath, BaseSHA256: digestOf(baseData),
		}},
	}
	task.Generation = GenerationKey(task.Files)
	uploadFixture(t, store, task)

	prefix := "snapshots/" + task.SnapshotID + "/" + task.Generation + "/"
	objects := objectNames(t, store, prefix)
	if len(objects) != 2 {
		t.Fatalf("snapshot generation objects = %v, want the disk and the manifest", objects)
	}
	if got := objectNames(t, store, "sandboxes/"); len(got) != 0 {
		t.Fatalf("snapshot objects landed under sandboxes/: %v", got)
	}
	if got := objectNames(t, store, "bases/"); len(got) != 1 {
		t.Fatalf("shared bases = %v, want the overlay's base", got)
	}
	var manifest string
	for _, name := range objects {
		if strings.HasSuffix(name, ManifestObject) {
			manifest = name
		}
	}
	r, err := store.NewReader(context.Background(), manifest)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(r)
	r.Close()
	if err != nil || !bytes.Contains(data, []byte(`"snapshot_id":"`+task.SnapshotID+`"`)) {
		t.Fatalf("manifest %q does not name the snapshot: %s (err %v)", manifest, data, err)
	}

	deleted, err := PurgeSnapshotGeneration(context.Background(), store, task.SnapshotID, task.Generation)
	if err != nil || deleted != 2 {
		t.Fatalf("purge deleted %d, err %v; want 2", deleted, err)
	}
	if left := objectNames(t, store, prefix); len(left) != 0 {
		t.Fatalf("objects left after purge: %v", left)
	}
	if got := objectNames(t, store, "bases/"); len(got) != 1 {
		t.Fatalf("purge touched the shared base: %v", got)
	}
}
