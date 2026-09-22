package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The uploader lets go of its own staging copies once they are streamed, and
// of nothing else: an unstaged path is an original the next resume faults
// from, and a shared base is re-read by every generation on its template.
func TestUploaderDropsOnlyStagedCopies(t *testing.T) {
	var dropped []string
	prev := dropStagingPages
	dropStagingPages = func(f *os.File) error {
		dropped = append(dropped, f.Name())
		return nil
	}
	t.Cleanup(func() { dropStagingPages = prev })

	// Unstaged: originals, never dropped.
	j, _ := testJournal(t)
	store := newMemStore()
	u := &Uploader{Journal: j, Store: store}
	task := writeTask(t, t.TempDir())
	if err := j.Enqueue(task); err != nil {
		t.Fatal(err)
	}
	if _, err := u.drainOne(context.Background(), time.Unix(2, 0)); err != nil {
		t.Fatal(err)
	}
	if len(dropped) != 0 {
		t.Fatalf("unstaged upload dropped %v, want nothing", dropped)
	}

	// Staged with a shared base: the generation's own copy is dropped, the
	// base is not.
	dir := t.TempDir()
	staging := filepath.Join(dir, "staging")
	base := filepath.Join(dir, "base.ext4")
	baseData := []byte("template base bytes")
	if err := os.WriteFile(base, baseData, 0o644); err != nil {
		t.Fatal(err)
	}
	baseSum := sha256.Sum256(baseData)
	overlay := filepath.Join(dir, "rootfs.ext4")
	odata := []byte("overlay bytes")
	if err := os.WriteFile(overlay, odata, 0o644); err != nil {
		t.Fatal(err)
	}
	osum := sha256.Sum256(odata)
	staged := Task{
		SandboxID: "sb", Generation: "gen", EnqueuedAt: time.Unix(1, 0),
		Files: []TaskFile{{
			Name: "rootfs.ext4", Path: overlay,
			SHA256: hex.EncodeToString(osum[:]), Size: int64(len(odata)),
			BasePath: base, BaseSHA256: hex.EncodeToString(baseSum[:]),
		}},
	}
	if err := StageTask(staging, &staged); err != nil {
		t.Fatal(err)
	}
	staged.Staged = true
	if err := j.Enqueue(staged); err != nil {
		t.Fatal(err)
	}
	u.StagingRoot = staging
	if _, err := u.drainOne(context.Background(), time.Unix(3, 0)); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.objects["sandboxes/sb/gen/manifest.json"]; !ok {
		t.Fatal("staged generation did not complete")
	}
	if len(dropped) != 1 || dropped[0] != staged.Files[0].Path {
		t.Fatalf("dropped %v, want only the staged copy %s", dropped, staged.Files[0].Path)
	}
}

// A copy the pipeline writes is fsynced and then let go of; the file is
// intact afterwards, the drop being a hint and not a change.
func TestSnapshotCopyDropsItsPagesAndKeepsItsBytes(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	data := []byte("staged bytes that must survive the drop")
	if err := os.WriteFile(src, data, 0o644); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "other", "dst")
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := snapshotFile(context.Background(), dst, src); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(data) {
		t.Fatalf("copy = %q, want %q", got, data)
	}
	if err := DropPageCache(dst); err != nil {
		t.Fatalf("DropPageCache: %v", err)
	}
}
