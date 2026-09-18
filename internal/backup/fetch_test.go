package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writePauseFixture(t *testing.T, dir string) Task {
	t.Helper()
	disk := filepath.Join(dir, "rootfs.ext4")
	f, err := os.Create(disk)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(bytes.Repeat([]byte{0xAA}, 64<<10), 0); err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(1 << 20); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vmstate.snap"), []byte("state"), 0o644); err != nil {
		t.Fatal(err)
	}
	task := Task{SandboxID: "sb-fetch", Priority: PriorityPause, EnqueuedAt: time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)}
	for _, name := range []string{"rootfs.ext4", "vmstate.snap"} {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		task.Files = append(task.Files, TaskFile{Name: name, Path: path, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data))})
	}
	task.Generation = GenerationKey(task.Files)
	return task
}

func TestFetchNewestStandaloneDisk(t *testing.T) {
	store := newMemBlobs()
	task := writePauseFixture(t, t.TempDir())
	uploadFixture(t, store, task)

	dest := filepath.Join(t.TempDir(), "sb-fetch")
	got, err := FetchNewest(context.Background(), store, store, task.SandboxID, dest, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Standalone || got.Base != "" || got.Disk != filepath.Join(dest, "rootfs.ext4") {
		t.Fatalf("restored = %+v", got)
	}
	want, _ := os.ReadFile(task.Files[0].Path)
	have, _ := os.ReadFile(got.Disk)
	if !bytes.Equal(want, have) {
		t.Fatal("restored disk differs from the paused one")
	}
}

func TestFetchNewestOverlayWithBase(t *testing.T) {
	store := newMemBlobs()
	dir := t.TempDir()
	baseData := bytes.Repeat([]byte{0x11}, 128<<10)
	basePath := filepath.Join(dir, "base.ext4")
	if err := os.WriteFile(basePath, baseData, 0o644); err != nil {
		t.Fatal(err)
	}
	task := writePauseFixture(t, dir)
	task.Files[0].BasePath = basePath
	task.Files[0].BaseSHA256 = digestOf(baseData)
	task.Generation = GenerationKey(task.Files)
	uploadFixture(t, store, task)

	root := t.TempDir()
	cache := &CachingBaseReader{Inner: store, Dir: filepath.Join(root, ".base-cache")}
	got, err := FetchNewest(context.Background(), cache, store, task.SandboxID, filepath.Join(root, task.SandboxID), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Standalone || got.Base == "" {
		t.Fatalf("overlay restored without its base: %+v", got)
	}
	have, _ := os.ReadFile(got.Base)
	if !bytes.Equal(have, baseData) {
		t.Fatal("restored base differs")
	}
}

func TestFetchNewestNoGeneration(t *testing.T) {
	store := newMemBlobs()
	_, err := FetchNewest(context.Background(), store, store, "sb-none", filepath.Join(t.TempDir(), "x"), nil)
	if !errors.Is(err, ErrNoBackup) {
		t.Fatalf("err = %v, want ErrNoBackup", err)
	}
}
