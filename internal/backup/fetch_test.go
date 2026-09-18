package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func writePauseFixture(t *testing.T, dir, state string) Task {
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
	if err := os.WriteFile(filepath.Join(dir, "vmstate.snap"), []byte(state), 0o644); err != nil {
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

func anchorFor(task Task) CaptureAnchor {
	for _, f := range task.Files {
		if f.Name == "vmstate.snap" {
			return CaptureAnchor{"vmstate.snap": f.SHA256}
		}
	}
	return nil
}

func TestFetchMatchingPicksTheAnchoredGenerationNotTheNewest(t *testing.T) {
	store := newMemBlobs()
	older := writePauseFixture(t, t.TempDir(), "pause A")
	uploadFixture(t, store, older)
	newer := writePauseFixture(t, t.TempDir(), "pause B")
	uploadFixture(t, store, newer)

	dest := filepath.Join(t.TempDir(), older.SandboxID)
	got, err := FetchMatching(context.Background(), store, store, older.SandboxID, anchorFor(older), dest, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Manifest.Generation != older.Generation {
		t.Fatalf("restored generation %s, want the anchored %s", got.Manifest.Generation, older.Generation)
	}
	if !got.Standalone || got.Disk != filepath.Join(dest, "rootfs.ext4") {
		t.Fatalf("restored = %+v", got)
	}
}

func TestFetchMatchingFailsClosed(t *testing.T) {
	store := newMemBlobs()
	task := writePauseFixture(t, t.TempDir(), "pause A")
	uploadFixture(t, store, task)
	dest := filepath.Join(t.TempDir(), "x")

	if _, err := FetchMatching(context.Background(), store, store, task.SandboxID, nil, dest, nil); !errors.Is(err, ErrNoMatchingBackup) {
		t.Fatalf("empty anchor: err = %v, want ErrNoMatchingBackup", err)
	}
	stale := CaptureAnchor{"vmstate.snap": digestOf([]byte("pause never uploaded"))}
	if _, err := FetchMatching(context.Background(), store, store, task.SandboxID, stale, dest, nil); !errors.Is(err, ErrNoMatchingBackup) {
		t.Fatalf("unmatched anchor: err = %v, want ErrNoMatchingBackup", err)
	}
	if _, err := os.Stat(dest); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a failed match must leave no restore dir behind")
	}
}

func TestFetchMatchingReusesACompletedRestore(t *testing.T) {
	store := newMemBlobs()
	task := writePauseFixture(t, t.TempDir(), "pause A")
	uploadFixture(t, store, task)
	dest := filepath.Join(t.TempDir(), task.SandboxID)
	if _, err := FetchMatching(context.Background(), store, store, task.SandboxID, anchorFor(task), dest, nil); err != nil {
		t.Fatal(err)
	}
	counter := &countingReader{inner: store}
	if _, err := FetchMatching(context.Background(), counter, store, task.SandboxID, anchorFor(task), dest, nil); err != nil {
		t.Fatal(err)
	}
	if len(counter.reads) != 0 {
		t.Fatalf("a completed restore was fetched again: %v", counter.reads)
	}
}

func TestFetchMatchingOverlayWithBaseThroughLimiter(t *testing.T) {
	store := newMemBlobs()
	dir := t.TempDir()
	baseData := bytes.Repeat([]byte{0x11}, 128<<10)
	basePath := filepath.Join(dir, "base.ext4")
	if err := os.WriteFile(basePath, baseData, 0o644); err != nil {
		t.Fatal(err)
	}
	task := writePauseFixture(t, dir, "pause A")
	task.Files[0].BasePath = basePath
	task.Files[0].BaseSHA256 = digestOf(baseData)
	task.Generation = GenerationKey(task.Files)
	uploadFixture(t, store, task)

	root := t.TempDir()
	limited := &LimitedReader{Inner: store, Limiter: rate.NewLimiter(rate.Limit(64<<20), 1<<20)}
	cache := &CachingBaseReader{Inner: limited, Dir: filepath.Join(root, ".base-cache")}
	got, err := FetchMatching(context.Background(), cache, store, task.SandboxID, anchorFor(task), filepath.Join(root, task.SandboxID), nil)
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

func TestPruneBaseCacheDropsOldestFirst(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, ".unpacked-aaaa")
	newer := filepath.Join(dir, ".unpacked-bbbb")
	for _, p := range []string{old, newer} {
		if err := os.WriteFile(p, bytes.Repeat([]byte{1}, 1024), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	past := time.Now().Add(-time.Hour)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}
	removed, err := PruneBaseCache(dir, 1500)
	if err != nil || removed != 1 {
		t.Fatalf("removed=%d err=%v", removed, err)
	}
	if _, err := os.Stat(old); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the oldest master must go first")
	}
	if _, err := os.Stat(newer); err != nil {
		t.Fatal("the newer master must stay")
	}
}

func TestAnchorKeyIsOrderIndependent(t *testing.T) {
	a := AnchorKey(map[string]string{"x": "1", "y": "2"})
	b := AnchorKey(map[string]string{"y": "2", "x": "1"})
	if a != b || a == "" || AnchorKey(nil) != "" {
		t.Fatalf("keys %q %q", a, b)
	}
}

func TestFetchMatchingUsesTheHostBaseWithoutDownloadingIt(t *testing.T) {
	store := newMemBlobs()
	dir := t.TempDir()
	baseData := bytes.Repeat([]byte{0x11}, 128<<10)
	basePath := filepath.Join(dir, "base.ext4")
	if err := os.WriteFile(basePath, baseData, 0o644); err != nil {
		t.Fatal(err)
	}
	task := writePauseFixture(t, dir, "pause A")
	task.Files[0].BasePath = basePath
	task.Files[0].BaseSHA256 = digestOf(baseData)
	task.Generation = GenerationKey(task.Files)
	uploadFixture(t, store, task)

	counter := &countingReader{inner: store}
	dest := filepath.Join(t.TempDir(), task.SandboxID)
	got, err := FetchMatching(context.Background(), counter, store, task.SandboxID, anchorFor(task), dest, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Base != basePath {
		t.Fatalf("base = %s, want the host's %s", got.Base, basePath)
	}
	for object := range counter.reads {
		if strings.HasPrefix(object, "bases/") {
			t.Fatalf("downloaded %s although the host holds the base", object)
		}
	}
}
