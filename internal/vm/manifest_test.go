package vm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestHashFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blob")
	content := []byte("the quick brown fox jumps over the lazy dog")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}

	sum, size, err := hashFile(context.Background(), path)
	if err != nil {
		t.Fatalf("hashFile: %v", err)
	}
	if size != int64(len(content)) {
		t.Errorf("size = %d, want %d", size, len(content))
	}
	want := sha256.Sum256(content)
	if sum != hex.EncodeToString(want[:]) {
		t.Errorf("sha256 = %s, want %s", sum, hex.EncodeToString(want[:]))
	}

	if _, _, err := hashFile(context.Background(), filepath.Join(dir, "missing")); err == nil {
		t.Error("hashFile on a missing file should error")
	}
}

func TestCollectPauseManifest(t *testing.T) {
	dir := t.TempDir()
	vmstate := filepath.Join(dir, "vmstate.snap")
	rootfs := filepath.Join(dir, "rootfs.ext4")
	if err := os.WriteFile(vmstate, []byte("state"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootfs, []byte("diskdata"), 0o644); err != nil {
		t.Fatal(err)
	}

	entries := collectPauseManifest(context.Background(), vmstate, rootfs, "/base/base.ext4", zerolog.Nop())
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(entries))
	}
	byName := map[string]ManifestEntry{}
	for _, e := range entries {
		byName[e.FileName] = e
	}
	vs, ok := byName["vmstate.snap"]
	if !ok || vs.Path != vmstate || vs.SizeBytes != 5 || vs.BasePath != "" {
		t.Errorf("vmstate entry wrong: %+v", vs)
	}
	rf, ok := byName["rootfs.ext4"]
	if !ok || rf.Path != rootfs || rf.SizeBytes != 8 || rf.BasePath != "/base/base.ext4" {
		t.Errorf("rootfs entry wrong: %+v", rf)
	}
	if rf.SHA256 == "" || len(rf.SHA256) != 64 {
		t.Errorf("rootfs sha256 malformed: %q", rf.SHA256)
	}
}

func TestCollectPauseManifestDegradesOnMissingFiles(t *testing.T) {
	dir := t.TempDir()
	vmstate := filepath.Join(dir, "vmstate.snap")
	if err := os.WriteFile(vmstate, []byte("state"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Missing disk file: manifest degrades to the surviving entry rather
	// than failing the pause.
	entries := collectPauseManifest(context.Background(), vmstate, filepath.Join(dir, "gone.ext4"), "", zerolog.Nop())
	if len(entries) != 1 || entries[0].FileName != "vmstate.snap" {
		t.Fatalf("expected only vmstate entry, got %+v", entries)
	}

	// Empty disk path (no disk recorded on the instance): same degradation.
	entries = collectPauseManifest(context.Background(), vmstate, "", "", zerolog.Nop())
	if len(entries) != 1 {
		t.Fatalf("expected only vmstate entry, got %+v", entries)
	}
}

func TestCollectPauseManifestSkipsWithoutBudget(t *testing.T) {
	dir := t.TempDir()
	vmstate := filepath.Join(dir, "vmstate.snap")
	if err := os.WriteFile(vmstate, []byte("state"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Deadline already inside the safety margin: hashing must be skipped
	// entirely, not stretched past the RPC deadline.
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Second))
	defer cancel()
	if entries := collectPauseManifest(ctx, vmstate, "", "", zerolog.Nop()); entries != nil {
		t.Fatalf("expected nil manifest with no budget, got %+v", entries)
	}
}
