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

	base := filepath.Join(dir, "base.ext4")
	if err := os.WriteFile(base, []byte("basedata"), 0o644); err != nil {
		t.Fatal(err)
	}
	entries := collectPauseManifest(context.Background(), vmstate, rootfs, base, zerolog.Nop())
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
	if !ok || rf.Path != rootfs || rf.SizeBytes != 8 || rf.BasePath != base || rf.BaseSHA256 == "" {
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

// The disk entry must carry the base image's content digest: the base's
// identity is its bytes, and a base rebuilt in place (same path, new
// contents) must surface as a different dependency.
func TestCollectPauseManifestBindsBaseContents(t *testing.T) {
	dir := t.TempDir()
	snap := filepath.Join(dir, "vmstate.snap")
	disk := filepath.Join(dir, "overlay.ext4")
	base := filepath.Join(dir, "base.ext4")
	for p, data := range map[string]string{snap: "vm state", disk: "overlay", base: "base v1"} {
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	first := collectPauseManifest(context.Background(), snap, disk, base, zerolog.Nop())
	var firstBase string
	for _, e := range first {
		if e.FileName == "rootfs.ext4" {
			if e.BasePath != base || e.BaseSHA256 == "" {
				t.Fatalf("disk entry = %+v, want base path and content digest", e)
			}
			firstBase = e.BaseSHA256
		}
	}
	if firstBase == "" {
		t.Fatal("no disk entry in manifest")
	}

	// Rebuild the base in place; ensure the mtime moves even on coarse
	// filesystem clocks.
	if err := os.WriteFile(base, []byte("base v2 bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(base, later, later); err != nil {
		t.Fatal(err)
	}
	second := collectPauseManifest(context.Background(), snap, disk, base, zerolog.Nop())
	for _, e := range second {
		if e.FileName == "rootfs.ext4" && e.BaseSHA256 == firstBase {
			t.Fatal("rebuilt base kept the old content digest (stale cache)")
		}
	}
}

// A caller joining (or starting) a base hash must honor its own budget:
// an exhausted context returns promptly instead of riding the flight's
// longer budget past the pause RPC deadline.
func TestBaseDigestHonorsCallerContext(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.ext4")
	if err := os.WriteFile(base, []byte("base"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if _, err := baseDigest(ctx, base); err == nil {
		// A cache hit from an earlier test sharing the same identity is
		// impossible: the path is unique per t.TempDir.
		t.Fatal("baseDigest succeeded under a canceled context")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("baseDigest blocked %v under a canceled context", elapsed)
	}
}

// The hashing budget follows the caller's deadline in both directions:
// a rehash context with ten minutes gets ten minutes (minus margin), not
// the 60-second default cap.
func TestHashBudgetFollowsCallerDeadline(t *testing.T) {
	if b, ok := hashBudget(context.Background()); !ok || b != hashBudgetCap {
		t.Fatalf("no-deadline budget = %v/%v, want cap", b, ok)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	b, ok := hashBudget(ctx)
	if !ok || b <= hashBudgetCap {
		t.Fatalf("long-deadline budget = %v/%v, want more than the default cap", b, ok)
	}
	short, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if _, ok := hashBudget(short); ok {
		t.Fatal("sub-margin deadline should yield no budget")
	}
}

// A base rewritten in place with its mtime restored (same inode, same
// size) must still miss the digest cache: ctime cannot be forged from
// userspace, so the identity sees the rewrite.
func TestBaseDigestDetectsTimestampPreservingRewrite(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.ext4")
	if err := os.WriteFile(base, []byte("basebytesv1"), 0o644); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(base)
	if err != nil {
		t.Fatal(err)
	}
	v1, err := baseDigest(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}

	// Kernel inode timestamps come from the coarse clock (jiffy
	// granularity), so a rewrite in the same tick would share the ctime;
	// real timestamp-preserving copies are never that fast.
	time.Sleep(50 * time.Millisecond)
	// Same length, different bytes, mtime restored.
	if err := os.WriteFile(base, []byte("basebytesv2"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(base, fi.ModTime(), fi.ModTime()); err != nil {
		t.Fatal(err)
	}
	v2, err := baseDigest(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}
	if v1 == v2 {
		t.Fatal("timestamp-preserving rewrite served the stale cached digest")
	}
}
