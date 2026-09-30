package backup

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The staging tree defaults onto the snapshot filesystem, and the
// retired OS-disk default is reported for removal unless it is the
// configured root itself.
func TestResolveStagingRoot(t *testing.T) {
	root, legacy := ResolveStagingRoot("", "/data/snapshots", "/var/lib/sandbox/rundir")
	if root != "/data/snapshots/.backup-staging" || legacy != "/var/lib/sandbox/backup-staging" {
		t.Fatalf("default = %q legacy %q", root, legacy)
	}
	root, legacy = ResolveStagingRoot("/elsewhere/staging", "/data/snapshots", "/var/lib/sandbox/rundir")
	if root != "/elsewhere/staging" || legacy != "/var/lib/sandbox/backup-staging" {
		t.Fatalf("override = %q legacy %q", root, legacy)
	}
	root, legacy = ResolveStagingRoot("/var/lib/sandbox/backup-staging", "/data/snapshots", "/var/lib/sandbox/rundir")
	if legacy != "" {
		t.Fatalf("legacy = %q, want suppressed when it is the configured root", legacy)
	}
	// Aliased and contained spellings must suppress too: treating the
	// configured root's own tree as retired would drain live staging.
	for _, override := range []string{
		"/var/lib/sandbox/backup-staging/",
		"/var/lib/sandbox/backup-staging/sub",
		"/var/lib/sandbox",
	} {
		if _, legacy := ResolveStagingRoot(override, "/data/snapshots", "/var/lib/sandbox/rundir"); legacy != "" {
			t.Fatalf("override %q: legacy = %q, want suppressed", override, legacy)
		}
	}
}

// A BACKUP_STAGING_DIR change between an ancestor and descendant path
// (or the same directory under an aliased spelling) is not a
// retirement: the "old" and "new" roots share a live subtree, and
// treating either as retired would let the background sweep walk
// referenced entries through the other's tree and delete them as
// apparent orphans.
func TestStagingRootsOverlap(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"/mnt/disk/staging", "/mnt/disk/staging", true},
		{"/mnt/disk/staging/", "/mnt/disk/staging", true},
		{"/mnt/disk/staging", "/mnt/disk/staging/sub", true},
		{"/mnt/disk/staging/sub", "/mnt/disk/staging", true},
		{"/mnt/disk/staging", "/mnt/other/staging", false},
		{"/mnt/disk/staging-2", "/mnt/disk/staging", false}, // shares a prefix, not a path component
		{"", "/mnt/disk/staging", false},
		{"/mnt/disk/staging", "", false},
	}
	for _, c := range cases {
		if got := StagingRootsOverlap(c.a, c.b); got != c.want {
			t.Errorf("StagingRootsOverlap(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// smallLimit shrinks the copy budget for one test so a fixture of a few
// kilobytes can exceed it.
func smallLimit(t *testing.T, n int64) {
	t.Helper()
	prev := inlineStageLimit
	inlineStageLimit = n
	t.Cleanup(func() { inlineStageLimit = prev })
}

// stubClone points the staging clone at fn for one test.
func stubClone(t *testing.T, fn func(dst, src *os.File) error) {
	t.Helper()
	prev := cloneInto
	cloneInto = fn
	t.Cleanup(func() { cloneInto = prev })
}

func copyClone(dst, src *os.File) error {
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return err
	}
	_, err := io.Copy(dst, src)
	return err
}

func noClone(*os.File, *os.File) error { return errors.New("no reflink here") }

func writeDisk(t *testing.T, dir, name string, n int) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, bytes.Repeat([]byte{0xAB}, n), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The copy budget bounds bytes copied, so an overlay past it must still
// stage where the filesystem can reflink. Charging a clone for bytes it
// never moves sends the pause to the marker-only worker, which requires
// the sandbox to still be at rest.
func TestStagePendingClonesPastTheCopyBudget(t *testing.T) {
	dir := t.TempDir()
	disk := writeDisk(t, dir, "rootfs.ext4", 8192)
	smallLimit(t, 4096)

	stubClone(t, copyClone)
	staged, paths, err := StagePending(context.Background(), t.TempDir(), "sb", "tok", "", map[string]string{"rootfs.ext4": disk})
	if err != nil {
		t.Fatalf("a clonable overlay past the budget was refused: %v", err)
	}
	if staged == "" || paths["rootfs.ext4"] == "" {
		t.Fatalf("staged = %q paths = %v", staged, paths)
	}
	if got, err := os.ReadFile(paths["rootfs.ext4"]); err != nil || len(got) != 8192 {
		t.Fatalf("staged disk = %d bytes, %v", len(got), err)
	}
}

// Without reflink the same overlay costs real bytes on the pause RPC
// path, so the budget still refuses it and leaves nothing behind.
func TestStagePendingBoundsTheCopyFallback(t *testing.T) {
	dir := t.TempDir()
	disk := writeDisk(t, dir, "rootfs.ext4", 8192)
	smallLimit(t, 4096)
	root := t.TempDir()

	stubClone(t, noClone)
	if _, _, err := StagePending(context.Background(), root, "sb", "tok", "", map[string]string{"rootfs.ext4": disk}); !errors.Is(err, ErrStageTooLarge) {
		t.Fatalf("err = %v, want ErrStageTooLarge once copying costs real bytes", err)
	}
	if _, err := os.Stat(filepath.Join(root, "sb", "pending-tok")); !os.IsNotExist(err) {
		t.Fatal("a refused stage left its pending directory behind")
	}
}

// A pause small enough to copy still stages without reflink.
func TestStagePendingCopiesWithinTheBudget(t *testing.T) {
	dir := t.TempDir()
	disk := writeDisk(t, dir, "rootfs.ext4", 4096)
	smallLimit(t, 8192)

	stubClone(t, noClone)
	_, paths, err := StagePending(context.Background(), t.TempDir(), "sb", "tok", "", map[string]string{"rootfs.ext4": disk})
	if err != nil {
		t.Fatalf("small pause refused: %v", err)
	}
	if got, err := os.ReadFile(paths["rootfs.ext4"]); err != nil || !bytes.Equal(got, bytes.Repeat([]byte{0xAB}, 4096)) {
		t.Fatalf("staged copy differs: %d bytes, %v", len(got), err)
	}
}

// Only the artifact that actually needs copying is charged: a sibling
// already cloned must not be discarded because another file is dense.
func TestStagePendingChargesOnlyTheArtifactItCopies(t *testing.T) {
	dir := t.TempDir()
	disk := writeDisk(t, dir, "rootfs.ext4", 8192)
	state := writeDisk(t, dir, "vmstate.snap", 128)
	smallLimit(t, 4096)

	// The disk clones; only the small vmstate falls back to a copy.
	stubClone(t, func(dst, src *os.File) error {
		if fi, err := src.Stat(); err == nil && fi.Size() == 128 {
			return errors.New("no reflink for this one")
		}
		return copyClone(dst, src)
	})
	_, paths, err := StagePending(context.Background(), t.TempDir(), "sb", "tok", "",
		map[string]string{"rootfs.ext4": disk, "vmstate.snap": state})
	if err != nil {
		t.Fatalf("a cloned disk was charged for a sibling's copy: %v", err)
	}
	if paths["rootfs.ext4"] == "" || paths["vmstate.snap"] == "" {
		t.Fatalf("paths = %v", paths)
	}
}

// A clone that outlives the pause RPC's deadline releases the caller to the
// marker-only worker instead of holding the VM operation lock, and starts no
// byte copy with even less time left.
func TestStagePendingAbandonsAClonePastTheDeadline(t *testing.T) {
	dir := t.TempDir()
	disk := writeDisk(t, dir, "rootfs.ext4", 4096)
	root := t.TempDir()

	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	stubClone(t, func(dst, src *os.File) error {
		<-release
		return errors.New("abandoned")
	})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	if _, _, err := StagePending(ctx, root, "sb", "tok", "", map[string]string{"rootfs.ext4": disk}); !errors.Is(err, ErrStageTooLarge) {
		t.Fatalf("err = %v, want the marker-only fallback", err)
	}
}

// The reflink ioctl cannot be interrupted, so a stalled one must release
// its caller rather than hold a pause or a restore past its deadline.
func TestSnapshotFileReleasesTheCallerWhenTheCloneStalls(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	stubClone(t, func(dst, src *os.File) error {
		entered <- struct{}{}
		<-release
		return nil
	})
	t.Cleanup(func() { close(release) })

	dir := t.TempDir()
	src := writeDisk(t, dir, "rootfs.ext4", 1<<20)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := snapshotFileMode(ctx, filepath.Join(dir, "staged.ext4"), src, stageAuto)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want the cancellation reported", err)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the clone was never attempted")
	}
	if _, err := os.Stat(filepath.Join(dir, "staged.ext4")); err == nil {
		t.Fatal("a cancelled clone published its destination")
	}
}
