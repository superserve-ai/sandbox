//go:build linux

package backup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestOpenRootNoFollowRejectsSymlinkAncestor pins the openat2 path: with
// RESOLVE_NO_SYMLINKS the kernel refuses a symlink in ANY component, so a
// symlinked ancestor of the destination cannot redirect the restore. The
// fallback path deliberately lacks this (leaf-only protection), so the
// test skips where openat2 is unavailable.
func TestOpenRootNoFollowRejectsSymlinkAncestor(t *testing.T) {
	probe := &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS,
	}
	if fd, err := unix.Openat2(unix.AT_FDCWD, "/", probe); err != nil {
		t.Skipf("openat2 unavailable, only the leaf guarantee applies: %v", err)
	} else {
		unix.Close(fd)
	}

	real := filepath.Join(t.TempDir(), "real")
	if err := os.MkdirAll(filepath.Join(real, "dest"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	root, err := openRootNoFollow(link, "dest")
	if err == nil {
		root.Close()
		t.Fatal("openRootNoFollow followed a symlink ancestor")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("err = %v, want symlink component rejection", err)
	}
	// The real path still opens.
	root, err = openRootNoFollow(real, "dest")
	if err != nil {
		t.Fatalf("real ancestor rejected: %v", err)
	}
	root.Close()
}

// TestMakeDirNoFollowRejectsSymlinkAncestor pins the creation side: a
// missing destination leaf under a symlinked ancestor must fail WITHOUT
// creating anything at the symlink target, where Mkdir/MkdirAll would
// have created it before the protected open ever ran.
func TestMakeDirNoFollowRejectsSymlinkAncestor(t *testing.T) {
	probe := &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS,
	}
	if fd, err := unix.Openat2(unix.AT_FDCWD, "/", probe); err != nil {
		t.Skipf("openat2 unavailable, only portable creation applies: %v", err)
	} else {
		unix.Close(fd)
	}

	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(link, "newdir")
	if err := makeDirNoFollow(dest); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("err = %v, want symlink component rejection", err)
	}
	entries, err := os.ReadDir(real)
	if err != nil || len(entries) != 0 {
		t.Fatalf("directory created at the symlink target: %d entries err=%v", len(entries), err)
	}
	// End to end: openFreshDir on the same path also refuses and creates
	// nothing.
	if _, err := openFreshDir(dest); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("openFreshDir err = %v, want symlink rejection", err)
	}
	entries, err = os.ReadDir(real)
	if err != nil || len(entries) != 0 {
		t.Fatalf("openFreshDir created at the symlink target: %d entries err=%v", len(entries), err)
	}
	// Deep creation through real components still works and the leaf
	// opens through the pinned path.
	deep := filepath.Join(real, "a", "b", "c")
	if err := makeDirNoFollow(deep); err != nil {
		t.Fatalf("deep creation: %v", err)
	}
	root, err := openRootNoFollow(filepath.Dir(deep), "c")
	if err != nil {
		t.Fatalf("open created leaf: %v", err)
	}
	root.Close()
}
