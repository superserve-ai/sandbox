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
