//go:build linux

package backup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

// openRootNoFollow opens base under parentPath as an os.Root without ever
// following a symlink at the leaf. The kernel enforces it atomically:
// openat with O_NOFOLLOW|O_DIRECTORY rejects a symlink (ELOOP) in the
// same syscall that opens the directory, so there is no window between a
// check and the open for a swap to slip through. The os.Root is then
// bound to the already-open descriptor via /proc/self/fd, which the
// kernel resolves to the open file description itself, not a fresh path
// lookup that could race.
func openRootNoFollow(parentPath, base string) (*os.Root, error) {
	pfd, err := unix.Open(parentPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: parentPath, Err: err}
	}
	defer unix.Close(pfd)
	fd, err := unix.Openat(pfd, base, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
			return nil, fmt.Errorf("%s is a symlink or not a directory: restore only writes into a real directory", filepath.Join(parentPath, base))
		}
		return nil, &os.PathError{Op: "openat", Path: filepath.Join(parentPath, base), Err: err}
	}
	// fd stays open until OpenRoot returns so the /proc entry cannot dangle.
	defer unix.Close(fd)
	root, err := os.OpenRoot("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil {
		return nil, fmt.Errorf("bind root to %s: %w", filepath.Join(parentPath, base), err)
	}
	return root, nil
}
