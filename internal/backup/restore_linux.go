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

// openRootNoFollow opens parentPath/base as an os.Root without following
// a symlink anywhere in the path.
//
// The strong path is openat2 with RESOLVE_NO_SYMLINKS: the kernel refuses
// a symlink in EVERY component of the path, atomically within the open
// syscall, so neither the leaf nor an ancestor swapped for a symlink
// between the caller's checks and this open can redirect the restore.
// The os.Root is then bound to the already-open descriptor via
// /proc/self/fd, which resolves to the open file description itself, not
// a fresh path lookup.
//
// On kernels without openat2 (pre-5.6, ENOSYS) or seccomp policies that
// deny it (older container runtimes report EPERM for filtered syscalls),
// the fallback pins the parent with a plain directory open and rejects a
// symlink leaf via openat O_NOFOLLOW. That protects the leaf atomically
// but follows symlinks in ancestor components, a weaker guarantee;
// production hosts run modern kernels, so the strong path is the
// production path.
// openat2NoSymlinks opens path as a directory, refusing symlinks in every
// component, atomically in the kernel. EINTR is retried.
func openat2NoSymlinks(path string) (int, error) {
	how := &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS,
	}
	for {
		fd, err := unix.Openat2(unix.AT_FDCWD, path, how)
		if err != unix.EINTR { //nolint:errorlint // raw errno from the syscall
			return fd, err
		}
	}
}

// makeDirNoFollow creates dir and any missing parents without following a
// symlink in any component. The deepest existing ancestor is resolved
// with one openat2(RESOLVE_NO_SYMLINKS) call, then each missing component
// is created and entered fd-relative with Mkdirat plus openat O_NOFOLLOW,
// holding the directory fd across each hop so no component can be swapped
// mid-walk. Mkdir or MkdirAll here instead would resolve ancestors
// normally and create the destination at a symlink target.
//
// Kernels without openat2 (and seccomp policies that filter it) fall back
// to portable creation with its documented weaker guarantee, matching the
// open-side fallback.
func makeDirNoFollow(dir string) error {
	dir = filepath.Clean(dir)
	var missing []string
	anc := dir
	var fd int
	for {
		f, err := openat2NoSymlinks(anc)
		if err == nil {
			fd = f
			break
		}
		switch {
		case errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR):
			return fmt.Errorf("%s contains a symlink or non-directory component: restore only writes through real directories", anc)
		case errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EPERM):
			return makeDirPortable(dir)
		case !errors.Is(err, unix.ENOENT):
			return &os.PathError{Op: "openat2", Path: anc, Err: err}
		}
		parent := filepath.Dir(anc)
		if parent == anc {
			return &os.PathError{Op: "openat2", Path: anc, Err: err}
		}
		missing = append([]string{filepath.Base(anc)}, missing...)
		anc = parent
	}
	defer func() { unix.Close(fd) }()
	for _, comp := range missing {
		// EEXIST is tolerated (a concurrent restore may have made the same
		// component); the O_NOFOLLOW open then decides whether whatever is
		// there is a real directory.
		if err := unix.Mkdirat(fd, comp, 0o755); err != nil && !errors.Is(err, unix.EEXIST) {
			return &os.PathError{Op: "mkdirat", Path: comp, Err: err}
		}
		nfd, err := unix.Openat(fd, comp, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
				return fmt.Errorf("%s is a symlink or not a directory: restore only writes through real directories", comp)
			}
			return &os.PathError{Op: "openat", Path: comp, Err: err}
		}
		unix.Close(fd)
		fd = nfd
	}
	return nil
}

func openRootNoFollow(parentPath, base string) (*os.Root, error) {
	dir := filepath.Join(parentPath, base)
	fd, err := openat2NoSymlinks(dir)
	switch {
	case err == nil:
		// fd stays open until OpenRoot returns so the /proc entry cannot
		// dangle.
		defer unix.Close(fd)
		root, rerr := os.OpenRoot("/proc/self/fd/" + strconv.Itoa(fd))
		if rerr != nil {
			return nil, fmt.Errorf("bind root to %s: %w", dir, rerr)
		}
		return root, nil
	case errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR):
		return nil, fmt.Errorf("%s contains a symlink or non-directory component: restore only writes through real directories", dir)
	case errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EPERM):
		return openRootNoFollowFallback(parentPath, base)
	default:
		return nil, &os.PathError{Op: "openat2", Path: dir, Err: err}
	}
}

// openRootNoFollowFallback is the pre-openat2 path: parent pinned by a
// plain directory open, leaf opened openat O_NOFOLLOW so a symlink leaf
// is rejected atomically. Ancestor components of parentPath are resolved
// normally and CAN follow symlinks; see openRootNoFollow for why this
// weaker guarantee is acceptable only as a fallback.
func openRootNoFollowFallback(parentPath, base string) (*os.Root, error) {
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
