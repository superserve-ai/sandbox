//go:build !linux

package backup

import (
	"fmt"
	"os"
	"path/filepath"
)

// openRootNoFollow on non-linux platforms approximates the atomic
// no-follow open with an Lstat through a Root on the parent followed by
// the confined OpenRoot. The check and the open are two operations, so a
// symlink swapped in between them is followed if its target stays inside
// the parent; os.Root confinement still prevents anchoring outside it.
// This is a weaker guarantee than linux, where the kernel rejects a
// symlink leaf in the open syscall itself; production hosts are linux.
// makeDirNoFollow on non-linux platforms is the portable creation: it
// resolves ancestors normally and can follow ancestor symlinks, a weaker
// guarantee than the linux no-symlink walk. Production hosts are linux.
func makeDirNoFollow(dir string) error {
	return makeDirPortable(dir)
}

func openRootNoFollow(parentPath, base string) (*os.Root, error) {
	parent, err := os.OpenRoot(parentPath)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	fi, err := parent.Lstat(base)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is a symlink or not a directory: restore only writes into a real directory", filepath.Join(parentPath, base))
	}
	return parent.OpenRoot(base)
}
