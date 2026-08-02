//go:build linux

package backup

import (
	"os"

	"golang.org/x/sys/unix"
)

// cloneFile reflinks src into dst (FICLONE): an immutable snapshot that
// costs no data copy. Filesystems without reflink return an error and
// the caller falls back to a sparse copy.
func cloneFile(dst, src *os.File) error {
	return unix.IoctlFileClone(int(dst.Fd()), int(src.Fd()))
}
