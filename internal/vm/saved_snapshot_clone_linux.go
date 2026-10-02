//go:build linux

package vm

import (
	"os"

	"golang.org/x/sys/unix"
)

// cloneFileFD reflinks src into dst (FICLONE). Filesystems without reflink
// return an error and the caller copies instead.
func cloneFileFD(dst, src *os.File) error {
	return unix.IoctlFileClone(int(dst.Fd()), int(src.Fd()))
}
