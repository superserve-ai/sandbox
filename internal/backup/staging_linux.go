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

// cloneRange reflinks length bytes at srcOff of src into dst at dstOff
// (FICLONERANGE). Same failure contract as cloneFile.
func cloneRange(dst, src *os.File, srcOff, length, dstOff int64) error {
	return unix.IoctlFileCloneRange(int(dst.Fd()), &unix.FileCloneRange{
		Src_fd: int64(src.Fd()), Src_offset: uint64(srcOff), Src_length: uint64(length), Dest_offset: uint64(dstOff),
	})
}
