//go:build linux

package backup

import (
	"os"

	"golang.org/x/sys/unix"
)

// cloneFile reflinks src into dst (FICLONE): an immutable snapshot that
// costs no data copy. Filesystems without reflink return an error and
// the caller falls back to a sparse copy.
// cloneSupported gates the per-filesystem clone probe; whether a given
// filesystem honours the ioctl is still learned by probing.
const cloneSupported = true

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

// deviceOf returns the filesystem device id of f, for caching per-filesystem
// answers such as reflink support.
func deviceOf(f *os.File) (uint64, bool) {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return 0, false
	}
	return uint64(st.Dev), true
}
