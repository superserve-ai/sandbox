//go:build linux

package backup

import (
	"os"

	"golang.org/x/sys/unix"
)

// dropPageCache asks the kernel to drop f's cached pages. For a file the
// pipeline reads once and never again, keeping them cached only evicts pages
// something else still needs. Dirty pages are left alone, so callers that
// wrote the file fsync it first. Best-effort: a failure changes nothing.
func dropPageCache(f *os.File) error {
	return unix.Fadvise(int(f.Fd()), 0, 0, unix.FADV_DONTNEED)
}
