package vm

import (
	"fmt"
	"os"
	"path/filepath"
)

// guestMemLink is the /proc/<pid>/fd readlink target of Firecracker's
// MAP_SHARED guest-memory memfd (created as memfd_create("guest_mem", ...) when
// shared_mem is set). The kernel reports a memfd as "/memfd:<name> (deleted)".
const guestMemLink = "/memfd:guest_mem (deleted)"

// captureGuestMemFd finds the guest-memory memfd of a running Firecracker
// process and reopens it as a fd owned by vmd. Holding the returned file keeps
// the guest RAM resident after that Firecracker exits — a memfd's pages live as
// long as any fd references the inode — which is what lets a paused VM's frozen
// memory be handed to a fresh Firecracker for an immediate resume.
//
// The Firecracker must have been restored with shared_mem on (VMD_SHARED_MEM);
// otherwise its guest memory is an anonymous mapping with no memfd and this
// returns an error. O_RDONLY is sufficient: a new Firecracker copies pages out
// of this source via UFFDIO_COPY and never writes back to it.
func captureGuestMemFd(fcPID int) (*os.File, error) {
	if fcPID <= 0 {
		return nil, fmt.Errorf("capture guest_mem fd: invalid pid %d", fcPID)
	}
	fdDir := fmt.Sprintf("/proc/%d/fd", fcPID)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil, fmt.Errorf("capture guest_mem fd: read %s: %w", fdDir, err)
	}
	for _, e := range entries {
		link := filepath.Join(fdDir, e.Name())
		target, err := os.Readlink(link)
		if err != nil {
			continue // fd closed between ReadDir and Readlink
		}
		if target != guestMemLink {
			continue
		}
		// Reopen through the magic symlink: yields a new fd to the SAME memfd
		// inode (same pages), independent of Firecracker's fd.
		f, err := os.OpenFile(link, os.O_RDONLY, 0)
		if err != nil {
			return nil, fmt.Errorf("capture guest_mem fd: reopen %s: %w", link, err)
		}
		return f, nil
	}
	return nil, fmt.Errorf("capture guest_mem fd: no guest_mem memfd in pid %d (shared_mem not enabled?)", fcPID)
}

// guestMemFdPath returns the path a freshly spawned Firecracker can use to
// reopen the memfd vmd holds: vmd's own /proc fd entry. Valid only while vmd
// keeps f open and the spawned process can read vmd's /proc (same user, no
// chroot — Firecracker runs un-jailed on the fleet).
func guestMemFdPath(f *os.File) string {
	return fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), int(f.Fd()))
}
