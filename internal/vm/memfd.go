package vm

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
)

// bridgeDirtyOffsetsName is the per-sandbox sidecar a memfd-bridge pause writes (the
// dirty page offsets vmd copies from the memfd). Removed when the flush completes; the
// orphan GC reclaims a stale one left by a crash mid-bridge.
const bridgeDirtyOffsetsName = "mem.dirty.offsets"

// guestMemLink is the /proc/<pid>/fd readlink target of Firecracker's MAP_SHARED guest-memory
// memfd for vmID. Firecracker names it "guest_mem-<instance id>" (the instance id is the vmID vmd
// passes as --id) and the kernel reports a memfd as "/memfd:<name> (deleted)". Matching the per-VM
// name — not a generic "guest_mem" — ties the capture to the intended VM: on a mis-resolved PID the
// names won't match, so capture fails and the caller falls back to the safe resume path rather than
// handing back another tenant's memory.
func guestMemLink(vmID string) string {
	return fmt.Sprintf("/memfd:guest_mem-%s (deleted)", vmID)
}

// captureGuestMemFd finds vmID's guest-memory memfd in a running Firecracker
// process and reopens it as a fd owned by vmd. Holding the returned file keeps
// the guest RAM resident after that Firecracker exits — a memfd's pages live as
// long as any fd references the inode — which is what lets a paused VM's frozen
// memory be handed to a fresh Firecracker for an immediate resume.
//
// The Firecracker must have been restored with shared_mem on (VMD_SHARED_MEM);
// otherwise its guest memory is an anonymous mapping with no memfd and this
// returns an error. O_RDONLY is sufficient: a new Firecracker copies pages out
// of this source via UFFDIO_COPY and never writes back to it.
func captureGuestMemFd(fcPID int, vmID string) (*os.File, error) {
	if fcPID <= 0 {
		return nil, fmt.Errorf("capture guest_mem fd: invalid pid %d", fcPID)
	}
	want := guestMemLink(vmID)
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
		if target != want {
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
	return nil, fmt.Errorf("capture guest_mem fd: no %s memfd in pid %d (shared_mem not enabled? wrong pid?)", want, fcPID)
}

// readDirtyOffsets parses the dirty-page-offsets sidecar Firecracker writes for a
// memfd-bridge pause: a sequence of little-endian u64 byte offsets (ascending). These
// are the exact pages a normal diff dump would have written.
func readDirtyOffsets(path string) ([]uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read dirty offsets: %w", err)
	}
	if len(data)%8 != 0 {
		return nil, fmt.Errorf("dirty offsets sidecar %q has truncated length %d", path, len(data))
	}
	offsets := make([]uint64, len(data)/8)
	for i := range offsets {
		offsets[i] = binary.LittleEndian.Uint64(data[i*8:])
	}
	return offsets, nil
}

// dumpMemfdPages copies the pages at `offsets` from the held guest-memory memfd into a
// fresh sparse diff layer at dstPath, producing the same overlay a Firecracker diff dump
// would have (only dirtied pages written; the rest left as holes that fall through to the
// base on restore). The layer is sized to the full memfd (guest RAM) so the offsets are
// valid and unwritten regions read as zero holes. Fsyncs before returning (the durability
// point is the caller's manifest commit, which follows).
func dumpMemfdPages(src *os.File, offsets []uint64, dstPath string, pageSize int) error {
	info, err := src.Stat()
	if err != nil {
		return fmt.Errorf("stat memfd: %w", err)
	}
	total := info.Size()

	dst, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("open diff layer: %w", err)
	}
	defer dst.Close()
	if err := dst.Truncate(total); err != nil {
		return fmt.Errorf("size diff layer: %w", err)
	}

	buf := make([]byte, pageSize)
	for _, off := range offsets {
		if int64(off)+int64(pageSize) > total {
			return fmt.Errorf("dirty offset %d + page exceeds guest RAM %d", off, total)
		}
		if _, err := src.ReadAt(buf, int64(off)); err != nil {
			return fmt.Errorf("read page at %d from memfd: %w", off, err)
		}
		if _, err := dst.WriteAt(buf, int64(off)); err != nil {
			return fmt.Errorf("write page at %d to diff layer: %w", off, err)
		}
	}
	if err := dst.Sync(); err != nil {
		return fmt.Errorf("fsync diff layer: %w", err)
	}
	return nil
}

// guestMemFdPath returns the path a freshly spawned Firecracker can use to
// reopen the memfd vmd holds: vmd's own /proc fd entry. Valid only while vmd
// keeps f open and the spawned process can read vmd's /proc (same user, no
// chroot — Firecracker runs un-jailed on the fleet).
func guestMemFdPath(f *os.File) string {
	return fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), int(f.Fd()))
}
