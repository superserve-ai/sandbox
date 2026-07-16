//go:build linux

package presence

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// ErrSidecarExists reports that WriteIfAbsent found a side-car already in
// place. For the convergence sweep this means the authoritative writer
// (Firecracker, at snapshot save) got there first — the sweep's scanned
// bitmap is the stale one and must be discarded, never the reverse.
var ErrSidecarExists = errors.New("presence side-car already exists")

// Scan derives a presence bitmap from memPath's allocated extents via
// SEEK_DATA/SEEK_HOLE: a written extent is a page the overlay provides, a
// hole falls through to the base. This is the same inference Firecracker's
// legacy restore fallback performs, so it is sound under the same conditions
// only: the file's extents must be the ones its dump wrote — i.e. the overlay
// has never been transferred — and the filesystem's allocation unit must not
// exceed the page size (a coarser unit over-reports clean pages as present,
// which a restore would serve as zeros instead of base content).
//
// Any unexpected seek error aborts the scan — including ENXIO from SEEK_HOLE,
// which on Linux can only mean the file shrank mid-scan (an implicit hole
// exists at EOF otherwise): a concurrent rewrite whose bitmap must not be
// trusted.
func Scan(memPath string, pageSize int) (Bitmap, error) {
	f, err := os.Open(memPath)
	if err != nil {
		return Bitmap{}, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return Bitmap{}, err
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && int64(sys.Blksize) > int64(pageSize) {
		return Bitmap{}, fmt.Errorf(
			"%s: filesystem allocation unit %d exceeds page size %d; extent scan would over-report presence",
			memPath, sys.Blksize, pageSize)
	}
	size := st.Size()
	ps := uint64(pageSize)
	npages := (uint64(size) + ps - 1) / ps
	p := Bitmap{
		PageSize: ps,
		NPages:   npages,
		Bits:     make([]uint64, (npages+63)/64),
	}
	var off int64
	for off < size {
		data, err := unix.Seek(int(f.Fd()), off, unix.SEEK_DATA)
		if err != nil {
			if errors.Is(err, unix.ENXIO) {
				break // no data at or after off — rest of the file is a hole
			}
			return Bitmap{}, fmt.Errorf("seek data %s: %w", memPath, err)
		}
		hole, err := unix.Seek(int(f.Fd()), data, unix.SEEK_HOLE)
		if err != nil {
			return Bitmap{}, fmt.Errorf("seek hole %s: %w", memPath, err)
		}
		end := min((uint64(hole)+ps-1)/ps, npages)
		for pg := uint64(data) / ps; pg < end; pg++ {
			p.Bits[pg>>6] |= 1 << (pg & 63)
		}
		off = hole
	}
	return p, nil
}

// WriteIfAbsent writes `<memPath>.presence` like Write, but refuses to
// replace an existing side-car: the rename uses RENAME_NOREPLACE, so if the
// authoritative writer (Firecracker, during a concurrent pause) created one
// between the caller's scan and this write, the stale scanned bitmap loses
// and ErrSidecarExists is returned. The reverse interleaving is benign —
// Firecracker's own writer truncates the destination in place, so a side-car
// this function placed is simply overwritten by the authoritative one.
func WriteIfAbsent(memPath string, pageSize, npages uint64, bits []uint64) error {
	dst := SidecarPath(memPath)
	tmp, err := writeSidecarTemp(dst, pageSize, npages, bits)
	if err != nil {
		return err
	}
	if err := unix.Renameat2(unix.AT_FDCWD, tmp, unix.AT_FDCWD, dst, unix.RENAME_NOREPLACE); err != nil {
		os.Remove(tmp)
		if errors.Is(err, unix.EEXIST) {
			return ErrSidecarExists
		}
		return fmt.Errorf("rename %s: %w", dst, err)
	}
	return syncDir(dst)
}
