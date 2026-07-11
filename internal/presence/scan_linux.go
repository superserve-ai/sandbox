//go:build linux

package presence

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// Scan derives a presence bitmap from memPath's allocated extents
// via SEEK_DATA/SEEK_HOLE: a written extent is a page the overlay provides, a
// hole falls through to the base. This is the same inference Firecracker's
// legacy restore fallback performs, so it is sound under the same conditions
// only: the file's extents must be the ones its dump wrote — i.e. the overlay
// has never been transferred — and the filesystem's allocation unit must not
// exceed the page size (a coarser unit over-reports clean pages as present,
// which a restore would serve as zeros instead of base content).
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
	npages := uint64((size + int64(pageSize) - 1) / int64(pageSize))
	p := Bitmap{
		PageSize: uint64(pageSize),
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
			if errors.Is(err, unix.ENXIO) || errors.Is(err, io.EOF) {
				hole = size
			} else {
				return Bitmap{}, fmt.Errorf("seek hole %s: %w", memPath, err)
			}
		}
		for pg := uint64(data) / uint64(pageSize); pg < (uint64(hole)+uint64(pageSize)-1)/uint64(pageSize) && pg < npages; pg++ {
			p.Bits[pg>>6] |= 1 << (pg & 63)
		}
		off = hole
	}
	return p, nil
}

// Generate builds `<memPath>.presence` from the overlay's own
// extents and writes it atomically. ONLY sound for a quiesced overlay that
// has never left the host it was dumped on — generating from a transferred
// file's extents would launder exactly the corruption the side-car exists to
// prevent, which is why the convergence sweep runs pre-marker only and never
// touches an overlay that already has a side-car (including the torn-save
// and un-layerable sentinels, whose loud refusal must be preserved).
func Generate(memPath string) error {
	pageSize := os.Getpagesize()
	p, err := Scan(memPath, pageSize)
	if err != nil {
		return err
	}
	return Write(memPath, p.PageSize, p.NPages, p.Bits)
}
