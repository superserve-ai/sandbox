//go:build linux

package backup

import (
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// Extents enumerates a file's data extents via SEEK_DATA/SEEK_HOLE. The
// fleet's disk overlays are heavily sparse (tens of MB of data inside
// multi-GiB apparent files), so uploads must move data extents only; naive
// full-file reads would ship two orders of magnitude more bytes than exist.
//
// Filesystems without hole tracking report one extent spanning the whole
// file, which degrades to a full-content upload, correct, just not compact.
func Extents(f *os.File) ([]Extent, int64, error) {
	fi, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	size := fi.Size()
	var extents []Extent
	var off int64
	for off < size {
		dataStart, err := unix.Seek(int(f.Fd()), off, unix.SEEK_DATA)
		if err != nil {
			// ENXIO: no more data past off, the rest is one hole.
			if errors.Is(err, unix.ENXIO) {
				break
			}
			return nil, 0, err
		}
		holeStart, err := unix.Seek(int(f.Fd()), dataStart, unix.SEEK_HOLE)
		if err != nil {
			return nil, 0, err
		}
		extents = append(extents, Extent{Offset: dataStart, Length: holeStart - dataStart})
		off = holeStart
	}
	return extents, size, nil
}

// packedReader streams a file's data extents back to back, skipping holes.
// The extent table travels in the generation manifest so restore can
// reconstruct the sparse file exactly (write each extent at its offset,
// truncate to apparent size).
type packedReader struct {
	f       *os.File
	extents []Extent
	idx     int
	pos     int64 // bytes consumed within extents[idx]
}

// NewPackedReader returns a reader over the data extents of f, in order.
// The caller keeps ownership of f and must not move its offset concurrently;
// reads use ReadAt and never touch the file position.
func NewPackedReader(f *os.File, extents []Extent) io.Reader {
	return &packedReader{f: f, extents: extents}
}

func (r *packedReader) Read(p []byte) (int, error) {
	for r.idx < len(r.extents) {
		ext := r.extents[r.idx]
		remain := ext.Length - r.pos
		if remain <= 0 {
			r.idx++
			r.pos = 0
			continue
		}
		if int64(len(p)) > remain {
			p = p[:remain]
		}
		n, err := r.f.ReadAt(p, ext.Offset+r.pos)
		r.pos += int64(n)
		if err == io.EOF {
			if r.pos == ext.Length {
				err = nil
			} else {
				// The file shrank under us (a newer pause rewrote it).
				// io.EOF here would let io.Copy treat the short stream as
				// success and finalize a truncated object; surface it as a
				// real error instead.
				err = ErrTruncatedSource
			}
		}
		return n, err
	}
	return 0, io.EOF
}
