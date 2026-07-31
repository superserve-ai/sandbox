//go:build !linux

package backup

import (
	"io"
	"os"
)

// Extents on non-linux platforms reports the whole file as one extent:
// correct, never compact. Production hosts are linux; this exists so the
// package builds everywhere.
func Extents(f *os.File) ([]Extent, int64, error) {
	fi, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	if fi.Size() == 0 {
		return nil, 0, nil
	}
	return []Extent{{Offset: 0, Length: fi.Size()}}, fi.Size(), nil
}

// NewPackedReader on non-linux platforms reads the extents via ReadAt like
// the linux implementation; with the single-extent table above it is a plain
// sequential read.
func NewPackedReader(f *os.File, extents []Extent) io.Reader {
	if len(extents) == 0 {
		return emptyReader{}
	}
	return io.NewSectionReader(f, extents[0].Offset, extents[0].Length)
}

type emptyReader struct{}

func (emptyReader) Read([]byte) (int, error) { return 0, io.EOF }
