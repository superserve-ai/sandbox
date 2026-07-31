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

// NewPackedReader streams the given extents in order via section readers,
// honoring arbitrary extent tables so behavior matches linux exactly.
func NewPackedReader(f *os.File, extents []Extent) io.Reader {
	readers := make([]io.Reader, 0, len(extents))
	for _, e := range extents {
		readers = append(readers, io.NewSectionReader(f, e.Offset, e.Length))
	}
	return io.MultiReader(readers...)
}
