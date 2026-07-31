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
// honoring arbitrary extent tables so behavior matches linux exactly,
// including surfacing ErrTruncatedSource when the file ends early.
func NewPackedReader(f *os.File, extents []Extent) io.Reader {
	readers := make([]io.Reader, 0, len(extents))
	for _, e := range extents {
		readers = append(readers, io.NewSectionReader(f, e.Offset, e.Length))
	}
	return &exactLengthReader{r: io.MultiReader(readers...), want: PackedSize(extents)}
}

// exactLengthReader converts a premature EOF into ErrTruncatedSource.
type exactLengthReader struct {
	r    io.Reader
	want int64
	got  int64
}

func (e *exactLengthReader) Read(p []byte) (int, error) {
	n, err := e.r.Read(p)
	e.got += int64(n)
	if err == io.EOF && e.got != e.want {
		err = ErrTruncatedSource
	}
	return n, err
}
