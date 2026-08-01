//go:build linux

package backup

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// Builds a sparse file shaped like a real overlay: data at the front, a
// large hole, data in the middle, trailing hole to the apparent size.
func TestExtentsAndPackedReader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "overlay.ext4")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	const apparent = 64 << 20 // 64MiB apparent
	front := bytes.Repeat([]byte{0xAA}, 128<<10)
	mid := bytes.Repeat([]byte{0xBB}, 64<<10)
	const midOff = 32 << 20
	if _, err := f.WriteAt(front, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(mid, midOff); err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(apparent); err != nil {
		t.Fatal(err)
	}

	extents, size, err := Extents(f)
	if err != nil {
		t.Fatal(err)
	}
	if size != apparent {
		t.Fatalf("apparent size = %d, want %d", size, apparent)
	}
	packed := PackedSize(extents)
	// Extent granularity is fs-block based, so allow slack, but the packed
	// size must be dramatically smaller than apparent and cover the data.
	if packed < int64(len(front)+len(mid)) || packed > apparent/4 {
		t.Fatalf("packed size = %d (extents %v), want compact coverage of %d data bytes",
			packed, extents, len(front)+len(mid))
	}

	// Round-trip: packed stream re-placed at extent offsets rebuilds the
	// original content exactly.
	data, err := io.ReadAll(NewPackedReader(f, extents))
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(data)) != packed {
		t.Fatalf("packed stream = %d bytes, want %d", len(data), packed)
	}
	rebuilt := make([]byte, apparent)
	var cursor int64
	for _, e := range extents {
		copy(rebuilt[e.Offset:e.Offset+e.Length], data[cursor:cursor+e.Length])
		cursor += e.Length
	}
	original := make([]byte, apparent)
	copy(original, front)
	copy(original[midOff:], mid)
	if !bytes.Equal(rebuilt, original) {
		t.Fatal("rebuilt sparse content differs from original")
	}
}

func TestExtentsEmptyAndDense(t *testing.T) {
	dir := t.TempDir()

	empty, err := os.Create(filepath.Join(dir, "empty"))
	if err != nil {
		t.Fatal(err)
	}
	defer empty.Close()
	extents, size, err := Extents(empty)
	if err != nil || size != 0 || len(extents) != 0 {
		t.Fatalf("empty: extents=%v size=%d err=%v", extents, size, err)
	}

	dense, err := os.Create(filepath.Join(dir, "dense"))
	if err != nil {
		t.Fatal(err)
	}
	defer dense.Close()
	content := bytes.Repeat([]byte{0xCC}, 256<<10)
	if _, err := dense.Write(content); err != nil {
		t.Fatal(err)
	}
	extents, size, err = Extents(dense)
	if err != nil || size != int64(len(content)) {
		t.Fatalf("dense: size=%d err=%v", size, err)
	}
	if PackedSize(extents) < int64(len(content)) {
		t.Fatalf("dense file packed smaller than content: %d < %d", PackedSize(extents), len(content))
	}
	got, err := io.ReadAll(NewPackedReader(dense, extents))
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("dense round-trip mismatch (err=%v)", err)
	}
}
