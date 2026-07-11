//go:build linux

package presence

import (
	"os"
	"path/filepath"
	"testing"
)

// writeSparseOverlay lays out a file the way a diff dump does: written
// extents for provided pages (zeros included), holes for the rest.
func writeSparseOverlay(t *testing.T, path string, pageSize, npages int, dataPages map[int]byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Truncate(int64(npages * pageSize)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, pageSize)
	for pg, b := range dataPages {
		for i := range buf {
			buf[i] = b
		}
		if _, err := f.WriteAt(buf, int64(pg*pageSize)); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
}

func TestScanAndGenerate(t *testing.T) {
	ps := os.Getpagesize()
	dir := t.TempDir()
	mem := filepath.Join(dir, "mem.diff")

	// Pages 1 (real data) and 2 (written zeros — still a provided page!)
	// present; 0 and 3 are holes.
	writeSparseOverlay(t, mem, ps, 4, map[int]byte{1: 0xAA, 2: 0x00})

	p, err := Scan(mem, ps)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if p.NPages != 4 {
		t.Fatalf("npages: got %d", p.NPages)
	}
	if p.IsSet(0) || !p.IsSet(1) || !p.IsSet(2) || p.IsSet(3) {
		t.Errorf("scan bits wrong: %+v", p.Bits)
	}

	// Generate = scan + atomic write; the side-car must decode to the same bits.
	if err := Generate(mem); err != nil {
		t.Fatalf("generate: %v", err)
	}
	rd, err := Read(mem)
	if err != nil {
		t.Fatalf("read generated: %v", err)
	}
	if rd.PageSize != uint64(ps) || rd.NPages != p.NPages {
		t.Errorf("generated geometry: %+v", rd)
	}
	for i := 0; i < 4; i++ {
		if rd.IsSet(i) != p.IsSet(i) {
			t.Errorf("page %d: generated %v, scanned %v", i, rd.IsSet(i), p.IsSet(i))
		}
	}
}

func TestScanAllHoles(t *testing.T) {
	ps := os.Getpagesize()
	dir := t.TempDir()
	mem := filepath.Join(dir, "mem.diff")
	writeSparseOverlay(t, mem, ps, 8, nil)

	p, err := Scan(mem, ps)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for i := 0; i < 8; i++ {
		if p.IsSet(i) {
			t.Errorf("page %d set in all-hole file", i)
		}
	}
}
