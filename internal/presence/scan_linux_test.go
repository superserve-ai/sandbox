//go:build linux

package presence

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/superserve-ai/sandbox/internal/presence/presencetest"
)

func TestScanAndGenerate(t *testing.T) {
	ps := os.Getpagesize()
	dir := t.TempDir()
	mem := filepath.Join(dir, "mem.diff")

	// Pages 1 (real data) and 2 (written zeros — still a provided page!)
	// present; 0 and 3 are holes.
	presencetest.WriteSparseOverlay(t, mem, ps, 4, map[int]byte{1: 0xAA, 2: 0x00})

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

	// Scan + WriteIfAbsent is the sweep's generation path; the side-car must
	// decode to the same bits, and a second write must refuse to replace it.
	if err := WriteIfAbsent(mem, p.PageSize, p.NPages, p.Bits); err != nil {
		t.Fatalf("write-if-absent: %v", err)
	}
	if err := WriteIfAbsent(mem, p.PageSize, p.NPages, p.Bits); err != ErrSidecarExists {
		t.Fatalf("second write-if-absent: got %v, want ErrSidecarExists", err)
	}
	if _, err := os.Stat(SidecarPath(mem) + ".tmp"); !os.IsNotExist(err) {
		t.Error("refused write left a temp file behind")
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
	presencetest.WriteSparseOverlay(t, mem, ps, 8, nil)

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
