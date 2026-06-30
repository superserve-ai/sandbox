package vm

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/sys/unix"
)

const tPages = 4 // 4-page test images

func tTotal() int64 { return tPages * flattenPageSize }

// writeSparsePage writes a full page of byte b at page index idx into a file
// pre-sized to the full image, leaving other pages as holes.
func writeSparsePage(t *testing.T, path string, idx int, b byte) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Truncate(tTotal()); err != nil {
		t.Fatal(err)
	}
	page := bytes.Repeat([]byte{b}, flattenPageSize)
	if _, err := f.WriteAt(page, int64(idx)*flattenPageSize); err != nil {
		t.Fatal(err)
	}
}

func readPage(t *testing.T, path string, idx int) []byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	buf := make([]byte, flattenPageSize)
	if _, err := f.ReadAt(buf, int64(idx)*flattenPageSize); err != nil {
		t.Fatal(err)
	}
	return buf
}

// pageIsHole reports whether the page at idx is a hole (not allocated) — i.e. the
// flatten left it absent so restore falls through to the base.
func pageIsHole(t *testing.T, path string, idx int) bool {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	off := int64(idx) * flattenPageSize
	data, err := unix.Seek(int(f.Fd()), off, unix.SEEK_DATA)
	if err == unix.ENXIO {
		return true // no data at/after off
	}
	if err != nil {
		t.Fatal(err)
	}
	return data >= off+flattenPageSize // next data is past this page ⇒ this page is a hole
}

func TestFlattenChain(t *testing.T) {
	dir := t.TempDir()

	// Base: full image, all 'B'.
	base := filepath.Join(dir, "base.mem")
	bf, err := os.Create(base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bf.WriteAt(bytes.Repeat([]byte{'B'}, int(tTotal())), 0); err != nil {
		t.Fatal(err)
	}
	bf.Close()

	// d0 owns pages 0 ('X') and 2 ('Y'); d1 (newest) owns page 0 ('Z').
	writeSparsePage(t, filepath.Join(dir, "mem.0.diff"), 0, 'X')
	writeSparsePage(t, filepath.Join(dir, "mem.0.diff"), 2, 'Y')
	writeSparsePage(t, filepath.Join(dir, "mem.1.diff"), 0, 'Z')

	man := &snapshotManifest{Base: base, Overlays: []string{"mem.0.diff", "mem.1.diff"}}
	if err := writeManifestAtomic(dir, man); err != nil {
		t.Fatal(err)
	}

	m := &Manager{log: zerolog.Nop()}
	if err := m.flattenChain(dir); err != nil {
		t.Fatalf("flattenChain: %v", err)
	}

	// Manifest collapsed to a single merged overlay; old layers gone.
	got, err := readManifest(dir)
	if err != nil || got == nil {
		t.Fatalf("readManifest: %v", err)
	}
	if len(got.Overlays) != 1 || got.Overlays[0] != "mem.flat.0.diff" {
		t.Fatalf("overlays = %v, want [mem.flat.0.diff]", got.Overlays)
	}
	if got.Base != base {
		t.Fatalf("base = %q, want %q (base sharing must be preserved)", got.Base, base)
	}
	for _, old := range []string{"mem.0.diff", "mem.1.diff"} {
		if _, err := os.Stat(filepath.Join(dir, old)); !os.IsNotExist(err) {
			t.Fatalf("old layer %s not reclaimed", old)
		}
	}

	merged := filepath.Join(dir, "mem.flat.0.diff")
	// Page 0: newest owner (d1) wins → 'Z'.
	if p0 := readPage(t, merged, 0); p0[0] != 'Z' {
		t.Fatalf("page 0 = %q, want all 'Z' (newest-wins)", p0[0])
	}
	// Page 2: only d0 owns it → 'Y'.
	if p2 := readPage(t, merged, 2); p2[0] != 'Y' {
		t.Fatalf("page 2 = %q, want all 'Y'", p2[0])
	}
	// Pages 1 and 3: owned by no overlay → must stay holes (fall through to base),
	// NOT written as zeros (which would shadow the base with zeros = corruption).
	if !pageIsHole(t, merged, 1) {
		t.Fatal("page 1 should be a hole (fall through to base), but it was written")
	}
	if !pageIsHole(t, merged, 3) {
		t.Fatal("page 3 should be a hole (fall through to base), but it was written")
	}
}

func TestGCOrphanLayers(t *testing.T) {
	dir := t.TempDir()
	old := time.Now().Add(-time.Hour)

	mk := func(name string, aged bool) {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if aged {
			if err := os.Chtimes(p, old, old); err != nil {
				t.Fatal(err)
			}
		}
	}

	// Referenced layer (kept), an aged orphan layer (reclaimed), an aged temp
	// (reclaimed), a recent orphan (kept — within grace), and an unrelated file (kept).
	mk("mem.0.diff", true)         // referenced
	mk("mem.1.diff", true)         // aged orphan → reclaim
	mk("manifest.json.next", true) // aged temp → reclaim
	mk("mem.2.diff", false)        // recent orphan → keep (grace)
	mk("vmstate.snap", true)       // not a layer/temp → keep

	man := &snapshotManifest{Base: "/templates/x/mem.snap", Overlays: []string{"mem.0.diff"}}
	if err := writeManifestAtomic(dir, man); err != nil {
		t.Fatal(err)
	}

	m := &Manager{log: zerolog.Nop()}
	if _, err := m.gcOrphanLayers(dir); err != nil {
		t.Fatalf("gcOrphanLayers: %v", err)
	}

	exists := func(name string) bool {
		_, err := os.Stat(filepath.Join(dir, name))
		return err == nil
	}
	for _, keep := range []string{"mem.0.diff", "mem.2.diff", "vmstate.snap", "manifest.json"} {
		if !exists(keep) {
			t.Fatalf("%s was reclaimed but should be kept", keep)
		}
	}
	for _, gone := range []string{"mem.1.diff", "manifest.json.next"} {
		if exists(gone) {
			t.Fatalf("%s should have been reclaimed", gone)
		}
	}
}

func TestNextFlatName(t *testing.T) {
	if n := nextFlatName([]string{"mem.0.diff", "mem.1.diff"}); n != "mem.flat.0.diff" {
		t.Fatalf("got %q, want mem.flat.0.diff", n)
	}
	if n := nextFlatName([]string{"mem.flat.0.diff", "mem.1.diff"}); n != "mem.flat.1.diff" {
		t.Fatalf("got %q, want mem.flat.1.diff", n)
	}
}
