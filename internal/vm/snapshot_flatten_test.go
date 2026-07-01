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
	newest, err := m.flattenChain(dir)
	if err != nil {
		t.Fatalf("flattenChain: %v", err)
	}
	if filepath.Base(newest) != "mem.flat.0.diff" {
		t.Fatalf("flattenChain returned newest %q, want …/mem.flat.0.diff", newest)
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

func TestFlattenChainRejectsShortOverlay(t *testing.T) {
	// A truncated/short overlay would silently leave its out-of-range pages to an older layer.
	// flattenChain must reject it (like the FC loader) and leave the chain intact, not mis-merge.
	dir := t.TempDir()
	base := filepath.Join(dir, "base.mem")
	if err := os.WriteFile(base, bytes.Repeat([]byte{'B'}, int(tTotal())), 0o644); err != nil {
		t.Fatal(err)
	}
	writeSparsePage(t, filepath.Join(dir, "mem.0.diff"), 0, 'X') // full guest-RAM size
	// mem.1.diff is one page long — shorter than guest RAM.
	if err := os.WriteFile(filepath.Join(dir, "mem.1.diff"), bytes.Repeat([]byte{'Z'}, flattenPageSize), 0o644); err != nil {
		t.Fatal(err)
	}
	man := &snapshotManifest{Base: base, Overlays: []string{"mem.0.diff", "mem.1.diff"}}
	if err := writeManifestAtomic(dir, man); err != nil {
		t.Fatal(err)
	}
	m := &Manager{log: zerolog.Nop()}
	if _, err := m.flattenChain(dir); err == nil {
		t.Fatal("flattenChain accepted a short overlay; want error")
	}
	if got, _ := readManifest(dir); got == nil || len(got.Overlays) != 2 {
		t.Fatalf("chain not left intact after a rejected flatten: %+v", got)
	}
}

func TestPlanLayerAppendAfterFlatten(t *testing.T) {
	// After a flatten, a pause whose resumed mem file is the flattened newest must be recognized
	// as an accumulating append — else VMD_LAYER_APPEND + VMD_LAYER_FLATTEN self-defeat (the pause
	// falls back to standalone and drops the chain).
	dir := t.TempDir()
	base := filepath.Join(dir, "base.mem")
	if err := os.WriteFile(base, bytes.Repeat([]byte{'B'}, int(tTotal())), 0o644); err != nil {
		t.Fatal(err)
	}
	writeSparsePage(t, filepath.Join(dir, "mem.0.diff"), 0, 'X')
	writeSparsePage(t, filepath.Join(dir, "mem.1.diff"), 1, 'Y')
	man := &snapshotManifest{Base: base, Overlays: []string{"mem.0.diff", "mem.1.diff"}}
	if err := writeManifestAtomic(dir, man); err != nil {
		t.Fatal(err)
	}
	m := &Manager{log: zerolog.Nop(), cfg: ManagerConfig{LayerAppendEnabled: true, IncrementalSnapshotEnabled: true}}
	newest, err := m.flattenChain(dir)
	if err != nil {
		t.Fatalf("flattenChain: %v", err)
	}
	if _, _, ok := m.planLayerAppend(dir, true, base, newest); !ok {
		t.Fatal("planLayerAppend rejected the flattened newest; append+flatten would drop the chain")
	}
}

func TestMaybeFlattenDefersDuringRestore(t *testing.T) {
	// A memfd bridge fast-resume skips waitForFlush and restores from the committed overlay
	// chain while a bridge completion may call maybeFlatten. Flattening then would delete those
	// overlay files out from under the in-flight restore. maybeFlatten must DEFER (not arm) while
	// a restore is in flight (restoring) or a bridge memfd is held (holdingBridgeMemfd).
	dir := t.TempDir()
	man := &snapshotManifest{
		Base:     "/templates/x/mem.snap",
		Overlays: []string{"mem.0.diff", "mem.1.diff", "mem.2.diff"}, // depth 3 ≥ threshold 2 ⇒ flatten-worthy
	}
	if err := writeManifestAtomic(dir, man); err != nil {
		t.Fatal(err)
	}
	m := &Manager{
		log:        zerolog.Nop(),
		flattenSem: make(chan struct{}, 2),
		cfg:        ManagerConfig{LayerFlattenEnabled: true, FlattenChainDepth: 2},
	}

	armed := func(inst *VMInstance) bool {
		m.maybeFlatten(inst, dir)
		inst.mu.Lock()
		defer inst.mu.Unlock()
		return inst.flattening
	}

	if armed(&VMInstance{ID: "r", restoring: true}) {
		t.Fatal("maybeFlatten armed flatten while a restore was in flight (would race the restore's lower-overlay reads)")
	}
	if armed(&VMInstance{ID: "h", holdingBridgeMemfd: true}) {
		t.Fatal("maybeFlatten armed flatten while a bridge memfd was held for resume")
	}
	if len(m.flattenSem) != 0 {
		t.Fatalf("deferred flatten leaked a flattenSem slot: len=%d, want 0", len(m.flattenSem))
	}
	// Sanity: with neither guard set, a flatten-worthy chain DOES arm.
	clean := &VMInstance{ID: "c"}
	m.maybeFlatten(clean, dir)
	clean.mu.Lock()
	gotArmed := clean.flattening
	clean.mu.Unlock()
	if !gotArmed {
		t.Fatal("maybeFlatten did not arm flatten for a flatten-worthy chain with no restore in flight")
	}
	if clean.flattenDone != nil {
		<-clean.flattenDone // let the background flatten finish (errors on the fake chain, but endFlatten still fires)
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
	mk("vmstate.snap", true)       // legacy vmstate (no index) → not a layer/temp → keep
	// Per-layer vmstate + its block-overlay sidecar: the committed one (man.Vmstate) and its
	// sidecar are kept; an older/interrupted layer's vmstate + sidecar are aged orphans → reclaim.
	mk("vmstate.5.snap", true)         // committed (man.Vmstate) → keep
	mk("vmstate.5.snap.overlay", true) // committed sidecar → keep (FC reads <vmstate>.overlay)
	mk("vmstate.1.snap", true)         // aged orphan vmstate → reclaim
	mk("vmstate.1.snap.overlay", true) // aged orphan sidecar → reclaim

	man := &snapshotManifest{Base: "/templates/x/mem.snap", Overlays: []string{"mem.0.diff"}, Vmstate: "vmstate.5.snap"}
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
	for _, keep := range []string{"mem.0.diff", "mem.2.diff", "vmstate.snap", "manifest.json", "vmstate.5.snap", "vmstate.5.snap.overlay"} {
		if !exists(keep) {
			t.Fatalf("%s was reclaimed but should be kept", keep)
		}
	}
	for _, gone := range []string{"mem.1.diff", "manifest.json.next", "vmstate.1.snap", "vmstate.1.snap.overlay"} {
		if exists(gone) {
			t.Fatalf("%s should have been reclaimed", gone)
		}
	}
}

func TestShouldFlatten(t *testing.T) {
	cases := []struct {
		name      string
		count     int
		allocated int64
		depth     int
		bytes     int64
		want      bool
	}{
		{"single overlay never flattens", 1, 1 << 40, 0, 1, false},
		{"below both thresholds", 3, 100, 16, 1 << 30, false},
		{"depth reached", 16, 0, 16, 0, true},
		{"depth default when unset", 16, 0, 0, 0, true},
		{"bytes reached below depth", 4, 2 << 30, 16, 1 << 30, true},
		{"bytes disabled (0) below depth", 4, 1 << 40, 16, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := shouldFlatten(c.count, c.allocated, c.depth, c.bytes); got != c.want {
				t.Fatalf("shouldFlatten(%d,%d,%d,%d) = %v, want %v", c.count, c.allocated, c.depth, c.bytes, got, c.want)
			}
		})
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
