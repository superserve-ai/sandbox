package vm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
)

func TestSnapshotManifestRoundTrip(t *testing.T) {
	dir := t.TempDir()

	// Absent manifest reads as (nil, nil), not an error.
	if m, err := readManifest(dir); err != nil || m != nil {
		t.Fatalf("readManifest(empty) = (%v, %v), want (nil, nil)", m, err)
	}

	want := &snapshotManifest{Base: "/templates/foo/mem.snap", Overlays: []string{"mem.0.diff", "mem.1.diff"}}
	if err := writeManifestAtomic(dir, want); err != nil {
		t.Fatalf("writeManifestAtomic: %v", err)
	}
	// The temp file must not survive a successful publish.
	if _, err := os.Stat(manifestPath(dir) + ".next"); !os.IsNotExist(err) {
		t.Fatalf("manifest .next survived publish: stat err = %v", err)
	}
	got, err := readManifest(dir)
	if err != nil || got == nil {
		t.Fatalf("readManifest after write = (%v, %v)", got, err)
	}
	if got.Base != want.Base || len(got.Overlays) != len(want.Overlays) {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", got, want)
	}
	for i := range want.Overlays {
		if got.Overlays[i] != want.Overlays[i] {
			t.Fatalf("overlay[%d] = %q, want %q", i, got.Overlays[i], want.Overlays[i])
		}
	}

	// A corrupt manifest is an error, not a silent empty chain.
	if err := os.WriteFile(manifestPath(dir), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readManifest(dir); err == nil {
		t.Fatal("readManifest(corrupt) = nil error, want parse error")
	}
}

func TestRemoveManifest(t *testing.T) {
	dir := t.TempDir()

	// Removing an absent manifest is not an error (a Full-fallback dir may have none).
	if err := removeManifest(dir); err != nil {
		t.Fatalf("removeManifest(absent) = %v, want nil", err)
	}

	if err := writeManifestAtomic(dir, &snapshotManifest{Base: "b", Overlays: []string{"mem.0.diff"}}); err != nil {
		t.Fatal(err)
	}
	if err := removeManifest(dir); err != nil {
		t.Fatalf("removeManifest = %v", err)
	}
	// After removal a resume must not see a manifest (standalone snapshot is authoritative).
	if m, err := readManifest(dir); err != nil || m != nil {
		t.Fatalf("readManifest after remove = (%v, %v), want (nil, nil)", m, err)
	}
}

func TestManifestVmstate(t *testing.T) {
	dir := t.TempDir()

	// A manifest that records its vmstate resolves to that per-layer file; the commit is
	// atomic (the single manifest rename carries chain + vmstate), and round-trips.
	want := &snapshotManifest{
		Base:     "/templates/foo/mem.snap",
		Overlays: []string{"mem.0.diff", "mem.1.diff"},
		Vmstate:  vmstateLayerName(1),
	}
	if want.Vmstate != "vmstate.1.snap" {
		t.Fatalf("vmstateLayerName(1) = %q, want vmstate.1.snap", want.Vmstate)
	}
	if err := writeManifestAtomic(dir, want); err != nil {
		t.Fatalf("writeManifestAtomic: %v", err)
	}
	got, err := readManifest(dir)
	if err != nil || got == nil {
		t.Fatalf("readManifest = (%v, %v)", got, err)
	}
	if got.Vmstate != want.Vmstate {
		t.Fatalf("round-trip Vmstate = %q, want %q", got.Vmstate, want.Vmstate)
	}
	if p := manifestVmstatePath(dir, got); p != filepath.Join(dir, "vmstate.1.snap") {
		t.Fatalf("manifestVmstatePath = %q, want dir/vmstate.1.snap", p)
	}

	// A manifest without a recorded vmstate (or no manifest) falls back to the legacy file.
	legacy := &snapshotManifest{Base: "b", Overlays: []string{"mem.0.diff"}}
	if p := manifestVmstatePath(dir, legacy); p != filepath.Join(dir, "vmstate.snap") {
		t.Fatalf("legacy manifestVmstatePath = %q, want dir/vmstate.snap", p)
	}
	if p := manifestVmstatePath(dir, nil); p != filepath.Join(dir, "vmstate.snap") {
		t.Fatalf("nil manifestVmstatePath = %q, want dir/vmstate.snap", p)
	}
}

func TestChainPaths(t *testing.T) {
	dir := "/snap/vm1"

	// Empty chain → not ok.
	empty := &snapshotManifest{Base: "/b"}
	if _, _, _, ok := empty.chainPaths(dir); ok {
		t.Fatal("chainPaths(empty) ok = true, want false")
	}
	if _, _, _, ok := (*snapshotManifest)(nil).chainPaths(dir); ok {
		t.Fatal("chainPaths(nil) ok = true, want false")
	}

	m := &snapshotManifest{Base: "/templates/x/mem.snap", Overlays: []string{"mem.0.diff", "mem.1.diff", "mem.2.diff"}}
	base, lower, newest, ok := m.chainPaths(dir)
	if !ok {
		t.Fatal("chainPaths ok = false, want true")
	}
	if base != "/templates/x/mem.snap" {
		t.Fatalf("base = %q", base)
	}
	if newest != filepath.Join(dir, "mem.2.diff") {
		t.Fatalf("newest = %q", newest)
	}
	wantLower := []string{filepath.Join(dir, "mem.0.diff"), filepath.Join(dir, "mem.1.diff")}
	if len(lower) != len(wantLower) {
		t.Fatalf("lower = %v, want %v", lower, wantLower)
	}
	for i := range wantLower {
		if lower[i] != wantLower[i] {
			t.Fatalf("lower[%d] = %q, want %q", i, lower[i], wantLower[i])
		}
	}

	// Single overlay: no lower overlays, newest is that one.
	one := &snapshotManifest{Base: "/b", Overlays: []string{"mem.0.diff"}}
	_, lower1, newest1, _ := one.chainPaths(dir)
	if len(lower1) != 0 || newest1 != filepath.Join(dir, "mem.0.diff") {
		t.Fatalf("single overlay: lower=%v newest=%q", lower1, newest1)
	}
}

func TestPlanLayerAppend(t *testing.T) {
	tmpl := "/templates/x/mem.snap"

	newMgr := func(layerAppend, incremental bool) *Manager {
		return &Manager{
			cfg: ManagerConfig{LayerAppendEnabled: layerAppend, IncrementalSnapshotEnabled: incremental},
			log: zerolog.Nop(),
		}
	}

	t.Run("disabled flags or no dirty tracking", func(t *testing.T) {
		dir := t.TempDir()
		if _, _, ok := newMgr(false, true).planLayerAppend(dir, true, tmpl, tmpl); ok {
			t.Fatal("append enabled with LayerAppend off")
		}
		if _, _, ok := newMgr(true, false).planLayerAppend(dir, true, tmpl, tmpl); ok {
			t.Fatal("append enabled with Incremental off")
		}
		if _, _, ok := newMgr(true, true).planLayerAppend(dir, false, tmpl, tmpl); ok {
			t.Fatal("append enabled without dirty tracking")
		}
	})

	t.Run("first layer from template base", func(t *testing.T) {
		dir := t.TempDir()
		base, man, ok := newMgr(true, true).planLayerAppend(dir, true, tmpl, tmpl)
		if !ok || base != tmpl || man == nil || len(man.Overlays) != 0 {
			t.Fatalf("first layer = (%q, %+v, %v), want (%q, empty-overlays, true)", base, man, ok, tmpl)
		}
	})

	t.Run("first layer rejected when not loaded from template", func(t *testing.T) {
		dir := t.TempDir()
		// instMemFile != instBaseMem → resumed from something else, not the base.
		if _, _, ok := newMgr(true, true).planLayerAppend(dir, true, tmpl, "/some/other.diff"); ok {
			t.Fatal("append allowed though VM didn't load from the template base")
		}
		// No base at all.
		if _, _, ok := newMgr(true, true).planLayerAppend(dir, true, "", ""); ok {
			t.Fatal("append allowed with no base")
		}
	})

	t.Run("accumulating from newest overlay", func(t *testing.T) {
		dir := t.TempDir()
		man := &snapshotManifest{Base: tmpl, Overlays: []string{"mem.0.diff"}}
		if err := writeManifestAtomic(dir, man); err != nil {
			t.Fatal(err)
		}
		newest := filepath.Join(dir, "mem.0.diff")
		base, got, ok := newMgr(true, true).planLayerAppend(dir, true, tmpl, newest)
		if !ok || base != tmpl || got == nil || len(got.Overlays) != 1 {
			t.Fatalf("accumulating = (%q, %+v, %v)", base, got, ok)
		}
	})

	t.Run("accumulating rejected when not resumed from newest", func(t *testing.T) {
		dir := t.TempDir()
		man := &snapshotManifest{Base: tmpl, Overlays: []string{"mem.0.diff", "mem.1.diff"}}
		if err := writeManifestAtomic(dir, man); err != nil {
			t.Fatal(err)
		}
		// Resumed from mem.0.diff, but newest is mem.1.diff → a diff here would lose state.
		stale := filepath.Join(dir, "mem.0.diff")
		if _, _, ok := newMgr(true, true).planLayerAppend(dir, true, tmpl, stale); ok {
			t.Fatal("append allowed though VM didn't resume from the newest overlay")
		}
	})
}
