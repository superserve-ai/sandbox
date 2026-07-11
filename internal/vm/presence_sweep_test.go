//go:build linux

package vm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/presence"
	"github.com/superserve-ai/sandbox/internal/presence/presencetest"
)

// sweepFixture writes a snapshot dir with a sparse mem.diff (page 1 data,
// page 2 written zeros, 0/3 holes) and returns the mem path.
func sweepFixture(t *testing.T, root, vmID string) string {
	t.Helper()
	dir := filepath.Join(root, vmID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	mem := filepath.Join(dir, "mem.diff")
	presencetest.WriteSparseOverlay(t, mem, os.Getpagesize(), 4, map[int]byte{1: 0xAA, 2: 0x00})
	return mem
}

func TestSweepConvergesAndFreezes(t *testing.T) {
	root := t.TempDir()
	m := &Manager{
		cfg: ManagerConfig{SnapshotDir: root},
		log: zerolog.Nop(),
		vms: map[string]*VMInstance{},
	}

	m.vms["vm-a"] = &VMInstance{ID: "vm-a", Status: StatusPaused}
	memA := sweepFixture(t, root, "vm-a") // known-paused: provably local, sweepable
	m.vms["vm-b"] = &VMInstance{ID: "vm-b", Status: StatusPaused}
	memB := sweepFixture(t, root, "vm-b") // active unit: must be deferred
	m.vms["vm-c"] = &VMInstance{ID: "vm-c", Status: StatusRunning}
	memC := sweepFixture(t, root, "vm-c") // running instance: deferred
	memO := sweepFixture(t, root, "vm-o") // orphan: unknown provenance, never swept

	// Pass 1: only vm-a is local+quiescent → generated; host not converged.
	m.sweepPresenceSidecars(map[string]bool{"vm-b": true})
	if _, err := presence.Read(memA); err != nil {
		t.Fatalf("vm-a side-car not generated: %v", err)
	}
	if _, err := os.Stat(presence.SidecarPath(memB)); !os.IsNotExist(err) {
		t.Error("vm-b swept while its unit was active")
	}
	if _, err := os.Stat(presence.SidecarPath(memC)); !os.IsNotExist(err) {
		t.Error("vm-c swept while transitional")
	}
	if _, err := os.Stat(presence.SidecarPath(memO)); !os.IsNotExist(err) {
		t.Error("orphan overlay swept: unknown provenance must never be generated from")
	}
	if m.presenceConverged.Load() {
		t.Fatal("converged with stragglers outstanding")
	}
	if m.presenceStrict() {
		t.Fatal("auto mode strict before convergence")
	}

	// Pass 2: vm-b quiesced (unit gone), vm-c now paused → all local overlays
	// generated; the orphan neither gets a side-car nor blocks the marker —
	// converging around it is deliberate (it is refused at restore instead).
	m.vms["vm-c"].Status = StatusPaused
	m.sweepPresenceSidecars(nil)
	for _, mem := range []string{memB, memC} {
		if _, err := presence.Read(mem); err != nil {
			t.Fatalf("side-car missing after pass 2 for %s: %v", mem, err)
		}
	}
	if _, err := os.Stat(presence.SidecarPath(memO)); !os.IsNotExist(err) {
		t.Error("orphan overlay swept on pass 2")
	}
	if !m.presenceConverged.Load() {
		t.Fatal("not converged after all side-cars generated")
	}
	if !m.presenceStrict() {
		t.Fatal("auto mode not strict after convergence")
	}
	if _, err := os.Stat(m.presenceConvergedMarkerPath()); err != nil {
		t.Fatalf("marker not written: %v", err)
	}

	// Post-convergence: a new side-car-less overlay (e.g. a transfer that
	// dropped the pair) must NOT be healed by the sweep — that's the gate's
	// refusal to make, not the sweep's to bless.
	memD := sweepFixture(t, root, "vm-d")
	m.sweepPresenceSidecars(nil)
	if _, err := os.Stat(presence.SidecarPath(memD)); !os.IsNotExist(err) {
		t.Error("post-convergence sweep generated a side-car; laundering hazard")
	}

	// The marker survives a restart.
	m2 := &Manager{cfg: ManagerConfig{SnapshotDir: root}, log: zerolog.Nop(), vms: map[string]*VMInstance{}}
	m2.loadPresenceConverged()
	if !m2.presenceConverged.Load() {
		t.Fatal("marker not loaded at startup")
	}
}

func TestSweepPreservesSentinels(t *testing.T) {
	root := t.TempDir()
	m := &Manager{cfg: ManagerConfig{SnapshotDir: root}, log: zerolog.Nop(), vms: map[string]*VMInstance{}}

	// A torn-save sentinel is a PRESENT side-car: the sweep must not
	// regenerate it from the (torn) overlay's extents — the loud refusal is
	// the correct outcome for a torn save.
	mem := sweepFixture(t, root, "vm-torn")
	if err := os.WriteFile(presence.SidecarPath(mem), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	m.sweepPresenceSidecars(nil)
	st, err := os.Stat(presence.SidecarPath(mem))
	if err != nil || st.Size() != 0 {
		t.Errorf("torn sentinel replaced: size=%v err=%v", st, err)
	}
	// And the sentinel doesn't block host convergence: it's present, so the
	// host still converges around it.
	if !m.presenceConverged.Load() {
		t.Error("sentinel blocked convergence")
	}
}

func TestPresenceStrictModes(t *testing.T) {
	root := t.TempDir()
	for _, c := range []struct {
		mode      string
		converged bool
		want      bool
	}{
		{"always", false, true},
		{"never", true, false},
		{"auto", false, false},
		{"auto", true, true},
		{"", true, true}, // unset behaves as auto
	} {
		m := &Manager{cfg: ManagerConfig{SnapshotDir: root, RequirePresenceSidecar: c.mode}}
		m.presenceConverged.Store(c.converged)
		if got := m.presenceStrict(); got != c.want {
			t.Errorf("mode=%q converged=%v: strict=%v, want %v", c.mode, c.converged, got, c.want)
		}
	}
}

func TestSweepAlwaysModeNeverGenerates(t *testing.T) {
	root := t.TempDir()
	m := &Manager{
		cfg: ManagerConfig{SnapshotDir: root, RequirePresenceSidecar: "always"},
		log: zerolog.Nop(),
		vms: map[string]*VMInstance{},
	}
	// An "always" host declares its artifacts may be transferred: extent
	// inference is never sound there, so the sweep must not touch this
	// side-car-less overlay even pre-convergence.
	mem := sweepFixture(t, root, "vm-x")
	m.sweepPresenceSidecars(nil)
	if _, err := os.Stat(presence.SidecarPath(mem)); !os.IsNotExist(err) {
		t.Error("always-mode sweep generated a side-car from possibly-transferred extents")
	}
	if !m.presenceStrict() {
		t.Error("always mode must be strict regardless of marker")
	}
}

func TestSweepRederivesMarkerBothDirections(t *testing.T) {
	root := t.TempDir()
	m := &Manager{cfg: ManagerConfig{SnapshotDir: root}, log: zerolog.Nop(), vms: map[string]*VMInstance{}}

	// Empty dir converges (fresh-host case).
	m.sweepPresenceSidecars(nil)
	if !m.presenceConverged.Load() {
		t.Fatal("empty host did not converge")
	}

	// Marker removed (ops action, or hidden by a late mount): the next tick
	// must un-converge — dropping strictness, the safe direction — and resume
	// healing rather than trusting the stale in-memory latch.
	if err := os.Remove(m.presenceConvergedMarkerPath()); err != nil {
		t.Fatal(err)
	}
	m.vms["vm-late"] = &VMInstance{ID: "vm-late", Status: StatusPaused}
	mem := sweepFixture(t, root, "vm-late")
	m.sweepPresenceSidecars(nil)
	if _, err := presence.Read(mem); err != nil {
		t.Fatalf("late overlay not healed after marker removal: %v", err)
	}
	if !m.presenceConverged.Load() {
		t.Fatal("host did not re-converge after healing")
	}
}

func TestSweepBoltDBProvenanceBeatsReattachRace(t *testing.T) {
	root := t.TempDir()
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	m := &Manager{
		cfg:   ManagerConfig{SnapshotDir: root},
		log:   zerolog.Nop(),
		vms:   map[string]*VMInstance{},
		state: store,
	}

	// A paused VM persisted in BoltDB but not yet reattached into memory (the
	// first tick racing the background reattach) is still provably local —
	// it must be swept, not misread as an orphan and stranded behind the gate.
	if err := store.Put(VMRecord{ID: "vm-bolt", Status: StatusPaused}); err != nil {
		t.Fatal(err)
	}
	mem := sweepFixture(t, root, "vm-bolt")
	m.sweepPresenceSidecars(nil)
	if _, err := presence.Read(mem); err != nil {
		t.Fatalf("BoltDB-known paused overlay not swept: %v", err)
	}
	if !m.presenceConverged.Load() {
		t.Fatal("host did not converge")
	}
}
