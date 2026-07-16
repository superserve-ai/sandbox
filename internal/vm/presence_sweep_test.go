//go:build linux

package vm

import (
	"os"
	"path/filepath"
	"testing"
	"time"

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

// newSweepManager builds a Manager with a real BoltDB store — the sweep
// enumerates paused records, so every test overlay needs one.
func newSweepManager(t *testing.T, root string) (*Manager, *StateStore) {
	t.Helper()
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return &Manager{
		cfg:   ManagerConfig{SnapshotDir: root},
		log:   zerolog.Nop(),
		vms:   map[string]*VMInstance{},
		state: store,
	}, store
}

func pausedRecord(t *testing.T, store *StateStore, vmID, memPath string) {
	t.Helper()
	if err := store.Put(VMRecord{ID: vmID, Status: StatusPaused, MemFilePath: memPath}); err != nil {
		t.Fatal(err)
	}
}

func TestSweepConvergesAndFreezes(t *testing.T) {
	root := t.TempDir()
	m, store := newSweepManager(t, root)

	memA := sweepFixture(t, root, "vm-a") // paused record: provably local, sweepable
	pausedRecord(t, store, "vm-a", memA)
	memB := sweepFixture(t, root, "vm-b") // active unit: must be deferred
	pausedRecord(t, store, "vm-b", memB)
	memC := sweepFixture(t, root, "vm-c") // record says paused, memory says running: deferred
	pausedRecord(t, store, "vm-c", memC)
	m.vms["vm-c"] = &VMInstance{ID: "vm-c", Status: StatusRunning}
	memO := sweepFixture(t, root, "vm-o") // overlay with NO record: never enumerated

	// Pass 1: only vm-a is local+quiescent → generated; host not converged.
	m.sweepPresenceSidecars(map[string]bool{"vm-b": true})
	if _, err := presence.Read(memA); err != nil {
		t.Fatalf("vm-a side-car not generated: %v", err)
	}
	if _, err := os.Stat(presence.SidecarPath(memB)); !os.IsNotExist(err) {
		t.Error("vm-b swept while its unit was active")
	}
	if _, err := os.Stat(presence.SidecarPath(memC)); !os.IsNotExist(err) {
		t.Error("vm-c swept while running in memory")
	}
	if m.presenceConverged.Load() {
		t.Fatal("converged with stragglers outstanding")
	}
	if m.presenceStrict() {
		t.Fatal("auto mode strict before convergence")
	}

	// Pass 2: vm-b quiesced (unit gone), vm-c paused in memory → all recorded
	// overlays generated; the record-less overlay neither gets a side-car nor
	// blocks the marker — an unrecorded mem.diff has no local provenance, and
	// converging around it is deliberate (it is refused at restore instead).
	m.vms["vm-c"].Status = StatusPaused
	m.sweepPresenceSidecars(nil)
	for _, mem := range []string{memB, memC} {
		if _, err := presence.Read(mem); err != nil {
			t.Fatalf("side-car missing after pass 2 for %s: %v", mem, err)
		}
	}
	if _, err := os.Stat(presence.SidecarPath(memO)); !os.IsNotExist(err) {
		t.Error("record-less overlay swept: no provenance, must never be generated from")
	}
	if !m.presenceConverged.Load() {
		t.Fatal("not converged after all recorded side-cars generated")
	}
	if !m.presenceStrict() {
		t.Fatal("auto mode not strict after convergence")
	}
	if _, err := os.Stat(m.presenceConvergedMarkerPath()); err != nil {
		t.Fatalf("marker not written: %v", err)
	}

	// Post-convergence: a new side-car-less overlay (even a recorded one) must
	// NOT be healed by the sweep — the marker short-circuits before enumeration.
	memD := sweepFixture(t, root, "vm-d")
	pausedRecord(t, store, "vm-d", memD)
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

func TestSweepHealsCustomPausePaths(t *testing.T) {
	// PauseVM accepts a caller-supplied snapshot dir, so a paused overlay can
	// live anywhere — including nested paths no fixed glob would find. The
	// record's MemFilePath must be the enumeration source; converging past a
	// custom-path overlay would strand it behind the strict gate.
	root := t.TempDir()
	m, store := newSweepManager(t, root)
	mem := sweepFixture(t, root, filepath.Join("custom", "snap-7", "deep"))
	pausedRecord(t, store, "vm-deep", mem)

	m.sweepPresenceSidecars(nil)
	if _, err := presence.Read(mem); err != nil {
		t.Fatalf("custom-path overlay not healed: %v", err)
	}
	if !m.presenceConverged.Load() {
		t.Fatal("host did not converge")
	}
}

func TestSweepPreservesSentinels(t *testing.T) {
	root := t.TempDir()
	m, store := newSweepManager(t, root)

	// A torn-save sentinel is a PRESENT side-car: the sweep must not
	// regenerate it from the (torn) overlay's extents — the loud refusal is
	// the correct outcome for a torn save.
	mem := sweepFixture(t, root, "vm-torn")
	pausedRecord(t, store, "vm-torn", mem)
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

func TestSweepStateStoreErrorBlocksConvergence(t *testing.T) {
	root := t.TempDir()
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	// A closed store errors on every read — standing in for any BoltDB
	// failure. "Can't enumerate" must defer the whole pass: converging
	// blind could strand local paused VMs behind the gate.
	store.Close()
	m := &Manager{
		cfg:   ManagerConfig{SnapshotDir: root},
		log:   zerolog.Nop(),
		vms:   map[string]*VMInstance{},
		state: store,
	}
	sweepFixture(t, root, "vm-err")
	m.sweepPresenceSidecars(nil)
	if m.presenceConverged.Load() {
		t.Error("converged past an unreadable state store")
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
	m, store := newSweepManager(t, root)

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
	mem := sweepFixture(t, root, "vm-late")
	pausedRecord(t, store, "vm-late", mem)
	m.sweepPresenceSidecars(nil)
	if _, err := presence.Read(mem); err != nil {
		t.Fatalf("late overlay not healed after marker removal: %v", err)
	}
	if !m.presenceConverged.Load() {
		t.Fatal("host did not re-converge after healing")
	}
}

func TestVerifyPresenceRefreshed(t *testing.T) {
	root := t.TempDir()
	m := &Manager{cfg: ManagerConfig{SnapshotDir: root}, log: zerolog.Nop(), vms: map[string]*VMInstance{}}
	nop := zerolog.Nop()
	mem := sweepFixture(t, root, "vm-r")
	sc := presence.SidecarPath(mem)

	// Fresh side-car (written during the save) is kept.
	if err := presence.Write(mem, 4096, 4, []uint64{0b0110}); err != nil {
		t.Fatal(err)
	}
	m.verifyPresenceRefreshed(mem, time.Now().Add(-time.Minute), nop)
	if _, err := os.Stat(sc); err != nil {
		t.Fatalf("fresh side-car removed: %v", err)
	}

	// Stale side-car (predates the save — the old-Firecracker misorder) is
	// removed so a newer Firecracker can never trust it.
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(sc, old, old); err != nil {
		t.Fatal(err)
	}
	m.verifyPresenceRefreshed(mem, time.Now(), nop)
	if _, err := os.Stat(sc); !os.IsNotExist(err) {
		t.Error("stale side-car not removed")
	}

	// Missing side-car: warn-only, nothing created.
	m.verifyPresenceRefreshed(mem, time.Now(), nop)
	if _, err := os.Stat(sc); !os.IsNotExist(err) {
		t.Error("guard created a side-car")
	}
}
