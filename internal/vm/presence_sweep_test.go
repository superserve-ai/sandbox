//go:build linux

package vm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/presence"
)

// sweepFixture writes a snapshot dir with a sparse mem.diff (page 1 data,
// page 2 written zeros, 0/3 holes) and returns the mem path.
func sweepFixture(t *testing.T, root, vmID string) string {
	t.Helper()
	ps := os.Getpagesize()
	dir := filepath.Join(root, vmID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	mem := filepath.Join(dir, "mem.diff")
	f, err := os.Create(mem)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(int64(4 * ps)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, ps)
	for i := range buf {
		buf[i] = 0xAA
	}
	if _, err := f.WriteAt(buf, int64(ps)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(make([]byte, ps), int64(2*ps)); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return mem
}

func TestSweepConvergesAndFreezes(t *testing.T) {
	root := t.TempDir()
	m := &Manager{
		cfg: ManagerConfig{SnapshotDir: root},
		log: zerolog.Nop(),
		vms: map[string]*VMInstance{},
	}

	memA := sweepFixture(t, root, "vm-a") // orphan dir: quiescent, sweepable
	memB := sweepFixture(t, root, "vm-b") // active unit: must be deferred
	m.vms["vm-c"] = &VMInstance{ID: "vm-c", Status: StatusRunning}
	memC := sweepFixture(t, root, "vm-c") // running instance: deferred

	// Pass 1: only vm-a is quiescent → generated; host not converged.
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
	if m.presenceConverged.Load() {
		t.Fatal("converged with stragglers outstanding")
	}
	if m.presenceStrict() {
		t.Fatal("auto mode strict before convergence")
	}

	// Pass 2: vm-b quiesced (unit gone), vm-c now paused → all generated,
	// marker written, auto mode turns strict.
	m.vms["vm-c"].Status = StatusPaused
	m.sweepPresenceSidecars(nil)
	for _, mem := range []string{memB, memC} {
		if _, err := presence.Read(mem); err != nil {
			t.Fatalf("side-car missing after pass 2 for %s: %v", mem, err)
		}
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
