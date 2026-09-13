package admission

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestDurableDrainSurvivesRestartAndRejectsStaleOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admission.json")
	gate := NewGate(false, 1)
	if err := gate.ConfigureDrain(path); err != nil {
		t.Fatal(err)
	}
	if err := gate.Admit("fresh", IntentCreate); err != ErrNotReady {
		t.Fatalf("fresh enrollment admitted: %v", err)
	}
	if err := gate.TransitionDrain(1, false); err != nil {
		t.Fatal(err)
	}
	if err := gate.Admit("existing", IntentCreate); err != nil {
		t.Fatal(err)
	}
	if err := gate.TransitionDrain(2, true); err != nil {
		t.Fatal(err)
	}
	if err := gate.TransitionDrain(1, false); err == nil {
		t.Fatal("stale open accepted")
	}
	if err := gate.Admit("other", IntentCreate); err != ErrNotReady {
		t.Fatal(err)
	}
	if err := gate.Admit("existing", IntentCreate); err != nil {
		t.Fatal(err)
	}
	if err := gate.Admit("paused", IntentResume); err != nil {
		t.Fatal(err)
	}
	if err := gate.AdmitBuild("build", new(int)); err != ErrNotReady {
		t.Fatal(err)
	}
	restarted := NewGate(false, 1)
	if err := restarted.ConfigureDrain(path); err != nil {
		t.Fatal(err)
	}
	restarted.Open() // Reconstruction must not override the persisted operator fence.
	if err := restarted.Admit("fresh", IntentCreate); err != ErrNotReady {
		t.Fatalf("restart reopened: %v", err)
	}
	if err := restarted.TransitionDrain(3, false); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Admit("fresh", IntentCreate); err != nil {
		t.Fatal(err)
	}
}

func TestDrainLinearizesWithAdmissions(t *testing.T) {
	gate := NewGate(false, 0)
	if err := gate.ConfigureDrain(filepath.Join(t.TempDir(), "state")); err != nil {
		t.Fatal(err)
	}
	if err := gate.TransitionDrain(1, false); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = gate.Admit("before", IntentCreate) }()
	}
	if err := gate.TransitionDrain(2, true); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	for i := 0; i < 100; i++ {
		if err := gate.Admit("after", IntentCreate); err != ErrNotReady {
			t.Fatal("post-close admission", err)
		}
	}
}

func TestDrainPersistenceFailureStaysClosed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state")
	gate := NewGate(false, 0)
	if err := gate.ConfigureDrain(path); err != nil {
		t.Fatal(err)
	}
	if err := gate.TransitionDrain(1, false); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := gate.TransitionDrain(2, false); err == nil {
		t.Fatal("persistence failure ignored")
	}
	if err := gate.Admit("new", IntentCreate); err != ErrNotReady {
		t.Fatal("failed write reopened", err)
	}
	if err := gate.TransitionDrain(1, false); err == nil {
		t.Fatal("failed write allowed stale open")
	}
}

func TestDrainRejectsCorruptState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	if err := os.WriteFile(path, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := NewGate(false, 0).ConfigureDrain(path); err == nil {
		t.Fatal("corrupt fence ignored")
	}
}

func TestRebuildRetainsBootAdmittedBeforeSnapshot(t *testing.T) {
	gate := NewGate(true, 10)
	if err := gate.BeginBoot("boot", IntentCreate); err != nil {
		t.Fatal(err)
	}
	since := gate.BeginReconstruct()
	gate.Reconstruct(since, nil, nil)
	if !gate.Holds("boot") || gate.PendingBoots() != 1 {
		t.Fatal("in-flight boot erased by rebuild")
	}
	gate.EndBoot("boot")
	gate.Reconstruct(gate.BeginReconstruct(), nil, nil)
	if gate.Holds("boot") || gate.PendingBoots() != 0 {
		t.Fatal("settled absent boot leaked")
	}
}

func TestDrainRejectsIncompleteState(t *testing.T) {
	for _, data := range []string{`{}`, `{"revision":1}`, `{"closed":false}`, `{"revision":0,"closed":false}`} {
		path := filepath.Join(t.TempDir(), "state")
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if err := NewGate(false, 0).ConfigureDrain(path); err == nil {
			t.Fatal("incomplete state accepted", data)
		}
	}
}
