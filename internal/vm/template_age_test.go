package vm

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestTemplateRestoreAge covers the phase-tag warmth proxy and the read/mark
// split: age is -1 until a restore is marked (so a failed restore can't stamp a
// false-warm reading), and per-VM resume snapshots are never tracked.
func TestTemplateRestoreAge(t *testing.T) {
	m := &Manager{
		cfg:            ManagerConfig{SnapshotDir: "/var/lib/sandbox/snapshots"},
		tplLastRestore: make(map[string]time.Time),
	}
	const tpl = "/var/lib/sandbox/snapshots/templates/tpl-abc/mem.snap"

	// Read alone must NOT record — an unmarked template stays -1 no matter how
	// many times its age is read (the pre-mark / failed-restore case).
	if age := m.templateRestoreAge(tpl); age != -1 {
		t.Fatalf("unmarked template must be -1, got %d", age)
	}
	if age := m.templateRestoreAge(tpl); age != -1 {
		t.Fatalf("reading age must not record; still -1, got %d", age)
	}
	// After a successful load is marked, age becomes a non-negative delta.
	m.markTemplateRestored(tpl)
	if age := m.templateRestoreAge(tpl); age < 0 {
		t.Fatalf("after mark, age must be non-negative, got %d", age)
	}

	// A paused sandbox's per-VM snapshot is never tracked, even if marked.
	resume := "/var/lib/sandbox/snapshots/vm123/mem.snap"
	m.markTemplateRestored(resume)
	if age := m.templateRestoreAge(resume); age != -1 {
		t.Fatalf("resume snapshot must be -1, got %d", age)
	}
	if _, keyed := m.tplLastRestore[filepath.Clean(resume)]; keyed {
		t.Fatal("resume snapshot must not be inserted into the map")
	}
	if age := m.templateRestoreAge(""); age != -1 {
		t.Fatalf("empty path must be -1, got %d", age)
	}
}

// TestPSISomeAvg10 covers the PSI parser: the "some avg10" figure is picked out
// (not "full"), and unavailable/unparseable inputs yield -1.
func TestPSISomeAvg10(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	cpu := write("cpu", "some avg10=12.34 avg60=5.00 avg300=1.00 total=999\n")
	if got := psiSomeAvg10(cpu); got != 12.34 {
		t.Fatalf("cpu: want 12.34, got %v", got)
	}
	// memory has both "some" and "full" lines — must take "some".
	mem := write("mem", "some avg10=0.50 avg60=0.10 avg300=0.00 total=1\nfull avg10=9.99 avg60=0.05 avg300=0.00 total=1\n")
	if got := psiSomeAvg10(mem); got != 0.50 {
		t.Fatalf("mem: want 0.50 (some, not full), got %v", got)
	}
	if got := psiSomeAvg10(filepath.Join(dir, "does-not-exist")); got != -1 {
		t.Fatalf("missing file: want -1, got %v", got)
	}
}
