package vm

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/db"
)

const (
	uuidA = "11111111-1111-1111-1111-111111111111"
	uuidB = "22222222-2222-2222-2222-222222222222"
	uuidC = "33333333-3333-3333-3333-333333333333"
)

// scanSandboxDirs enumerates only UUID-named dirs and merges a sandbox's dirs
// across roots, so template/templates/build-* and stray files are ignored.
func TestScanSandboxDirs_UUIDOnly_MergesRoots(t *testing.T) {
	runDir := t.TempDir()
	snapDir := t.TempDir()

	for _, name := range []string{uuidA, uuidB, templateDirName, TemplatesDirName, "build-xyz"} {
		if err := os.MkdirAll(filepath.Join(runDir, name), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", name, err)
		}
	}
	if err := os.WriteFile(filepath.Join(runDir, "stray.file"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write stray: %v", err)
	}
	// uuidA also under snapshots (merge), plus a snapshots-only uuidC.
	for _, name := range []string{uuidA, uuidC} {
		if err := os.MkdirAll(filepath.Join(snapDir, name), 0o755); err != nil {
			t.Fatalf("mkdir snap %s: %v", name, err)
		}
	}

	got := scanSandboxDirs(runDir, snapDir)

	if len(got) != 3 {
		t.Fatalf("want 3 sandbox dirs, got %d: %v", len(got), keysOf(got))
	}
	for _, id := range []string{uuidA, uuidB, uuidC} {
		if _, ok := got[id]; !ok {
			t.Errorf("missing %s", id)
		}
	}
	if n := len(got[uuidA].paths); n != 2 {
		t.Errorf("uuidA should span both roots (2 paths), got %d", n)
	}
	for _, reserved := range []string{templateDirName, TemplatesDirName, "build-xyz", "stray.file"} {
		if _, ok := got[reserved]; ok {
			t.Errorf("reserved/non-uuid entry %q was enumerated", reserved)
		}
	}
}

// selectOrphanDirs keeps live and grace-window sandboxes, drops orphans, and
// ignores dirs newer than the pass snapshot.
func TestSelectOrphanDirs(t *testing.T) {
	cutoff := time.Unix(1_000_000, 0)
	old := cutoff.Add(-time.Hour)
	fresh := cutoff.Add(time.Hour)

	onDisk := map[string]sandboxDirInfo{
		uuidA: {mtime: old},   // not in keep, older than cutoff → orphan
		uuidB: {mtime: old},   // in keep → kept
		uuidC: {mtime: fresh}, // not in keep but within grace (in-flight create) → kept
	}
	keep := map[string]struct{}{uuidB: {}}

	got := selectOrphanDirs(onDisk, keep, cutoff)
	if len(got) != 1 || got[0] != uuidA {
		t.Fatalf("want [%s], got %v", uuidA, got)
	}
}

// dirSize counts allocated blocks (du-style), not apparent length, so a sparse
// overlay's huge logical size isn't reported as reclaimable.
func TestDirSize(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "real"), make([]byte, 8192), 0o600); err != nil {
		t.Fatal(err)
	}
	// Apparent size 1 GiB, but Truncate allocates no blocks → sparse.
	f, err := os.Create(filepath.Join(dir, "sparse.ext4"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(1 << 30); err != nil {
		t.Fatal(err)
	}
	f.Close()

	got := dirSize(context.Background(), []string{dir})
	if got == 0 {
		t.Error("dirSize = 0; the real file's allocated blocks should be counted")
	}
	if got >= 1<<30 {
		t.Errorf("dirSize = %d; want << 1 GiB (sparse apparent size must not be counted)", got)
	}
}

// diskKeepSet is the complete reclaim guard: it must keep a dir live via ANY
// source — a non-destroyed DB row (any status, including failed, which retains
// billed disk until delete), recently-destroyed grace, or an active unit — and
// reclaim only UUIDs present in no source at all.
func TestDiskKeepSet(t *testing.T) {
	row := func(s db.SandboxStatus) db.ListSandboxesByHostRow {
		return db.ListSandboxesByHostRow{Sandbox: db.Sandbox{Status: s}}
	}
	const (
		recentID = "44444444-4444-4444-4444-444444444444" // recently destroyed → kept
		activeID = "55555555-5555-5555-5555-555555555555" // running unit, no row → kept
		orphanID = "66666666-6666-6666-6666-666666666666" // in no source → reclaimable
	)
	dbSandboxes := map[string]db.ListSandboxesByHostRow{
		uuidA: row(db.SandboxStatusActive), // live → kept
		uuidB: row(db.SandboxStatusPaused), // live → kept
		uuidC: row(db.SandboxStatusFailed), // failed retains billed disk → kept until delete
	}
	recent := []uuid.UUID{uuid.MustParse(recentID)}
	active := map[string]bool{activeID: true}

	keep := diskKeepSet(dbSandboxes, recent, active)

	for _, id := range []string{uuidA, uuidB, uuidC, recentID, activeID} {
		if _, ok := keep[id]; !ok {
			t.Errorf("%s should be in keep-set", id)
		}
	}
	if _, ok := keep[orphanID]; ok {
		t.Errorf("%s should NOT be in keep-set (no source → reclaimable)", orphanID)
	}
}

func TestKeepSetCollapsed(t *testing.T) {
	cases := []struct {
		name      string
		prev, cur int
		want      bool
	}{
		{"first pass", -1, 50, false},
		{"prev drained", 0, 0, false},
		{"stable", 40, 40, false},
		{"exactly half", 40, 20, false},
		{"more than half gone", 40, 19, true},
		{"vanished", 40, 0, true},
		{"growth", 10, 50, false},
	}
	for _, c := range cases {
		if got := keepSetCollapsed(c.prev, c.cur); got != c.want {
			t.Errorf("%s: keepSetCollapsed(%d,%d)=%v want %v", c.name, c.prev, c.cur, got, c.want)
		}
	}
}

func TestQuarantineDir(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, uuidA)
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "overlay.ext4"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := quarantineDir(src, "2026-06-20"); err != nil {
		t.Fatalf("quarantineDir: %v", err)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Error("source dir should be gone after quarantine")
	}
	if _, err := os.Stat(filepath.Join(root, ".trash", "2026-06-20", uuidA, "overlay.ext4")); err != nil {
		t.Errorf("dir should be under .trash: %v", err)
	}
}

func TestQuarantineDir_RejectsNonUUID(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "templates")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := quarantineDir(src, "2026-06-20"); err == nil {
		t.Error("expected error quarantining a non-uuid dir")
	}
	if _, err := os.Stat(src); err != nil {
		t.Error("non-uuid dir must not be moved")
	}
}

func TestSweepTrash_RemovesExpiredKeepsRecent(t *testing.T) {
	runDir := t.TempDir()
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC) // retention 72h → cutoff 06-17 12:00
	mk := func(label string, mtime time.Time) string {
		p := filepath.Join(runDir, ".trash", label)
		if err := os.MkdirAll(filepath.Join(p, uuidA), 0o755); err != nil {
			t.Fatal(err)
		}
		// Age is taken from the bucket's mtime, not its label.
		if err := os.Chtimes(p, mtime, mtime); err != nil {
			t.Fatal(err)
		}
		return p
	}
	expired := mk("2026-06-15", now.Add(-96*time.Hour)) // soaked 96h → swept
	// Soaked only 48h: a date-label sweep could remove this early, but by actual
	// mtime it has not reached the 72h window, so the full retention is honored.
	young := mk("2026-06-18", now.Add(-48*time.Hour))

	r := &Reconciler{
		mgr: &Manager{cfg: ManagerConfig{RunDir: runDir}, log: zerolog.Nop()},
		cfg: ReconcilerConfig{DiskTrashRetention: 72 * time.Hour},
	}
	r.sweepTrash(now)

	if _, err := os.Stat(expired); !os.IsNotExist(err) {
		t.Error("quarantine soaked 96h should be removed")
	}
	if _, err := os.Stat(young); err != nil {
		t.Error("quarantine soaked only 48h should be kept (full 72h retention honored)")
	}
}

func TestReclaimDiskOrphans_QuarantinesUpToBudget(t *testing.T) {
	runDir := t.TempDir()
	ids := []string{uuidA, uuidB, uuidC}
	onDisk := map[string]sandboxDirInfo{}
	for _, id := range ids {
		p := filepath.Join(runDir, id)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		onDisk[id] = sandboxDirInfo{paths: []string{p}}
	}

	r := &Reconciler{
		mgr: &Manager{cfg: ManagerConfig{RunDir: runDir}, log: zerolog.Nop()},
		cfg: ReconcilerConfig{DiskDeleteBudget: 2},
	}
	r.reclaimDiskOrphans(context.Background(), time.Date(2026, 6, 20, 0, 0, 0, 0, time.UTC), ids, onDisk, map[string]db.ListSandboxesByHostRow{})

	// Budget 2: the first two (slice order) move, the third stays.
	if _, err := os.Stat(filepath.Join(runDir, uuidA)); !os.IsNotExist(err) {
		t.Error("uuidA should have been quarantined")
	}
	if _, err := os.Stat(filepath.Join(runDir, uuidC)); err != nil {
		t.Error("uuidC should remain (over budget)")
	}
	entries, _ := os.ReadDir(filepath.Join(runDir, ".trash", "2026-06-20"))
	if len(entries) != 2 {
		t.Errorf(".trash has %d entries, want 2 (budget)", len(entries))
	}
}

// The reclaim-time tripwire must refuse to move a dir whose UUID still has a
// live (non-destroyed) DB row, even if it reached the orphan list.
func TestReclaimDiskOrphans_SkipsLiveSandbox(t *testing.T) {
	runDir := t.TempDir()
	ids := []string{uuidA, uuidB}
	onDisk := map[string]sandboxDirInfo{}
	for _, id := range ids {
		p := filepath.Join(runDir, id)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		onDisk[id] = sandboxDirInfo{paths: []string{p}}
	}
	dbSandboxes := map[string]db.ListSandboxesByHostRow{
		uuidA: {Sandbox: db.Sandbox{Status: db.SandboxStatusPaused}}, // live → must not move
	}

	r := &Reconciler{
		mgr: &Manager{cfg: ManagerConfig{RunDir: runDir}, log: zerolog.Nop()},
		cfg: ReconcilerConfig{DiskDeleteBudget: 10},
	}
	r.reclaimDiskOrphans(context.Background(), time.Date(2026, 6, 20, 0, 0, 0, 0, time.UTC), ids, onDisk, dbSandboxes)

	if _, err := os.Stat(filepath.Join(runDir, uuidA)); err != nil {
		t.Error("live sandbox dir (uuidA) must NOT be quarantined")
	}
	if _, err := os.Stat(filepath.Join(runDir, uuidB)); !os.IsNotExist(err) {
		t.Error("orphan uuidB should have been quarantined")
	}
}

// A cancelled pass (e.g. runTimeout) must stop before any destructive move,
// even with budget to spare.
func TestReclaimDiskOrphans_StopsOnCancel(t *testing.T) {
	runDir := t.TempDir()
	ids := []string{uuidA, uuidB}
	onDisk := map[string]sandboxDirInfo{}
	for _, id := range ids {
		p := filepath.Join(runDir, id)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		onDisk[id] = sandboxDirInfo{paths: []string{p}}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	r := &Reconciler{
		mgr: &Manager{cfg: ManagerConfig{RunDir: runDir}, log: zerolog.Nop()},
		cfg: ReconcilerConfig{DiskDeleteBudget: 10},
	}
	r.reclaimDiskOrphans(ctx, time.Date(2026, 6, 20, 0, 0, 0, 0, time.UTC), ids, onDisk, map[string]db.ListSandboxesByHostRow{})

	for _, id := range ids {
		if _, err := os.Stat(filepath.Join(runDir, id)); err != nil {
			t.Errorf("%s must not be moved when ctx is cancelled", id)
		}
	}
	if _, err := os.Stat(filepath.Join(runDir, trashDirName)); !os.IsNotExist(err) {
		t.Error("no .trash should be created when ctx is cancelled")
	}
}

func keysOf(m map[string]sandboxDirInfo) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// The crash-window orphan rule (Drift 7b) must lose the race with adoption: a
// retry re-verifies and adopts such a VM, keeping the guest's work, so the
// reaper may only act on orphans nobody came back for. These pin the four
// boundaries — the grace one is the regression guard for that race.
func TestUnverifiedOrphanGrace(t *testing.T) {
	newRec := func(cfg ReconcilerConfig, inst *VMInstance) *Reconciler {
		m := &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{}}
		if inst != nil {
			m.vms[inst.ID] = inst
		}
		return NewReconciler(m, cfg)
	}
	cfg := DefaultReconcilerConfig()

	t.Run("verified Running record is never a candidate", func(t *testing.T) {
		r := newRec(cfg, &VMInstance{ID: "vm-1", Status: StatusRunning}) // no marker
		if r.mgr.instanceUnverifiedRunning("vm-1") {
			t.Fatal("a verified Running record must stay protected by the Running deference")
		}
	})

	t.Run("unverified Running record is a candidate", func(t *testing.T) {
		r := newRec(cfg, &VMInstance{ID: "vm-1", Status: StatusRunning, Unverified: true})
		if !r.mgr.instanceUnverifiedRunning("vm-1") {
			t.Fatal("an unverified Running record must be reapable — Running was never proven")
		}
	})

	t.Run("adoption wins: recent orphan is left alone", func(t *testing.T) {
		r := newRec(cfg, &VMInstance{ID: "vm-1", Status: StatusRunning, Unverified: true})
		now := time.Now()
		if r.graceElapsed("unverifiedorphan:vm-1", now, cfg.UnverifiedOrphanGrace) {
			t.Fatal("first sighting must never reap")
		}
		// Well past the DEFAULT grace, nowhere near the orphan grace: this is
		// the window in which a customer retry must still be able to adopt.
		if r.graceElapsed("unverifiedorphan:vm-1", now.Add(5*time.Minute), cfg.UnverifiedOrphanGrace) {
			t.Fatal("reaper must not outrace adoption — 5min-old orphan must survive")
		}
	})

	t.Run("abandoned orphan is reaped once the window passes", func(t *testing.T) {
		r := newRec(cfg, &VMInstance{ID: "vm-1", Status: StatusRunning, Unverified: true})
		now := time.Now()
		r.graceElapsed("unverifiedorphan:vm-1", now, cfg.UnverifiedOrphanGrace) // first sighting
		if !r.graceElapsed("unverifiedorphan:vm-1", now.Add(cfg.UnverifiedOrphanGrace), cfg.UnverifiedOrphanGrace) {
			t.Fatal("an abandoned orphan must be reaped once its window elapses")
		}
	})

	t.Run("orphan grace far exceeds the default", func(t *testing.T) {
		// The whole design rests on this ordering; a future tuning change that
		// inverts it silently reintroduces the reap-before-adopt data loss.
		if cfg.UnverifiedOrphanGrace <= cfg.GracePeriod {
			t.Fatalf("orphan grace (%s) must far exceed the default grace (%s)",
				cfg.UnverifiedOrphanGrace, cfg.GracePeriod)
		}
	})
}

// markStale's delete is the gate for the whole cleanup: the map entry and the
// network slot only go once the record is durably gone. Callers that stop the
// unit first retire the condition their rule matches on, so a swallowed
// failure would be reported as a completed reap and never revisited.
func TestMarkStaleReportsDeleteFailure(t *testing.T) {
	newRec := func(t *testing.T) (*Reconciler, *StateStore) {
		t.Helper()
		st, err := OpenStateStore(filepath.Join(t.TempDir(), "vmd.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.Close() })
		if err := st.Put(VMRecord{ID: "vm-1", Status: StatusRunning, Unverified: true}); err != nil {
			t.Fatal(err)
		}
		m := &Manager{
			log:   zerolog.Nop(),
			state: st,
			vms:   map[string]*VMInstance{"vm-1": {ID: "vm-1", Status: StatusRunning, Unverified: true}},
		}
		return NewReconciler(m, DefaultReconcilerConfig()), st
	}

	t.Run("failure leaves the instance tracked", func(t *testing.T) {
		r, st := newRec(t)
		if err := st.Close(); err != nil { // the store is gone; the delete cannot land
			t.Fatal(err)
		}
		if err := r.markStale("vm-1"); err == nil {
			t.Fatal("an undeletable record must be reported, not reaped silently")
		}
		r.mgr.mu.RLock()
		_, tracked := r.mgr.vms["vm-1"]
		r.mgr.mu.RUnlock()
		if !tracked {
			t.Fatal("the instance must stay tracked: dropping it while the record survives lets reattach resurrect it")
		}
	})

	t.Run("success drops the instance", func(t *testing.T) {
		r, _ := newRec(t)
		if err := r.markStale("vm-1"); err != nil {
			t.Fatalf("markStale: %v", err)
		}
		r.mgr.mu.RLock()
		_, tracked := r.mgr.vms["vm-1"]
		r.mgr.mu.RUnlock()
		if tracked {
			t.Fatal("a deleted record must not leave its instance tracked")
		}
	})
}
