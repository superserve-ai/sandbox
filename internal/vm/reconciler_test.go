package vm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
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
	stubUnitTerminal(t, true)
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
		if err := r.markStale(context.Background(), "vm-1", ""); err == nil {
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
		if err := r.markStale(context.Background(), "vm-1", ""); err != nil {
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

// Drift 8 must not retire its marker on a release that did not happen: the
// record, its instance and its slot are still held, and only the marker keeps
// the dead-unit half coming back for them.
func TestFinalizeErrorReap_FailedDeleteKeepsMarker(t *testing.T) {
	newRec := func() *Reconciler {
		r := NewReconciler(&Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{}}, DefaultReconcilerConfig())
		r.driftSeen["errdead:vm-1"] = time.Now()
		return r
	}

	t.Run("failed delete keeps the marker", func(t *testing.T) {
		r := newRec()
		r.finalizeErrorReap(context.Background(), "vm-1", "errdead:vm-1", "stale_cleanup",
			"error record with no unit", "boltdb_error_unit_missing", errors.New("boltdb write failed"))
		r.mu.Lock()
		_, kept := r.driftSeen["errdead:vm-1"]
		r.mu.Unlock()
		if !kept {
			t.Fatal("marker must survive a failed release, or nothing revisits the held record and slot")
		}
	})

	t.Run("successful delete retires the marker", func(t *testing.T) {
		r := newRec()
		r.finalizeErrorReap(context.Background(), "vm-1", "errdead:vm-1", "stale_cleanup",
			"error record with no unit", "boltdb_error_unit_missing", nil)
		r.mu.Lock()
		_, kept := r.driftSeen["errdead:vm-1"]
		r.mu.Unlock()
		if kept {
			t.Fatal("a completed release must retire its marker")
		}
	})
}

// The retry itself: a store that refuses the delete leaves the VM fully owned,
// and a later pass — once the store recovers — completes the same cleanup.
func TestMarkStale_FailedDeleteRetriedOnLaterPass(t *testing.T) {
	stubUnitTerminal(t, true)
	path := filepath.Join(t.TempDir(), "vmd.db")
	store, err := OpenStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(VMRecord{ID: "vm-1", Status: StatusError, Namespace: "ns-1"}); err != nil {
		t.Fatal(err)
	}
	m := &Manager{
		log:   zerolog.Nop(),
		state: store,
		vms:   map[string]*VMInstance{"vm-1": {ID: "vm-1", Status: StatusError}},
	}
	r := NewReconciler(m, DefaultReconcilerConfig())

	// Pass 1: the store cannot serve the delete.
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := r.markStale(context.Background(), "vm-1", ""); err == nil {
		t.Fatal("an undeletable record must report failure")
	}
	m.mu.RLock()
	_, tracked := m.vms["vm-1"]
	m.mu.RUnlock()
	if !tracked {
		t.Fatal("a failed release must keep ownership of the instance and its slot")
	}

	// Pass 2: the store is healthy again and the same cleanup completes.
	reopened, err := OpenStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	m.state = reopened
	if err := r.markStale(context.Background(), "vm-1", ""); err != nil {
		t.Fatalf("retry must succeed once the store recovers: %v", err)
	}
	m.mu.RLock()
	_, stillTracked := m.vms["vm-1"]
	m.mu.RUnlock()
	if stillTracked {
		t.Fatal("the completed retry must drop the instance")
	}
	if rec, gerr := reopened.Get("vm-1"); gerr != nil || rec != nil {
		t.Fatalf("the completed retry must delete the record, got rec=%v err=%v", rec, gerr)
	}
}

// Only proven absence may flip a paused row to failed: a stat error that is
// not ErrNotExist says nothing about the artifact, and a present file at the
// same path is a healed or NEW pause generation the pass snapshot cannot see.
func TestStatPauseArtifact(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "vmstate.snap")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if p, cm := statPauseArtifact(f); !p || cm {
		t.Fatalf("existing artifact: got present=%v confirmedMissing=%v", p, cm)
	}
	if p, cm := statPauseArtifact(filepath.Join(dir, "absent.snap")); p || !cm {
		t.Fatalf("absent artifact: got present=%v confirmedMissing=%v", p, cm)
	}
	// A path routed THROUGH a regular file yields ENOTDIR — an error that is
	// not ErrNotExist, i.e. inconclusive. (Root-proof, unlike a chmod probe.)
	if p, cm := statPauseArtifact(filepath.Join(f, "child.snap")); p || cm {
		t.Fatalf("inconclusive stat: got present=%v confirmedMissing=%v", p, cm)
	}
}

// The drill-caught regression: a dead unit behind an active row must be
// reaped even while the in-memory instance still claims Running — nothing
// updates that record when firecracker dies out from under vmd, so trusting
// it vetoes every reap. The unit probe is the only valid oracle here.
func TestReapDeadActiveVMs_StaleRunningRecordDoesNotVetoReap(t *testing.T) {
	stubUnitTerminal(t, true) // markStale's own terminal guard must not veto the reap in tests
	newFixture := func(t *testing.T, unitDown bool) (*Reconciler, *StateStore, string, *[]string) {
		t.Helper()
		sbID := uuid.New()
		id := sbID.String()
		store, err := OpenStateStore(filepath.Join(t.TempDir(), "vmd.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })
		if err := store.Put(VMRecord{ID: id, Status: StatusRunning}); err != nil {
			t.Fatal(err)
		}
		m := &Manager{
			log:   zerolog.Nop(),
			state: store,
			// The stale claim: still Running in memory though the unit is gone.
			vms: map[string]*VMInstance{id: {ID: id, Status: StatusRunning}},
		}
		r := NewReconciler(m, DefaultReconcilerConfig())
		r.driftSeen[id] = time.Now().Add(-2 * r.cfg.GracePeriod)

		origProbe := unitFullyDownProbe
		unitFullyDownProbe = func(context.Context, string) bool { return unitDown }
		t.Cleanup(func() { unitFullyDownProbe = origProbe })

		flips := &[]string{}
		r.markFailed = func(_ context.Context, vmID string, observed db.SandboxStatus) bool {
			if observed != db.SandboxStatusActive {
				t.Errorf("Drift 1 must assert the active state it matched, got %v", observed)
			}
			*flips = append(*flips, vmID)
			return true
		}
		return r, store, id, flips
	}
	rows := func(id string) map[string]db.ListSandboxesByHostRow {
		sbID := uuid.MustParse(id)
		return map[string]db.ListSandboxesByHostRow{
			id: {Sandbox: db.Sandbox{ID: sbID, Status: db.SandboxStatusActive}},
		}
	}
	noError := func(string) bool { return false }

	t.Run("conclusively dead unit is reaped despite the Running claim", func(t *testing.T) {
		r, store, id, flips := newFixture(t, true)
		r.reapDeadActiveVMs(context.Background(), zerolog.Nop(), rows(id), map[string]bool{}, noError, time.Now())
		if len(*flips) != 1 {
			t.Fatalf("expected exactly one row flip, got %v", *flips)
		}
		if rec, _ := store.Get(id); rec != nil {
			t.Fatal("the stale record must be released")
		}
		r.mgr.mu.RLock()
		_, tracked := r.mgr.vms[id]
		r.mgr.mu.RUnlock()
		if tracked {
			t.Fatal("the stale instance must be dropped")
		}
	})

	t.Run("a relaunched unit defers the reap", func(t *testing.T) {
		r, store, id, flips := newFixture(t, false) // probe: not terminal
		r.reapDeadActiveVMs(context.Background(), zerolog.Nop(), rows(id), map[string]bool{}, noError, time.Now())
		if len(*flips) != 0 {
			t.Fatalf("a live unit must never be failed, got flips %v", *flips)
		}
		if rec, _ := store.Get(id); rec == nil {
			t.Fatal("a live VM's record must survive")
		}
	})
}

// The lock-window race: a resume + re-pause can write a NEW artifact at the
// same path while this rule waits on the lifecycle lock. The re-stat under
// the lock must see it and heal rather than fail the fresh generation; an
// inconclusive stat must defer, and only proven absence may flip the row.
func TestFailMissingSnapshots_LockWindow(t *testing.T) {
	newFixture := func(t *testing.T) (*Reconciler, string, *[]string) {
		t.Helper()
		sbID := uuid.New()
		id := sbID.String()
		m := &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{}}
		r := NewReconciler(m, DefaultReconcilerConfig())
		r.driftSeen["paused:"+id] = time.Now().Add(-2 * r.cfg.GracePeriod)
		flips := &[]string{}
		r.markFailed = func(_ context.Context, vmID string, observed db.SandboxStatus) bool {
			if observed != db.SandboxStatusPaused {
				t.Errorf("Drift 4 must assert the paused state it matched, got %v", observed)
			}
			*flips = append(*flips, vmID)
			return true
		}
		return r, id, flips
	}
	rows := func(id, snapPath string) map[string]db.ListSandboxesByHostRow {
		sbID := uuid.MustParse(id)
		return map[string]db.ListSandboxesByHostRow{
			id: {
				Sandbox:      db.Sandbox{ID: sbID, Status: db.SandboxStatusPaused, SnapshotID: pgtype.UUID{Bytes: sbID, Valid: true}},
				SnapshotPath: &snapPath,
			},
		}
	}
	stubStat := func(t *testing.T, present, missing bool) {
		t.Helper()
		orig := statPauseArtifact
		statPauseArtifact = func(string) (bool, bool) { return present, missing }
		t.Cleanup(func() { statPauseArtifact = orig })
	}

	t.Run("new generation written while waiting on the lock heals", func(t *testing.T) {
		r, id, flips := newFixture(t)
		stubStat(t, true, false) // the pause completed: artifact present at re-stat
		r.failMissingSnapshots(context.Background(), zerolog.Nop(), rows(id, filepath.Join(t.TempDir(), "gone.snap")), time.Now())
		if len(*flips) != 0 {
			t.Fatalf("a fresh pause generation must not be failed, got %v", *flips)
		}
		r.mu.Lock()
		_, kept := r.driftSeen["paused:"+id]
		r.mu.Unlock()
		if kept {
			t.Fatal("a healed sandbox must retire its drift marker")
		}
	})

	t.Run("inconclusive stat defers and keeps the marker", func(t *testing.T) {
		r, id, flips := newFixture(t)
		stubStat(t, false, false)
		r.failMissingSnapshots(context.Background(), zerolog.Nop(), rows(id, filepath.Join(t.TempDir(), "gone.snap")), time.Now())
		if len(*flips) != 0 {
			t.Fatalf("an inconclusive read must never fail a sandbox, got %v", *flips)
		}
		r.mu.Lock()
		_, kept := r.driftSeen["paused:"+id]
		r.mu.Unlock()
		if !kept {
			t.Fatal("a deferred verdict must keep the marker for the next pass")
		}
	})

	t.Run("proven absence flips the row", func(t *testing.T) {
		r, id, flips := newFixture(t)
		stubStat(t, false, true)
		r.failMissingSnapshots(context.Background(), zerolog.Nop(), rows(id, filepath.Join(t.TempDir(), "gone.snap")), time.Now())
		if len(*flips) != 1 {
			t.Fatalf("proven absence must flip exactly once, got %v", *flips)
		}
	})

	t.Run("an in-flight lifecycle op defers", func(t *testing.T) {
		r, id, flips := newFixture(t)
		stubStat(t, false, true)
		r.mgr.vmOpCh(id) <- struct{}{} // a pause/resume holds the lock
		defer func() { <-r.mgr.vmOpCh(id) }()
		r.failMissingSnapshots(context.Background(), zerolog.Nop(), rows(id, filepath.Join(t.TempDir(), "gone.snap")), time.Now())
		if len(*flips) != 0 {
			t.Fatalf("a locked VM must defer, got %v", *flips)
		}
	})
}

// stubUnitTerminal swaps the terminal-state probe so release tests do not
// depend on a live systemd.
func stubUnitTerminal(t *testing.T, terminal bool) {
	t.Helper()
	orig := unitFullyDownCtx
	unitFullyDownCtx = func(context.Context, string) bool { return terminal }
	t.Cleanup(func() { unitFullyDownCtx = orig })
}

// A release must not hand a VM's namespace, IP and tap device back to the pool
// while its unit still has a process: the next VM would claim a device the old
// Firecracker still owns. Deferring is safe because the retry comes back.
func TestMarkStaleDefersWhileUnitNotTerminal(t *testing.T) {
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "vmd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Put(VMRecord{ID: "vm-1", Status: StatusError, Namespace: "ns-1"}); err != nil {
		t.Fatal(err)
	}
	m := &Manager{
		log:   zerolog.Nop(),
		state: store,
		vms:   map[string]*VMInstance{"vm-1": {ID: "vm-1", Status: StatusError}},
	}
	r := NewReconciler(m, DefaultReconcilerConfig())

	stubUnitTerminal(t, false) // unit still deactivating
	if err := r.markStale(context.Background(), "vm-1", ""); !errors.Is(err, errUnitNotTerminal) {
		t.Fatalf("a non-terminal unit must defer the release, got %v", err)
	}
	if rec, _ := store.Get("vm-1"); rec == nil {
		t.Fatal("the record must survive a deferred release")
	}
	m.mu.RLock()
	_, tracked := m.vms["vm-1"]
	m.mu.RUnlock()
	if !tracked {
		t.Fatal("the instance and its slot must stay owned while the unit lives")
	}
	if got := r.pendingReleaseIDs(); len(got) != 1 || got[0] != "vm-1" {
		t.Fatalf("a deferred release must be remembered for retry, got %v", got)
	}

	// The unit reaches a terminal state; the deferred release completes.
	stubUnitTerminal(t, true)
	r.retryPendingReleases(context.Background())
	if rec, _ := store.Get("vm-1"); rec != nil {
		t.Fatal("the retry must release once the unit is terminal")
	}
	if got := r.pendingReleaseIDs(); len(got) != 0 {
		t.Fatalf("a completed release must be forgotten, got %v", got)
	}
}

// A deferred release must not be audited as a completed reap, and must not
// retire the drift marker: the record and its slot are still held. The guard
// makes deferral the COMMON outcome, so a rule that reported success here
// would mislabel routine cleanups, not just rare store failures.
func TestFinalizeRelease_DeferralIsNotSuccess(t *testing.T) {
	newRec := func() *Reconciler {
		r := NewReconciler(&Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{}}, DefaultReconcilerConfig())
		r.driftSeen["orphan:vm-1"] = time.Now()
		return r
	}

	t.Run("deferral keeps the marker", func(t *testing.T) {
		r := newRec()
		r.finalizeRelease(context.Background(), "vm-1", "orphan:vm-1", "orphan_stop",
			"systemd unit with no DB row", "systemd_active_db_missing", errUnitNotTerminal)
		r.mu.Lock()
		_, kept := r.driftSeen["orphan:vm-1"]
		r.mu.Unlock()
		if !kept {
			t.Fatal("a deferred release must keep its marker — the slot is still held")
		}
	})

	t.Run("completion retires the marker", func(t *testing.T) {
		r := newRec()
		r.finalizeRelease(context.Background(), "vm-1", "orphan:vm-1", "orphan_stop",
			"systemd unit with no DB row", "systemd_active_db_missing", nil)
		r.mu.Lock()
		_, kept := r.driftSeen["orphan:vm-1"]
		r.mu.Unlock()
		if kept {
			t.Fatal("a completed release must retire its marker")
		}
	})
}

// A reap whose release fails is remembered and finished on a later pass. No
// drift rule can do this: they all match on a live unit, and the reap already
// stopped it, so without this the record and its network slot are held until
// the next vmd restart.
func TestRetryPendingReleases(t *testing.T) {
	stubUnitTerminal(t, true)
	newRec := func(t *testing.T) (*Reconciler, string) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "vmd.db")
		store, err := OpenStateStore(path)
		if err != nil {
			t.Fatal(err)
		}
		// Running is the shape most reap sources leave behind — nothing
		// updates a record when firecracker dies — and the shape the old
		// status-keyed void silently discarded.
		if err := store.Put(VMRecord{ID: "vm-1", Status: StatusRunning, Namespace: "ns-1"}); err != nil {
			t.Fatal(err)
		}
		m := &Manager{
			log:   zerolog.Nop(),
			state: store,
			vms:   map[string]*VMInstance{"vm-1": {ID: "vm-1", Status: StatusRunning}},
		}
		r := NewReconciler(m, DefaultReconcilerConfig())
		// Pass 1: the store refuses the delete, so the reap is left unfinished.
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		if err := r.markStale(context.Background(), "vm-1", ""); err == nil {
			t.Fatal("an undeletable record must report failure")
		}
		return r, path
	}

	t.Run("failed release is remembered", func(t *testing.T) {
		r, _ := newRec(t)
		if got := r.pendingReleaseIDs(); len(got) != 1 || got[0] != "vm-1" {
			t.Fatalf("an abandoned release must be remembered, got %v", got)
		}
	})

	t.Run("later pass completes it", func(t *testing.T) {
		r, path := newRec(t)
		reopened, err := OpenStateStore(path)
		if err != nil {
			t.Fatal(err)
		}
		defer reopened.Close()
		r.mgr.state = reopened

		r.retryPendingReleases(context.Background())

		if got := r.pendingReleaseIDs(); len(got) != 0 {
			t.Fatalf("a completed release must be forgotten, got %v", got)
		}
		r.mgr.mu.RLock()
		_, tracked := r.mgr.vms["vm-1"]
		r.mgr.mu.RUnlock()
		if tracked {
			t.Fatal("the completed retry must drop the instance")
		}
		if rec, gerr := reopened.Get("vm-1"); gerr != nil || rec != nil {
			t.Fatalf("the completed retry must delete the record, got rec=%v err=%v", rec, gerr)
		}
	})

	t.Run("a relaunched VM voids the reap", func(t *testing.T) {
		r, path := newRec(t)
		reopened, err := OpenStateStore(path)
		if err != nil {
			t.Fatal(err)
		}
		defer reopened.Close()
		r.mgr.state = reopened
		// A relaunch REPLACES the tracked instance — that pointer swap, not
		// any status value, is what says a lifecycle op owns the VM now.
		r.mgr.vms["vm-1"] = &VMInstance{ID: "vm-1", Status: StatusRunning}

		r.retryPendingReleases(context.Background())

		if got := r.pendingReleaseIDs(); len(got) != 0 {
			t.Fatalf("a voided reap must be forgotten, got %v", got)
		}
		r.mgr.mu.RLock()
		_, tracked := r.mgr.vms["vm-1"]
		r.mgr.mu.RUnlock()
		if !tracked {
			t.Fatal("a relaunched VM must never be released by the retry")
		}
		if rec, _ := reopened.Get("vm-1"); rec == nil {
			t.Fatal("a relaunched VM's record must survive")
		}
	})
	t.Run("a relaunched then re-paused VM is never released", func(t *testing.T) {
		// The trap a unit-state void would fall into: the new generation
		// paused, so its unit is terminal — exactly like the stale entry —
		// and only instance identity tells them apart. Releasing here would
		// delete a legitimately paused record and free its slot.
		r, path := newRec(t)
		reopened, err := OpenStateStore(path)
		if err != nil {
			t.Fatal(err)
		}
		defer reopened.Close()
		r.mgr.state = reopened
		fresh := &VMInstance{ID: "vm-1", Status: StatusPaused}
		r.mgr.vms["vm-1"] = fresh
		if err := reopened.Put(VMRecord{ID: "vm-1", Status: StatusPaused, Namespace: "ns-1"}); err != nil {
			t.Fatal(err)
		}

		r.retryPendingReleases(context.Background())

		if got := r.pendingReleaseIDs(); len(got) != 0 {
			t.Fatalf("the voided entry must be forgotten, got %v", got)
		}
		if rec, _ := reopened.Get("vm-1"); rec == nil || rec.Status != StatusPaused {
			t.Fatalf("the re-paused record must survive untouched, got %v", rec)
		}
		r.mgr.mu.RLock()
		still := r.mgr.vms["vm-1"] == fresh
		r.mgr.mu.RUnlock()
		if !still {
			t.Fatal("the new generation's instance must stay tracked")
		}
	})
}

// Retiring a deferred release must retire its originating drift marker too:
// the deferring rule kept the marker alive on purpose, and a later episode of
// the same rule for the same id would inherit its timestamp — an
// unverified-orphan reap would then skip UnverifiedOrphanGrace entirely and
// beat adoption to a brand-new crash window.
func TestRetryPendingReleases_RetiresOriginMarker(t *testing.T) {
	stubUnitTerminal(t, true)
	newRec := func(t *testing.T) (*Reconciler, string, string) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "vmd.db")
		store, err := OpenStateStore(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Put(VMRecord{ID: "vm-1", Status: StatusRunning, Namespace: "ns-1"}); err != nil {
			t.Fatal(err)
		}
		m := &Manager{
			log:   zerolog.Nop(),
			state: store,
			vms:   map[string]*VMInstance{"vm-1": {ID: "vm-1", Status: StatusRunning, Unverified: true}},
		}
		r := NewReconciler(m, DefaultReconcilerConfig())
		marker := "unverifiedorphan:vm-1"
		r.driftSeen[marker] = time.Now().Add(-2 * r.cfg.UnverifiedOrphanGrace)
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		if err := r.markStale(context.Background(), "vm-1", marker); err == nil {
			t.Fatal("an undeletable record must report failure")
		}
		return r, path, marker
	}

	t.Run("successful retry clears it", func(t *testing.T) {
		r, path, marker := newRec(t)
		reopened, err := OpenStateStore(path)
		if err != nil {
			t.Fatal(err)
		}
		defer reopened.Close()
		r.mgr.state = reopened
		r.retryPendingReleases(context.Background())
		r.mu.Lock()
		_, kept := r.driftSeen[marker]
		r.mu.Unlock()
		if kept {
			t.Fatal("a completed release must retire the deferring rule's marker")
		}
	})

	t.Run("identity void clears it", func(t *testing.T) {
		r, _, marker := newRec(t)
		r.mgr.vms["vm-1"] = &VMInstance{ID: "vm-1", Status: StatusRunning} // new generation
		r.retryPendingReleases(context.Background())
		r.mu.Lock()
		_, kept := r.driftSeen[marker]
		r.mu.Unlock()
		if kept {
			t.Fatal("a voided release must retire the old episode's marker")
		}
	})
}

// The in-place claim: adoption clears Unverified and pause flips Status on
// the SAME tracked object, so pointer identity alone reads an adopted-then-
// paused VM as the original reap target — and releases a healthy paused
// record. Any observed mutation of the snapshot must void the entry.
func TestRetryPendingReleases_InPlaceAdoptionVoids(t *testing.T) {
	stubUnitTerminal(t, true)
	path := ""
	newRec := func(t *testing.T) *Reconciler {
		t.Helper()
		path = filepath.Join(t.TempDir(), "vmd.db")
		store, err := OpenStateStore(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Put(VMRecord{ID: "vm-1", Status: StatusRunning, Namespace: "ns-1"}); err != nil {
			t.Fatal(err)
		}
		m := &Manager{
			log:   zerolog.Nop(),
			state: store,
			vms:   map[string]*VMInstance{"vm-1": {ID: "vm-1", Status: StatusRunning, Unverified: true}},
		}
		r := NewReconciler(m, DefaultReconcilerConfig())
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		if err := r.markStale(context.Background(), "vm-1", ""); err == nil {
			t.Fatal("an undeletable record must report failure")
		}
		return r
	}

	t.Run("adopted then paused, same pointer, is never released", func(t *testing.T) {
		r := newRec(t)
		reopened, err := OpenStateStore(path)
		if err != nil {
			t.Fatal(err)
		}
		defer reopened.Close()
		r.mgr.state = reopened
		// Adoption clears the marker in place; a later pause flips status in
		// place. Same object throughout — only the snapshot tells the story.
		inst := r.mgr.vms["vm-1"]
		inst.mu.Lock()
		inst.Unverified = false
		inst.Status = StatusPaused
		inst.mu.Unlock()
		if err := reopened.Put(VMRecord{ID: "vm-1", Status: StatusPaused, Namespace: "ns-1"}); err != nil {
			t.Fatal(err)
		}

		r.retryPendingReleases(context.Background())

		if rec, _ := reopened.Get("vm-1"); rec == nil || rec.Status != StatusPaused {
			t.Fatalf("the adopted VM's paused record must survive untouched, got %v", rec)
		}
		if got := r.pendingReleaseIDs(); len(got) != 0 {
			t.Fatalf("the voided entry must be forgotten, got %v", got)
		}
	})

	t.Run("an unmutated stale instance is still released", func(t *testing.T) {
		r := newRec(t)
		reopened, err := OpenStateStore(path)
		if err != nil {
			t.Fatal(err)
		}
		defer reopened.Close()
		r.mgr.state = reopened

		r.retryPendingReleases(context.Background())

		if rec, _ := reopened.Get("vm-1"); rec != nil {
			t.Fatal("a genuinely stale record must still be released")
		}
	})
}

// Drift 8's deferral must carry its marker into the pending release, like
// every other deferring rule: a retry that completes without it retires the
// record while the errdead: timestamp survives, robbing the id's next Error
// episode of its grace period.
func TestFinalizeErrorReap_TagsDeferredRelease(t *testing.T) {
	stubUnitTerminal(t, true)
	path := filepath.Join(t.TempDir(), "vmd.db")
	store, err := OpenStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(VMRecord{ID: "vm-1", Status: StatusError, Namespace: "ns-1"}); err != nil {
		t.Fatal(err)
	}
	m := &Manager{
		log:   zerolog.Nop(),
		state: store,
		vms:   map[string]*VMInstance{"vm-1": {ID: "vm-1", Status: StatusError}},
	}
	r := NewReconciler(m, DefaultReconcilerConfig())
	marker := "errdead:vm-1"
	r.driftSeen[marker] = time.Now().Add(-2 * r.cfg.GracePeriod)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	staleErr := r.markStale(context.Background(), "vm-1", marker)
	if staleErr == nil {
		t.Fatal("an undeletable record must report failure")
	}
	r.finalizeErrorReap(context.Background(), "vm-1", marker, "stale_cleanup",
		"error record with no unit", "boltdb_error_unit_missing", staleErr)

	reopened, err := OpenStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	m.state = reopened
	r.retryPendingReleases(context.Background())

	if rec, _ := reopened.Get("vm-1"); rec != nil {
		t.Fatal("the retry must complete the release")
	}
	r.mu.Lock()
	_, kept := r.driftSeen[marker]
	r.mu.Unlock()
	if kept {
		t.Fatal("a completed retry must retire the Drift 8 marker it was deferred under")
	}
}

// A deferred release keeps its rule's predicate true (Running record, dead
// unit), so without standing aside the rule re-decides every pass and one
// wedged record drains the host's five-per-hour budget in minutes,
// suppressing unrelated destructive reconciliation.
func TestHasPendingReleaseStandsAside(t *testing.T) {
	stubUnitTerminal(t, false) // the unit never reaches terminal: every release defers
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "vmd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Put(VMRecord{ID: "vm-1", Status: StatusRunning, Namespace: "ns-1"}); err != nil {
		t.Fatal(err)
	}
	m := &Manager{
		log:   zerolog.Nop(),
		state: store,
		vms:   map[string]*VMInstance{"vm-1": {ID: "vm-1", Status: StatusRunning}},
	}
	r := NewReconciler(m, DefaultReconcilerConfig())

	// The rule's first decision: charge once, defer the release.
	if !r.consumeAutoFailBudget("vm-1") {
		t.Fatal("first decision must have budget")
	}
	if err := r.markStale(context.Background(), "vm-1", ""); !errors.Is(err, errUnitNotTerminal) {
		t.Fatalf("non-terminal unit must defer, got %v", err)
	}
	if !r.hasPendingRelease("vm-1") {
		t.Fatal("a deferred release must be visible to the rules")
	}

	// Later passes: the retry re-drives the release without charging budget…
	spent := len(r.autoFailLog)
	for i := 0; i < 10; i++ {
		r.retryPendingReleases(context.Background())
	}
	if len(r.autoFailLog) != spent {
		t.Fatalf("the retry must never charge budget, spent %d more", len(r.autoFailLog)-spent)
	}
	if !r.hasPendingRelease("vm-1") {
		t.Fatal("a still-deferred release must stay owned by the retry")
	}
	// …and the release completes once the unit lands, budget untouched.
	stubUnitTerminal(t, true)
	r.retryPendingReleases(context.Background())
	if r.hasPendingRelease("vm-1") {
		t.Fatal("the retry must complete once the unit is terminal")
	}
	if len(r.autoFailLog) != spent {
		t.Fatal("completion must not charge budget either")
	}
}

// Drift 1/2 grace under the BARE vm id and defer with marker "" — a
// successful markStale clears that id itself, but a void never runs
// markStale. Without clearing it here, the elapsed timestamp survives the
// void, and the relaunched VM's next death reaps instantly without grace.
func TestRetryPendingReleases_VoidClearsBareIDGrace(t *testing.T) {
	stubUnitTerminal(t, false) // defer the release
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "vmd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Put(VMRecord{ID: "vm-1", Status: StatusRunning, Namespace: "ns-1"}); err != nil {
		t.Fatal(err)
	}
	m := &Manager{
		log:   zerolog.Nop(),
		state: store,
		vms:   map[string]*VMInstance{"vm-1": {ID: "vm-1", Status: StatusRunning}},
	}
	r := NewReconciler(m, DefaultReconcilerConfig())
	// The Drift 1/2 shape: grace elapsed under the bare id, then a deferral.
	r.driftSeen["vm-1"] = time.Now().Add(-2 * r.cfg.GracePeriod)
	if err := r.markStale(context.Background(), "vm-1", ""); err == nil {
		t.Fatal("non-terminal unit must defer")
	}

	// A relaunch replaces the instance; the retry voids the stale decision.
	r.mgr.vms["vm-1"] = &VMInstance{ID: "vm-1", Status: StatusRunning}
	r.retryPendingReleases(context.Background())

	if r.hasPendingRelease("vm-1") {
		t.Fatal("the void must retire the entry")
	}
	r.mu.Lock()
	_, kept := r.driftSeen["vm-1"]
	r.mu.Unlock()
	if kept {
		t.Fatal("the void must retire the bare-id grace, or the relaunched VM's next death skips its waiting period")
	}
}

// The ABA the two-field snapshot cannot see: a lifecycle op can drive the
// SAME instance away from and back to its noted (Status, Unverified) values
// between passes. The claim hook closes the class at its choke point — every
// lifecycle op acquires the vm-op lock, and acquiring it voids any release
// deferred against the instance's predecessor.
func TestLifecycleClaimVoidsPendingRelease(t *testing.T) {
	stubUnitTerminal(t, false) // defer the release
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "vmd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Put(VMRecord{ID: "vm-1", Status: StatusPaused, Namespace: "ns-1"}); err != nil {
		t.Fatal(err)
	}
	inst := &VMInstance{ID: "vm-1", Status: StatusPaused}
	m := &Manager{
		log:   zerolog.Nop(),
		state: store,
		vms:   map[string]*VMInstance{"vm-1": inst},
	}
	r := NewReconciler(m, DefaultReconcilerConfig())
	r.driftSeen["bolt-orphan:vm-1"] = time.Now().Add(-2 * r.cfg.GracePeriod)
	if err := r.markStale(context.Background(), "vm-1", "bolt-orphan:vm-1"); err == nil {
		t.Fatal("non-terminal unit must defer")
	}

	// A resume claims the VM, drives it Running, then a pause returns it to
	// Paused — same pointer, both snapshot fields back to their noted values.
	unlock, err := m.lockVMOp(context.Background(), "vm-1")
	if err != nil {
		t.Fatal(err)
	}
	inst.mu.Lock()
	inst.Status = StatusRunning
	inst.mu.Unlock()
	unlock()
	unlock2, err := m.lockVMOp(context.Background(), "vm-1")
	if err != nil {
		t.Fatal(err)
	}
	inst.mu.Lock()
	inst.Status = StatusPaused
	inst.mu.Unlock()
	unlock2()

	if r.hasPendingRelease("vm-1") {
		t.Fatal("the claim must void the deferred release at the lock, not at state comparison")
	}
	r.mu.Lock()
	_, kept := r.driftSeen["bolt-orphan:vm-1"]
	r.mu.Unlock()
	if kept {
		t.Fatal("the void must retire the episode's marker")
	}

	// And the retry, running later with the unit now terminal, must not
	// release the healthy re-paused VM.
	stubUnitTerminal(t, true)
	r.retryPendingReleases(context.Background())
	if rec, _ := store.Get("vm-1"); rec == nil || rec.Status != StatusPaused {
		t.Fatalf("the re-paused record must survive untouched, got %v", rec)
	}
}

// A deferred release owns only the RELEASE half of Drift 1's reap: the row
// flip re-drives uncharged (nobody else moves a stuck-active row off a dead
// VM), and no second auto-fail slot is spent for the same decision.
func TestReapDeadActiveVMs_PendingReleaseRedrivesFlipUncharged(t *testing.T) {
	stubUnitTerminal(t, false) // the release stays deferred
	sbID := uuid.New()
	id := sbID.String()
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "vmd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Put(VMRecord{ID: id, Status: StatusRunning, Namespace: "ns-1"}); err != nil {
		t.Fatal(err)
	}
	m := &Manager{
		log:   zerolog.Nop(),
		state: store,
		vms:   map[string]*VMInstance{id: {ID: id, Status: StatusRunning}},
	}
	r := NewReconciler(m, DefaultReconcilerConfig())
	if err := r.markStale(context.Background(), id, ""); err == nil {
		t.Fatal("non-terminal unit must defer")
	}
	flips := 0
	r.markFailed = func(_ context.Context, vmID string, observed db.SandboxStatus) bool {
		flips++
		return true // row moved active→failed
	}
	rows := map[string]db.ListSandboxesByHostRow{
		id: {Sandbox: db.Sandbox{ID: sbID, Status: db.SandboxStatusActive}},
	}

	spent := len(r.autoFailLog)
	r.reapDeadActiveVMs(context.Background(), zerolog.Nop(), rows, map[string]bool{}, func(string) bool { return false }, time.Now())

	if flips != 1 {
		t.Fatalf("the stuck-active row must be flipped exactly once, got %d", flips)
	}
	if len(r.autoFailLog) != spent {
		t.Fatalf("re-driving an already-budgeted decision must not charge again, spent %d more", len(r.autoFailLog)-spent)
	}
	if !r.hasPendingRelease(id) {
		t.Fatal("the release must stay owned by the retry")
	}
}

// The reconciler is constructed while the gRPC server is already serving, so
// the hook's publication must be race-free against concurrent lock
// acquisitions — this test is the race detector's tripwire for a plain-field
// regression.
func TestLifecycleClaimHookPublicationIsRaceFree(t *testing.T) {
	m := &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{}}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 500; i++ {
			if unlock, err := m.lockVMOp(context.Background(), "vm-race"); err == nil {
				unlock()
			}
		}
	}()
	NewReconciler(m, DefaultReconcilerConfig()) // publishes the hook mid-traffic
	<-done
}
