package vm

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
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
		return db.ListSandboxesByHostRow{Status: s}
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
		uuidA: {Status: db.SandboxStatusPaused}, // live → must not move
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

// The direct-spawn service weight must track the LIVE direct-VM count (100
// per VM = one legacy peer each), clamp to cgroup v2's [100, 10000], skip the
// set-property when unchanged, and only run when managing cgroup VMs.
func TestAdjustDirectSpawnWeight(t *testing.T) {
	orig := setUnitWeight
	var got []int
	setUnitWeight = func(_ context.Context, _ string, w int) error { got = append(got, w); return nil }
	defer func() { setUnitWeight = orig }()

	tree := &cgroupTree{vms: t.TempDir()} // non-nil => managing cgroup VMs
	r := &Reconciler{mgr: &Manager{cgroups: tree, log: zerolog.Nop()}}

	sup := func(ids ...string) (map[string]bool, map[string]Supervision) {
		a := map[string]bool{}
		s := map[string]Supervision{}
		for _, id := range ids {
			a[id] = true
			s[id] = SupervisionCgroup
		}
		// A legacy unit in the set must NOT count toward the weight.
		a["legacy-1"] = true
		s["legacy-1"] = SupervisionUnit
		return a, s
	}

	// 3 live direct VMs -> 300.
	a, s := sup("d1", "d2", "d3")
	r.adjustDirectSpawnWeight(context.Background(), a, s)
	// Same count again -> no second call.
	r.adjustDirectSpawnWeight(context.Background(), a, s)
	// Zero direct VMs -> floor 100.
	r.adjustDirectSpawnWeight(context.Background(), map[string]bool{"legacy-1": true}, map[string]Supervision{"legacy-1": SupervisionUnit})
	// 200 direct VMs -> clamped to 10000.
	many := []string{}
	for i := 0; i < 200; i++ {
		many = append(many, "d"+strconv.Itoa(i))
	}
	a2, s2 := sup(many...)
	r.adjustDirectSpawnWeight(context.Background(), a2, s2)

	want := []int{300, 100, 10000}
	if len(got) != len(want) {
		t.Fatalf("set-property calls = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("call %d weight = %d, want %d (all: %v)", i, got[i], want[i], got)
		}
	}

	// Not managing cgroup VMs => never touches the weight.
	got = nil
	r2 := &Reconciler{mgr: &Manager{cgroups: nil, log: zerolog.Nop()}}
	r2.adjustDirectSpawnWeight(context.Background(), a, s)
	if len(got) != 0 {
		t.Fatalf("unarmed reconciler set weight %v, want none", got)
	}
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
	if err := r.markStale("vm-1"); err == nil {
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
	if err := r.markStale("vm-1"); err != nil {
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
			id: {ID: sbID, Status: db.SandboxStatusActive},
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

// A large stale-record backlog must not blow through the pass's own
// deadline: markStale's netns teardown and BoltDB delete run on their own
// unrelated context, so nothing but an explicit ctx.Err() check between
// candidates stops the loop once the pass budget is spent. An already-
// expired context must make the rule a no-op rather than grinding through
// every candidate anyway.
func TestReapDeadActiveVMs_ExpiredContextStopsBeforeAnyWork(t *testing.T) {
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "vmd.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ids := make([]string, 5)
	rows := make(map[string]db.ListSandboxesByHostRow, len(ids))
	for i := range ids {
		sbID := uuid.New()
		id := sbID.String()
		ids[i] = id
		if err := store.Put(VMRecord{ID: id, Status: StatusRunning}); err != nil {
			t.Fatal(err)
		}
		rows[id] = db.ListSandboxesByHostRow{ID: sbID, Status: db.SandboxStatusActive}
	}

	m := &Manager{log: zerolog.Nop(), state: store, vms: map[string]*VMInstance{}}
	r := NewReconciler(m, DefaultReconcilerConfig())
	for _, id := range ids {
		r.driftSeen[id] = time.Now().Add(-2 * r.cfg.GracePeriod)
	}

	origProbe := unitFullyDownProbe
	unitFullyDownProbe = func(context.Context, string) bool { return true } // every unit conclusively dead
	t.Cleanup(func() { unitFullyDownProbe = origProbe })

	flips := &[]string{}
	r.markFailed = func(_ context.Context, vmID string, _ db.SandboxStatus) bool {
		*flips = append(*flips, vmID)
		return true
	}

	expiredCtx, cancel := context.WithCancel(context.Background())
	cancel() // already expired before the rule ever runs

	r.reapDeadActiveVMs(expiredCtx, zerolog.Nop(), rows, map[string]bool{}, func(string) bool { return false }, time.Now())

	if len(*flips) != 0 {
		t.Fatalf("an expired pass context must stop the loop before touching any candidate, got %d flips: %v", len(*flips), *flips)
	}
	for _, id := range ids {
		if rec, _ := store.Get(id); rec == nil {
			t.Fatalf("record %s must survive an aborted pass — it was never processed, not cleaned up", id)
		}
	}
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
	// input builds a paused row plus the batched snapshot-path map that
	// resolvePausedSnapshotPaths would supply in production (path is a
	// missing file, so Drift 4 evaluates the miss).
	input := func(t *testing.T, id string) (map[string]db.ListSandboxesByHostRow, map[uuid.UUID]string) {
		t.Helper()
		sbID := uuid.MustParse(id)
		snapPath := filepath.Join(t.TempDir(), "gone.snap")
		return map[string]db.ListSandboxesByHostRow{
				id: {ID: sbID, Status: db.SandboxStatusPaused, SnapshotID: pgtype.UUID{Bytes: sbID, Valid: true}},
			}, map[uuid.UUID]string{
				sbID: snapPath,
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
		dbRows, paths := input(t, id)
		r.failMissingSnapshots(context.Background(), zerolog.Nop(), dbRows, paths, time.Now())
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
		dbRows, paths := input(t, id)
		r.failMissingSnapshots(context.Background(), zerolog.Nop(), dbRows, paths, time.Now())
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
		dbRows, paths := input(t, id)
		r.failMissingSnapshots(context.Background(), zerolog.Nop(), dbRows, paths, time.Now())
		if len(*flips) != 1 {
			t.Fatalf("proven absence must flip exactly once, got %v", *flips)
		}
	})

	t.Run("an in-flight lifecycle op defers", func(t *testing.T) {
		r, id, flips := newFixture(t)
		stubStat(t, false, true)
		r.mgr.vmOpCh(id) <- struct{}{} // a pause/resume holds the lock
		defer func() { <-r.mgr.vmOpCh(id) }()
		dbRows, paths := input(t, id)
		r.failMissingSnapshots(context.Background(), zerolog.Nop(), dbRows, paths, time.Now())
		if len(*flips) != 0 {
			t.Fatalf("a locked VM must defer, got %v", *flips)
		}
	})
}

// --- Mode-aware release rules: a cgroup VM must never be released on the
// unit oracle's vacuous answers (no firecracker@ unit exists for it). ---

// shimSystemctlDown puts a systemctl on PATH that answers every unit query
// with the conclusively-down answers a NONEXISTENT unit produces: exactly the
// vacuous evidence these rules must refuse to release cgroup VMs on.
func shimSystemctlDown(t *testing.T) {
	t.Helper()
	shim := t.TempDir()
	script := "#!/bin/sh\ncase \"$1\" in\nlist-units) exit 0 ;;\nshow) echo inactive ;;\nis-active) exit 3 ;;\nesac\nexit 0\n"
	if err := os.WriteFile(filepath.Join(shim, "systemctl"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shim+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// cgroupFixtureTree builds a delegated-subtree stand-in with one per-VM group
// whose cgroup.events reads as given.
func cgroupFixtureTree(t *testing.T, id, events string) *cgroupTree {
	t.Helper()
	vms := t.TempDir()
	if err := os.MkdirAll(filepath.Join(vms, id), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vms, id, "cgroup.events"), []byte(events), 0o644); err != nil {
		t.Fatal(err)
	}
	return &cgroupTree{vms: vms}
}

func setCgroupPopulated(t *testing.T, tree *cgroupTree, id string, populated bool) {
	t.Helper()
	v := "0"
	if populated {
		v = "1"
	}
	if err := os.WriteFile(filepath.Join(tree.vms, id, "cgroup.events"), []byte("populated "+v+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The prod-reachable shape releaseFailedRestore parks: an Error record in
// cgroup mode whose FC is still alive. Driving the REAL pass (BoltDB-only
// mode): the error rule must stop by the scanned mode and must not release
// the record while the group stays populated; once the group is conclusively
// empty, the next pass completes the release.
func TestRunOnce_ErrorCgroupVM_ModeAwareStopAndRelease(t *testing.T) {
	shimSystemctlDown(t)
	id := uuid.New().String()
	tree := cgroupFixtureTree(t, id, "populated 1\n")

	store, err := OpenStateStore(filepath.Join(t.TempDir(), "vmd.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Put(VMRecord{ID: id, Status: StatusError, Supervision: SupervisionCgroup, Namespace: "ns-1"}); err != nil {
		t.Fatal(err)
	}
	runDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(runDir, id), 0o755); err != nil {
		t.Fatal(err)
	}
	m := &Manager{
		log:     zerolog.Nop(),
		state:   store,
		netMgr:  nil,
		cgroups: tree,
		cfg:     ManagerConfig{RunDir: runDir},
		vms:     map[string]*VMInstance{},
	}
	r := NewReconciler(m, DefaultReconcilerConfig())
	var stops []Supervision
	r.stopVM = func(_ context.Context, _ string, sup Supervision) error {
		stops = append(stops, sup)
		return nil // reported stopped — but the group stays populated (wedged FC)
	}
	past := time.Now().Add(-2 * r.cfg.GracePeriod)
	r.driftSeen["errunit:"+id] = past

	r.runOnce(context.Background())
	if len(stops) != 1 || stops[0] != SupervisionCgroup {
		t.Fatalf("the error rule must stop by the scanned mode (cgroup), got %v", stops)
	}
	if rec, gerr := store.Get(id); gerr != nil || rec == nil {
		t.Fatal("a populated group must veto the release — record was freed under a live FC")
	}

	// The FC finally exits; the dead half completes the release.
	setCgroupPopulated(t, tree, id, false)
	r.driftSeen["errdead:"+id] = past
	r.runOnce(context.Background())
	if rec, gerr := store.Get(id); gerr == nil && rec != nil {
		t.Fatalf("a conclusively-empty group must release the record, still present: %+v", rec)
	}
}

// Drift 7b on a direct-spawn crash-window orphan: stop must dispatch by mode,
// and the release needs the group conclusively empty — a stop that could not
// kill the FC must leave record, instance and slot owned for the next pass.
func TestReapUnverifiedOrphans_CgroupOrphan_ModeAwareStopAndProof(t *testing.T) {
	id := uuid.New().String()
	tree := cgroupFixtureTree(t, id, "populated 1\n")
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "vmd.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Put(VMRecord{ID: id, Status: StatusRunning, Unverified: true, Supervision: SupervisionCgroup}); err != nil {
		t.Fatal(err)
	}
	inst := &VMInstance{ID: id, Status: StatusRunning, Unverified: true, Supervision: SupervisionCgroup}
	m := &Manager{log: zerolog.Nop(), state: store, cgroups: tree, vms: map[string]*VMInstance{id: inst}}
	r := NewReconciler(m, DefaultReconcilerConfig())
	var stops []Supervision
	r.stopVM = func(_ context.Context, _ string, sup Supervision) error {
		stops = append(stops, sup)
		return nil
	}
	r.driftSeen["unverifiedorphan:"+id] = time.Now().Add(-2 * r.cfg.UnverifiedOrphanGrace)

	sbID := uuid.MustParse(id)
	rows := map[string]db.ListSandboxesByHostRow{
		id: {ID: sbID, Status: db.SandboxStatusPaused},
	}
	active := map[string]bool{id: true}
	sup := map[string]Supervision{id: SupervisionCgroup}

	r.reapUnverifiedOrphans(context.Background(), zerolog.Nop(), rows, active, sup, time.Now())
	if len(stops) != 1 || stops[0] != SupervisionCgroup {
		t.Fatalf("orphan stop must dispatch by mode, got %v", stops)
	}
	if rec, gerr := store.Get(id); gerr != nil || rec == nil {
		t.Fatal("a populated group must veto the release")
	}

	setCgroupPopulated(t, tree, id, false)
	r.driftSeen["unverifiedorphan:"+id] = time.Now().Add(-2 * r.cfg.UnverifiedOrphanGrace)
	r.reapUnverifiedOrphans(context.Background(), zerolog.Nop(), rows, active, sup, time.Now())
	if rec, gerr := store.Get(id); gerr == nil && rec != nil {
		t.Fatal("a conclusively-empty group must complete the release")
	}
}

// Drift 1b on a direct-spawn empty shell: the probe finds no microVM behind
// the socket, but the stop must dispatch by mode and the row flip + release
// need the group conclusively empty.
func TestFailEmptyShells_CgroupShell_ModeAwareStopAndProof(t *testing.T) {
	id := uuid.New().String()
	tree := cgroupFixtureTree(t, id, "populated 1\n")
	// A short base dir: the rule dials RunDir/<id>/firecracker.sock, and
	// t.TempDir's long test-name path would blow the 108-char sun_path cap.
	runDir, err := os.MkdirTemp("", "fes")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(runDir) })
	if err := os.MkdirAll(filepath.Join(runDir, id), 0o755); err != nil {
		t.Fatal(err)
	}
	// A fake FC API socket answering "Not started" — the empty-shell answer.
	sock := filepath.Join(runDir, id, "firecracker.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"x","state":"Not started"}`))
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	store, serr := OpenStateStore(filepath.Join(t.TempDir(), "vmd.db"))
	if serr != nil {
		t.Fatal(serr)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Put(VMRecord{ID: id, Status: StatusRunning, Supervision: SupervisionCgroup}); err != nil {
		t.Fatal(err)
	}
	m := &Manager{log: zerolog.Nop(), state: store, cgroups: tree, cfg: ManagerConfig{RunDir: runDir}, vms: map[string]*VMInstance{}}
	r := NewReconciler(m, DefaultReconcilerConfig())
	var stops []Supervision
	r.stopVM = func(_ context.Context, _ string, sup Supervision) error {
		stops = append(stops, sup)
		return nil
	}
	r.driftSeen["fcempty:"+id] = time.Now().Add(-2 * r.cfg.GracePeriod)

	sbID := uuid.MustParse(id)
	rows := map[string]db.ListSandboxesByHostRow{
		id: {ID: sbID, Status: db.SandboxStatusActive},
	}
	active := map[string]bool{id: true}
	sup := map[string]Supervision{id: SupervisionCgroup}

	r.failEmptyShells(context.Background(), zerolog.Nop(), rows, active, sup, time.Now())
	if len(stops) != 1 || stops[0] != SupervisionCgroup {
		t.Fatalf("empty-shell stop must dispatch by mode, got %v", stops)
	}
	if rec, gerr := store.Get(id); gerr != nil || rec == nil {
		t.Fatal("a populated group must veto the flip and release")
	}

	setCgroupPopulated(t, tree, id, false)
	r.driftSeen["fcempty:"+id] = time.Now().Add(-2 * r.cfg.GracePeriod)
	r.failEmptyShells(context.Background(), zerolog.Nop(), rows, active, sup, time.Now())
	if rec, gerr := store.Get(id); gerr == nil && rec != nil {
		t.Fatal("a conclusively-empty group must complete the flip and release")
	}
}

// The rollback drain: with direct spawn disarmed, a paused cgroup record must
// demote to unit supervision — durably, and in the tracked instance when one
// exists — but ONLY with the group conclusively empty and no lifecycle op in
// flight. (Dir removal is not asserted: the fixture's cgroup.events is a real
// file, so rmdir legitimately fails where a real cgroup's would succeed.)
func TestDemotePausedCgroupRecords(t *testing.T) {
	newFixture := func(t *testing.T, events string, inst *VMInstance) (*Reconciler, *StateStore, string) {
		t.Helper()
		id := uuid.New().String()
		tree := cgroupFixtureTree(t, id, events)
		store, err := OpenStateStore(filepath.Join(t.TempDir(), "vmd.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })
		if err := store.Put(VMRecord{ID: id, Status: StatusPaused, Supervision: SupervisionCgroup}); err != nil {
			t.Fatal(err)
		}
		m := &Manager{log: zerolog.Nop(), state: store, cgroups: tree, vms: map[string]*VMInstance{}}
		if inst != nil {
			inst.ID = id
			m.vms[id] = inst
		}
		return NewReconciler(m, DefaultReconcilerConfig()), store, id
	}
	supOf := func(store *StateStore, id string) Supervision {
		rec, err := store.Get(id)
		if err != nil || rec == nil {
			return Supervision("gone")
		}
		return rec.Supervision
	}

	t.Run("empty group demotes the tracked instance and the record", func(t *testing.T) {
		inst := &VMInstance{Status: StatusPaused, Supervision: SupervisionCgroup}
		r, store, id := newFixture(t, "populated 0\n", inst)
		r.demotePausedCgroupRecords(context.Background(), zerolog.Nop())
		if got := supOf(store, id); got != SupervisionUnit {
			t.Fatalf("record must demote to unit, got %q", got)
		}
		inst.mu.RLock()
		got := inst.Supervision
		inst.mu.RUnlock()
		if got != SupervisionUnit {
			t.Fatalf("tracked instance must demote too, got %q", got)
		}
	})

	t.Run("untracked record demotes via the store", func(t *testing.T) {
		r, store, id := newFixture(t, "populated 0\n", nil)
		r.demotePausedCgroupRecords(context.Background(), zerolog.Nop())
		if got := supOf(store, id); got != SupervisionUnit {
			t.Fatalf("record must demote to unit, got %q", got)
		}
	})

	t.Run("populated group defers", func(t *testing.T) {
		r, store, id := newFixture(t, "populated 1\n", nil)
		r.demotePausedCgroupRecords(context.Background(), zerolog.Nop())
		if got := supOf(store, id); got != SupervisionCgroup {
			t.Fatalf("a populated group must defer the demotion, got %q", got)
		}
	})

	t.Run("malformed events defers (unprovably empty)", func(t *testing.T) {
		r, store, id := newFixture(t, "frozen 0\n", nil)
		r.demotePausedCgroupRecords(context.Background(), zerolog.Nop())
		if got := supOf(store, id); got != SupervisionCgroup {
			t.Fatalf("an unprovably-empty group must defer the demotion, got %q", got)
		}
	})

	t.Run("a resume that raced to Running defers", func(t *testing.T) {
		inst := &VMInstance{Status: StatusRunning, Supervision: SupervisionCgroup}
		r, store, id := newFixture(t, "populated 0\n", inst)
		r.demotePausedCgroupRecords(context.Background(), zerolog.Nop())
		if got := supOf(store, id); got != SupervisionCgroup {
			t.Fatalf("a running instance must veto the demotion, got %q", got)
		}
		inst.mu.RLock()
		got := inst.Supervision
		inst.mu.RUnlock()
		if got != SupervisionCgroup {
			t.Fatal("the running instance's mode must be untouched")
		}
	})

	t.Run("an in-flight lifecycle op defers", func(t *testing.T) {
		r, store, id := newFixture(t, "populated 0\n", nil)
		r.mgr.vmOpCh(id) <- struct{}{}
		defer func() { <-r.mgr.vmOpCh(id) }()
		r.demotePausedCgroupRecords(context.Background(), zerolog.Nop())
		if got := supOf(store, id); got != SupervisionCgroup {
			t.Fatalf("a locked VM must defer, got %q", got)
		}
	})
}

// The release chokepoint must refuse unknown supervision modes: every rule
// proves death via the unit and cgroup oracles, and a mode this binary
// predates may supervise a live FC neither can see. The record, its instance
// and its slot must all stay owned.
func TestMarkStaleRefusesUnknownSupervision(t *testing.T) {
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "vmd.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Put(VMRecord{ID: "vm-1", Status: StatusError, Supervision: Supervision("checkpointed"), Namespace: "ns-1"}); err != nil {
		t.Fatal(err)
	}
	m := &Manager{log: zerolog.Nop(), state: store, vms: map[string]*VMInstance{
		"vm-1": {ID: "vm-1", Status: StatusError, Supervision: Supervision("checkpointed")},
	}}
	r := NewReconciler(m, DefaultReconcilerConfig())

	if err := r.markStale("vm-1"); err == nil {
		t.Fatal("an unknown supervision mode must refuse release, not delete the record")
	}
	if rec, gerr := store.Get("vm-1"); gerr != nil || rec == nil {
		t.Fatal("the record must survive the refusal")
	}
	if _, tracked := m.vms["vm-1"]; !tracked {
		t.Fatal("the instance must stay tracked")
	}
}
