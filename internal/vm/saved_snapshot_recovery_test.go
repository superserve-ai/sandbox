package vm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/presence"
)

// frozenSourceRecord makes the seeded source one whose overlay an earlier
// pause froze under its token, as the record and the manifest beside the
// overlay both say, with a guest that freezes and thaws on request.
func frozenSourceRecord(t *testing.T, m *Manager, inst *VMInstance) (overlay string) {
	t.Helper()
	overlay = inst.MemFilePath
	prior := WallClockManifest{Version: WallClockManifestVersion, ArtifactID: "art-a", WorkloadFrozen: true, GuestCorrectsClock: true, FreezeToken: "tok-a"}
	if err := WriteWallClockManifest(overlay, prior); err != nil {
		t.Fatal(err)
	}
	yes := true
	inst.mu.Lock()
	inst.IP = "10.0.0.2"
	inst.CorrectsWallClock, inst.SnapshotWorkloadFrozen = &yes, &yes
	inst.FreezeToken, inst.ArtifactID = "tok-a", "art-a"
	inst.mu.Unlock()
	if !m.persistState(inst) {
		t.Fatal("record not persisted")
	}
	origF, origT, origR := boxdFreezeGuest, boxdThawGuest, boxdGuestRunning
	t.Cleanup(func() { boxdFreezeGuest, boxdThawGuest, boxdGuestRunning = origF, origT, origR })
	boxdFreezeGuest = func(_ context.Context, _, token string) (freezeEcho, error) {
		return freezeEcho{Version: WakeProtocolVersion, Token: token}, nil
	}
	boxdThawGuest = func(context.Context, string, string) error { return nil }
	boxdGuestRunning = func(context.Context, string) error { return nil }
	m.cfg.GuestClockFreezeEnabled = true
	m.clockRealtimeCapable.Store(true)
	return overlay
}

// refreshPresence is the presence map's rewrite by the diff, after the intent.
func refreshPresence(t *testing.T, overlay string) {
	t.Helper()
	later := time.Now().Add(time.Second)
	if err := os.Chtimes(presence.SidecarPath(overlay), later, later); err != nil {
		t.Fatal(err)
	}
}

// reattachFromRecord is a vmd restart: the source is forgotten, rebuilt
// from its last durable record and its intent recovered.
func reattachFromRecord(t *testing.T, m *Manager, store *StateStore, vmID string) *VMInstance {
	t.Helper()
	m.state = store
	m.mu.Lock()
	delete(m.vms, vmID)
	m.mu.Unlock()
	rec, err := store.Get(vmID)
	if err != nil || rec == nil {
		t.Fatalf("durable record: %+v %v", rec, err)
	}
	inst := toInstance(*rec)
	if !m.recoverPauseIntent(context.Background(), inst, zerolog.Nop()) {
		t.Fatal("recovery parked the source")
	}
	return inst
}

// A running capture rewrites the chain under its own freeze token and its
// record write is lost. Recovery finds the rewrite whole, by the manifest
// it wrote, and the record takes it durably, so a relaunch from the chain
// wakes the guest under the token it is frozen with, not the earlier one.
func TestRecoveryRecordsAChainAdvanceWhoseRecordWasLost(t *testing.T) {
	fc := startChainFC(t, map[int]byte{2: 'X'})
	m := newSavedTestManager(t)
	statePath := filepath.Join(t.TempDir(), "state.db")
	store, err := OpenStateStore(statePath)
	if err != nil {
		t.Fatal(err)
	}
	m.state = store
	inst := seedRunningSource(t, m, fc, false)
	overlay := frozenSourceRecord(t, m, inst)
	chainDir := filepath.Join(m.cfg.SnapshotDir, inst.ID)
	// The store goes away between the release and the record.
	fc.onResume = func() { _ = m.state.Close() }
	if _, err := m.CreateSavedSnapshot(context.Background(), inst.ID, uuid.NewString(), SavedSnapshotMemFS); err == nil {
		t.Fatal("a chain advance that could not be recorded was reported as a capture")
	}
	fc.onResume = nil
	man, err := ReadWallClockManifest(overlay)
	if err != nil || man == nil || !man.WorkloadFrozen || man.FreezeToken == "" || man.FreezeToken == "tok-a" {
		t.Fatalf("rewritten overlay's manifest %+v %v; want frozen under the capture's own token", man, err)
	}
	reopened, err := OpenStateStore(statePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reopened.Close() })
	if rec, err := reopened.Get(inst.ID); err != nil || rec == nil || rec.FreezeToken != "tok-a" {
		t.Fatalf("durable record before recovery %+v %v; want the earlier pause's token", rec, err)
	}

	recovered := reattachFromRecord(t, m, reopened, inst.ID)
	if recovered.FreezeToken != man.FreezeToken || recovered.ArtifactID != man.ArtifactID || recovered.MemFilePath != overlay || recovered.DirtyTrackingGeneration != 1 {
		t.Fatalf("recovered token=%q artifact=%q mem=%s gen=%d; want the chain as the capture wrote it", recovered.FreezeToken, recovered.ArtifactID, recovered.MemFilePath, recovered.DirtyTrackingGeneration)
	}
	if rec, err := reopened.Get(inst.ID); err != nil || rec == nil || rec.FreezeToken != man.FreezeToken || rec.ArtifactID != man.ArtifactID || rec.MemFilePath != overlay {
		t.Fatalf("durable record after recovery %+v %v; want the chain as the capture wrote it", rec, err)
	}
	if in, err := readPauseIntent(chainDir); err != nil || in != nil {
		t.Fatalf("intent after recovery: %+v %v; want none", in, err)
	}
	// The next relaunch from the chain wakes it under the capture's token.
	if blocked, why := pauseIntentBlocks(chainDir, recovered.ArtifactID); blocked {
		t.Fatal(why)
	}
	_, frozen, token, err := resumeImageFacts(overlay, recovered.MemFilePath, recovered.CorrectsWallClock, recovered.SnapshotWorkloadFrozen, recovered.FreezeToken)
	if err != nil || !frozen || token != man.FreezeToken {
		t.Fatalf("wake would use token %q (frozen=%v, err=%v); want the capture's %q", token, frozen, err, man.FreezeToken)
	}
}

// A rewrite that died before its manifest left a chain that may be torn,
// or whole under a freeze its manifest does not name. Recovery withdraws
// it: nothing relaunches from it until the next pause writes it whole, and
// a first-pass overlay the record never named goes with it.
func TestRecoveryWithdrawsAChainARewriteLeftUncertain(t *testing.T) {
	fc := startChainFC(t)
	m := newSavedTestManager(t)
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	m.state = store
	inst := seedRunningSource(t, m, fc, false)
	raiseFloorForTest(t)
	overlay := frozenSourceRecord(t, m, inst)
	chainDir := filepath.Join(m.cfg.SnapshotDir, inst.ID)
	vmstate := filepath.Join(chainDir, "vmstate.snap")
	for _, p := range []string{vmstate, overlayBlockMapPath(vmstate)} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := writePauseIntent(chainDir, pauseIntent{VMID: inst.ID, FreezeToken: "tok-b", ArtifactID: "art-b"}); err != nil {
		t.Fatal(err)
	}
	refreshPresence(t, overlay)
	recovered := reattachFromRecord(t, m, store, inst.ID)
	if fileExists(vmstate) || fileExists(overlayBlockMapPath(vmstate)) {
		t.Fatal("an uncertain chain image was left restorable")
	}
	if !fileExists(overlay) {
		t.Fatal("the overlay the record names was removed")
	}
	if in, err := readPauseIntent(chainDir); err != nil || in != nil {
		t.Fatalf("intent after the withdrawal: %+v %v; want none", in, err)
	}
	if recovered.FreezeToken != "tok-a" || recovered.MemFilePath != overlay {
		t.Fatalf("record changed by a withdrawal: token=%q mem=%s", recovered.FreezeToken, recovered.MemFilePath)
	}
	// Whether Firecracker moved on is unknown: the next pause is a full one,
	// after a restart too.
	if rec, err := store.Get(inst.ID); err != nil || rec == nil || rec.DirtyTrackingSessionID != "" || toInstance(*rec).DirtyTracked {
		t.Fatalf("durable record after a withdrawal %+v %v; want the baseline spent", rec, err)
	}
	// A relaunch from the record's paths is refused for want of its vmstate.
	if _, err := os.Stat(recovered.SnapshotPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stat of the withdrawn vmstate: %v", err)
	}

	first := seedRunningSource(t, m, fc, true)
	raiseFloorForTest(t)
	firstDir := filepath.Join(m.cfg.SnapshotDir, first.ID)
	leftover := filepath.Join(firstDir, "mem.diff")
	pageFile(t, leftover, chainPages, map[int]byte{1: 'T'}, true)
	for _, p := range []string{filepath.Join(firstDir, "vmstate.snap"), layeredBaseSidecarPath(leftover), WallClockMarkerPath(leftover)} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := writePauseIntent(firstDir, pauseIntent{VMID: first.ID, FreezeToken: "tok-c", ArtifactID: "art-c"}); err != nil {
		t.Fatal(err)
	}
	recovered = reattachFromRecord(t, m, store, first.ID)
	for _, p := range []string{leftover, layeredBaseSidecarPath(leftover), presence.SidecarPath(leftover), WallClockMarkerPath(leftover), filepath.Join(firstDir, "vmstate.snap")} {
		if fileExists(p) {
			t.Errorf("%s survived the withdrawal of a first-pass rewrite", filepath.Base(p))
		}
	}
	if recovered.MemFilePath != first.BaseMemPath || !fileExists(first.BaseMemPath) {
		t.Fatalf("first-pass record after the withdrawal names %s; want its base, intact", recovered.MemFilePath)
	}
}

// A rewrite found whole whose record cannot be written keeps its intent:
// the guest is served, and a relaunch from the chain is refused until a
// reattach records it.
func TestRecoveryKeepsTheIntentWhenTheAdoptedChainCannotBeRecorded(t *testing.T) {
	fc := startChainFC(t)
	m := newSavedTestManager(t)
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	m.state = store
	inst := seedRunningSource(t, m, fc, false)
	raiseFloorForTest(t)
	overlay := frozenSourceRecord(t, m, inst)
	chainDir := filepath.Join(m.cfg.SnapshotDir, inst.ID)
	if err := os.WriteFile(filepath.Join(chainDir, "vmstate.snap"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	whole := WallClockManifest{Version: WallClockManifestVersion, ArtifactID: "art-b", WorkloadFrozen: true, GuestCorrectsClock: true, FreezeToken: "tok-b"}
	if err := WriteWallClockManifest(overlay, whole); err != nil {
		t.Fatal(err)
	}
	if err := writePauseIntent(chainDir, pauseIntent{VMID: inst.ID, FreezeToken: "tok-b", ArtifactID: "art-b"}); err != nil {
		t.Fatal(err)
	}
	refreshPresence(t, overlay)
	rec, err := store.Get(inst.ID)
	if err != nil || rec == nil {
		t.Fatal(err)
	}
	// The store is gone when the reconciled record would be written.
	store.Close()
	m.mu.Lock()
	delete(m.vms, inst.ID)
	m.mu.Unlock()
	recovered := toInstance(*rec)
	if !m.recoverPauseIntent(context.Background(), recovered, zerolog.Nop()) {
		t.Fatal("a released guest whose record could not be written was parked")
	}
	if in, err := readPauseIntent(chainDir); err != nil || in == nil || in.ArtifactID != "art-b" {
		t.Fatalf("intent after a failed record write: %+v %v; want it kept", in, err)
	}
	if blocked, _ := pauseIntentBlocks(chainDir, rec.ArtifactID); !blocked {
		t.Fatal("a relaunch from a chain the record does not know was allowed")
	}
	if fileExists(filepath.Join(chainDir, "vmstate.snap")) != true {
		t.Fatal("a chain found whole was withdrawn")
	}
}

// A rewrite that died after its manifest and before its record: the chain
// is whole, and recovery records it, durably, before the intent goes.
func TestRecoveryRecordsAChainARewriteCompletedBeforeItsRecord(t *testing.T) {
	fc := startChainFC(t)
	m := newSavedTestManager(t)
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	m.state = store
	inst := seedRunningSource(t, m, fc, false)
	raiseFloorForTest(t)
	overlay := frozenSourceRecord(t, m, inst)
	chainDir := filepath.Join(m.cfg.SnapshotDir, inst.ID)
	if err := os.WriteFile(filepath.Join(chainDir, "vmstate.snap"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	whole := WallClockManifest{Version: WallClockManifestVersion, ArtifactID: "art-b", WorkloadFrozen: true, GuestCorrectsClock: true, FreezeToken: "tok-b"}
	if err := WriteWallClockManifest(overlay, whole); err != nil {
		t.Fatal(err)
	}
	if err := writePauseIntent(chainDir, pauseIntent{VMID: inst.ID, FreezeToken: "tok-b", ArtifactID: "art-b"}); err != nil {
		t.Fatal(err)
	}
	refreshPresence(t, overlay)
	recovered := reattachFromRecord(t, m, store, inst.ID)
	if recovered.FreezeToken != "tok-b" || recovered.ArtifactID != "art-b" || recovered.DirtyTrackingGeneration != 1 {
		t.Fatalf("recovered token=%q artifact=%q gen=%d; want the rewrite's", recovered.FreezeToken, recovered.ArtifactID, recovered.DirtyTrackingGeneration)
	}
	if rec, err := store.Get(inst.ID); err != nil || rec == nil || rec.FreezeToken != "tok-b" || rec.ArtifactID != "art-b" {
		t.Fatalf("durable record after recovery %+v %v; want the rewrite's", rec, err)
	}
	if in, err := readPauseIntent(chainDir); err != nil || in != nil {
		t.Fatalf("intent after recovery: %+v %v; want none", in, err)
	}
	if _, frozen, token, err := resumeImageFacts(overlay, recovered.MemFilePath, recovered.CorrectsWallClock, recovered.SnapshotWorkloadFrozen, recovered.FreezeToken); err != nil || !frozen || token != "tok-b" {
		t.Fatalf("wake would use token %q (frozen=%v, err=%v); want the rewrite's", token, frozen, err)
	}
}

// A diff Firecracker refused before it moved on leaves the overlay without
// the records that make it restorable, and the source's baseline spent in
// memory; the record says so too, or a restart would re-arm the baseline
// and the next guarded diff would be accepted against that overlay.
func TestRunningCaptureRefusedBeforeFirecrackerMovedOnSpendsTheBaselineDurably(t *testing.T) {
	fc := startChainFC(t)
	fc.failDiff = true
	m := newSavedTestManager(t)
	inst := seedRunningSource(t, m, fc, false)
	chainDir := filepath.Join(m.cfg.SnapshotDir, inst.ID)
	if _, err := m.CreateSavedSnapshot(context.Background(), inst.ID, uuid.NewString(), SavedSnapshotMemFS); err == nil {
		t.Fatal("a refused diff was reported as a capture")
	}
	rec, err := m.state.Get(inst.ID)
	if err != nil || rec == nil || rec.DirtyTrackingSessionID != "" || rec.DirtyTrackingGeneration != 0 || toInstance(*rec).DirtyTracked {
		t.Fatalf("durable record after a refused diff %+v %v; want the baseline spent", rec, err)
	}
	if in, err := readPauseIntent(chainDir); err != nil || in != nil {
		t.Fatalf("intent after a durable abandonment: %+v %v; want none", in, err)
	}
}

// A rewrite that died after its manifest is adopted only with an overlay a
// restore can serve: one with its base record and a presence map the
// rewrite refreshed. A Firecracker from before the map leaves it stale or
// absent, and such a chain is withdrawn instead.
func TestRecoveryDoesNotAdoptAnOverlayItCannotServe(t *testing.T) {
	cases := []struct {
		name   string
		damage func(overlay string) error
	}{
		{"presence map not refreshed", func(overlay string) error {
			return os.Chtimes(presence.SidecarPath(overlay), presenceSaveMark, presenceSaveMark)
		}},
		{"presence map absent", func(overlay string) error { return os.Remove(presence.SidecarPath(overlay)) }},
		{"presence map older than the intent, as a crash rolls back", func(overlay string) error {
			old := time.Now().Add(-time.Hour)
			return os.Chtimes(presence.SidecarPath(overlay), old, old)
		}},
		{"base record absent", func(overlay string) error { return os.Remove(layeredBaseSidecarPath(overlay)) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fc := startChainFC(t)
			m := newSavedTestManager(t)
			store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			m.state = store
			inst := seedRunningSource(t, m, fc, false)
			raiseFloorForTest(t)
			overlay := frozenSourceRecord(t, m, inst)
			chainDir := filepath.Join(m.cfg.SnapshotDir, inst.ID)
			vmstate := filepath.Join(chainDir, "vmstate.snap")
			if err := os.WriteFile(vmstate, []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
			whole := WallClockManifest{Version: WallClockManifestVersion, ArtifactID: "art-b", WorkloadFrozen: true, GuestCorrectsClock: true, FreezeToken: "tok-b"}
			if err := WriteWallClockManifest(overlay, whole); err != nil {
				t.Fatal(err)
			}
			if err := writePauseIntent(chainDir, pauseIntent{VMID: inst.ID, FreezeToken: "tok-b", ArtifactID: "art-b"}); err != nil {
				t.Fatal(err)
			}
			if err := tc.damage(overlay); err != nil {
				t.Fatal(err)
			}
			recovered := reattachFromRecord(t, m, store, inst.ID)
			if recovered.FreezeToken != "tok-a" || recovered.ArtifactID != "art-a" {
				t.Fatalf("recovered token=%q artifact=%q; want the chain refused, the record as it was", recovered.FreezeToken, recovered.ArtifactID)
			}
			if fileExists(vmstate) {
				t.Fatal("a chain the record cannot serve was left restorable")
			}
			if in, err := readPauseIntent(chainDir); err != nil || in != nil {
				t.Fatalf("intent after the withdrawal: %+v %v; want none", in, err)
			}
		})
	}
}
