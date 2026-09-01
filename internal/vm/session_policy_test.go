package vm

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/network"
	"github.com/superserve-ai/sandbox/internal/presence"
)

// snapshotAPIFake serves the Firecracker API on a unix socket and records every
// snapshot request body. respond decides each snapshot request's status and
// payload from its body; nil means 204.
type snapshotAPIFake struct {
	socketPath string
	mu         sync.Mutex
	bodies     []string
	respond    func(path, body string) (int, string)
}

func startSnapshotAPIFake(t *testing.T, respond func(path, body string) (int, string)) *snapshotAPIFake {
	t.Helper()
	f := &snapshotAPIFake{socketPath: filepath.Join(t.TempDir(), "fc.sock"), respond: respond}
	ln, err := net.Listen("unix", f.socketPath)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPatch && r.URL.Path == "/vm":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/snapshot/"):
			b, _ := io.ReadAll(r.Body)
			f.mu.Lock()
			f.bodies = append(f.bodies, string(b))
			f.mu.Unlock()
			code, payload := http.StatusNoContent, ""
			if f.respond != nil {
				code, payload = f.respond(r.URL.Path, string(b))
			}
			if payload != "" {
				w.Header().Set("Content-Type", "application/json")
			}
			w.WriteHeader(code)
			_, _ = io.WriteString(w, payload)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close(); ln.Close() })
	waitForUnixSocket(t, f.socketPath)
	return f
}

func (f *snapshotAPIFake) snapshotBodies() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.bodies...)
}

const mismatchPayload = `{"fault_message":"Dirty-tracking session mismatch","error_kind":"DirtyTrackingSessionMismatch"}`

func unknownFieldPayload(field string) string {
	return `{"fault_message":"unknown field ` + "`" + field + "`" + `, expected one of snapshot_path, mem_file_path"}`
}

func isDiffRequest(body string) bool { return strings.Contains(body, `"snapshot_type":"Diff"`) }

// The generation is a pointer precisely so that 0 — the only value vmd ever
// sends — serializes instead of being dropped as a zero value.
func TestGuardedSnapshotFieldsSerialize(t *testing.T) {
	fc := startSnapshotAPIFake(t, nil)
	if err := CreateDiffSnapshot(fc.socketPath, "/tmp/snap", "/tmp/mem", "tok-1"); err != nil {
		t.Fatal(err)
	}
	if err := RestoreSnapshotUffdInternalWithOverrides(
		fc.socketPath, "/tmp/snap", "/tmp/mem", "", "", "", "eth0", "tap0", "",
		true, false, "tok-2", nil,
	); err != nil {
		t.Fatal(err)
	}
	if err := CreateDiffSnapshot(fc.socketPath, "/tmp/snap", "/tmp/mem", ""); err != nil {
		t.Fatal(err)
	}
	bodies := fc.snapshotBodies()
	if len(bodies) != 3 {
		t.Fatalf("got %d snapshot requests, want 3", len(bodies))
	}
	for _, want := range []string{`"expected_session_id":"tok-1"`, `"expected_generation":0`} {
		if !strings.Contains(bodies[0], want) {
			t.Fatalf("guarded diff body lacks %s: %s", want, bodies[0])
		}
	}
	if !strings.Contains(bodies[1], `"tracking_session_id":"tok-2"`) {
		t.Fatalf("load body lacks the session: %s", bodies[1])
	}
	if strings.Contains(bodies[2], "expected_") {
		t.Fatalf("unguarded diff must carry no token fields: %s", bodies[2])
	}
}

// layeredPauseFixture builds a VM on its accumulating overlay (resumed from
// mem.diff over a template base) so a pause takes the layered path.
func layeredPauseFixture(t *testing.T, fc *snapshotAPIFake) (m *Manager, inst *VMInstance, dir, overlay string) {
	t.Helper()
	dir = t.TempDir()
	base := filepath.Join(dir, "template.mem")
	overlay = filepath.Join(dir, "mem.diff")
	for _, p := range []string{base, overlay, layeredBaseSidecarPath(overlay), presence.SidecarPath(overlay)} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	store, err := OpenStateStore(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	if err := store.Put(VMRecord{ID: "vm-1", Status: StatusRunning}); err != nil {
		t.Fatal(err)
	}
	inst = &VMInstance{
		ID: "vm-1", Status: StatusRunning, SocketPath: fc.socketPath,
		// cgroup mode with no delegated subtree: the stop fails fast and is
		// never confirmed, which is exactly the window the reclaim must wait out.
		Supervision:            SupervisionCgroup,
		DirtyTracked:           true,
		DirtyTrackingSessionID: "tok",
		BaseMemPath:            base,
		MemFilePath:            overlay,
	}
	m = &Manager{
		log: zerolog.Nop(), state: store,
		vms: map[string]*VMInstance{"vm-1": inst},
		cfg: ManagerConfig{IncrementalSnapshotEnabled: true, DirtyTrackingSessionEnabled: true},
	}
	m.dirtyTrackingSessionCapable.Store(true)
	return m, inst, dir, overlay
}

func assertOverlayIntact(t *testing.T, overlay string) {
	t.Helper()
	for _, p := range []string{overlay, layeredBaseSidecarPath(overlay), presence.SidecarPath(overlay)} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s must survive: %v", filepath.Base(p), err)
		}
	}
}

// A mismatch degrades to one Full, and the overlay it strands keeps every
// sidecar until the stop is confirmed — here it never is, so nothing is
// reclaimed and the layered artifact stays restorable.
func TestPauseVM_MismatchFallsBackToFullAndKeepsOverlayUntilStop(t *testing.T) {
	fc := startSnapshotAPIFake(t, func(_, body string) (int, string) {
		if isDiffRequest(body) {
			return http.StatusBadRequest, mismatchPayload
		}
		return http.StatusNoContent, ""
	})
	m, inst, dir, overlay := layeredPauseFixture(t, fc)

	_, memPath, _, err := m.PauseVM(context.Background(), "vm-1", dir, "tok-test")
	if err != nil {
		t.Fatalf("pause must succeed via the Full fallback: %v", err)
	}
	if memPath != filepath.Join(dir, "mem.snap") {
		t.Fatalf("fallback must record the Full image, got %s", memPath)
	}
	bodies := fc.snapshotBodies()
	if len(bodies) != 2 || !isDiffRequest(bodies[0]) || isDiffRequest(bodies[1]) {
		t.Fatalf("want a guarded Diff then a Full, got %v", bodies)
	}
	if !strings.Contains(bodies[0], `"expected_session_id":"tok"`) {
		t.Fatalf("diff must be guarded by the armed session: %s", bodies[0])
	}
	assertOverlayIntact(t, overlay)
	inst.mu.RLock()
	defer inst.mu.RUnlock()
	if inst.Status != StatusPaused || inst.BaseMemPath != "" || inst.DirtyTrackingSessionID != "" {
		t.Fatalf("paused state not recorded as standalone: %+v", inst)
	}
}

// If the replacement Full fails, nothing has been removed: the VM keeps
// running on its overlay, and that overlay is still the valid artifact.
func TestPauseVM_MismatchThenFullFailurePreservesOverlay(t *testing.T) {
	fc := startSnapshotAPIFake(t, func(_, body string) (int, string) {
		if isDiffRequest(body) {
			return http.StatusBadRequest, mismatchPayload
		}
		return http.StatusInternalServerError, `{"fault_message":"disk full"}`
	})
	m, inst, dir, overlay := layeredPauseFixture(t, fc)

	if _, _, _, err := m.PauseVM(context.Background(), "vm-1", dir, "tok-test"); err == nil {
		t.Fatal("a failed Full must fail the pause")
	}
	assertOverlayIntact(t, overlay)
	inst.mu.RLock()
	defer inst.mu.RUnlock()
	if inst.Status != StatusRunning || inst.MemFilePath != overlay || inst.DirtyTrackingSessionID != "tok" {
		t.Fatalf("a failed fallback must leave the running VM untouched: %+v", inst)
	}
}

// A rolled-back binary rejects the guarded fields as unknown; the pause must
// degrade to Full like a mismatch, and arming must stop for later restores.
func TestPauseVM_UnknownSessionFieldFallsBackToFull(t *testing.T) {
	fc := startSnapshotAPIFake(t, func(_, body string) (int, string) {
		if isDiffRequest(body) {
			// serde names the first unknown field, and the client serializes
			// the generation before the id — this is what an old binary says.
			return http.StatusBadRequest, unknownFieldPayload("expected_generation")
		}
		return http.StatusNoContent, ""
	})
	m, _, dir, _ := layeredPauseFixture(t, fc)

	if _, _, _, err := m.PauseVM(context.Background(), "vm-1", dir, "tok-test"); err != nil {
		t.Fatalf("pause must succeed via the Full fallback: %v", err)
	}
	if bodies := fc.snapshotBodies(); len(bodies) != 2 || isDiffRequest(bodies[1]) {
		t.Fatalf("want a Full after the refusal, got %v", bodies)
	}
	if m.sessionArmingEnabled() {
		t.Fatal("a refusal must clear the capability so later restores arm nothing")
	}
}

// After a vmd restart the persisted token guards the reattached VM's pause.
func TestPauseVM_ReattachedSessionGuardsThePause(t *testing.T) {
	origDown := vmUnitFullyDown
	vmUnitFullyDown = func(string) bool { return false }
	defer func() { vmUnitFullyDown = origDown }()

	fc := startSnapshotAPIFake(t, nil)
	dir := t.TempDir()
	memSnap := filepath.Join(dir, "mem.snap")
	if err := os.WriteFile(memSnap, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStateStore(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	rec := VMRecord{
		ID: "vm-1", Status: StatusRunning, Supervision: SupervisionCgroup,
		SocketPath: fc.socketPath, MemFilePath: memSnap,
		DirtyTrackingSessionID: "session-a",
	}
	if err := store.Put(rec); err != nil {
		t.Fatal(err)
	}
	m := &Manager{
		log: zerolog.Nop(), state: store, netMgr: &network.Manager{},
		vms: map[string]*VMInstance{},
		cfg: ManagerConfig{IncrementalSnapshotEnabled: true, DirtyTrackingSessionEnabled: true},
	}
	if inst, ok := m.reattachRecord(context.Background(), rec, true); inst == nil || !ok {
		t.Fatalf("reattach must adopt the live VM, got %+v %v", inst, ok)
	}

	if _, _, _, err := m.PauseVM(context.Background(), "vm-1", dir, "tok-test"); err != nil {
		t.Fatal(err)
	}
	bodies := fc.snapshotBodies()
	if len(bodies) != 1 || !isDiffRequest(bodies[0]) ||
		!strings.Contains(bodies[0], `"expected_session_id":"session-a"`) ||
		!strings.Contains(bodies[0], `"expected_generation":0`) {
		t.Fatalf("the reattached pause must be a Diff guarded by the persisted token, got %v", bodies)
	}
}

func resumeManager(t *testing.T, capable bool) *Manager {
	t.Helper()
	m := &Manager{log: zerolog.Nop(), cfg: ManagerConfig{
		ResumeUffdEnabled: true, UffdEnabled: true,
		IncrementalSnapshotEnabled: true, DirtyTrackingSessionEnabled: true,
	}}
	m.dirtyTrackingSessionCapable.Store(capable)
	return m
}

func loadBodyHasSession(body string) bool { return strings.Contains(body, `"tracking_session_id"`) }

// The flag alone is not enough: a session is armed only when the binary on
// disk advertises the fields, or an older Firecracker refuses the whole load.
func TestRestoreForResume_SessionRequiresCapability(t *testing.T) {
	fc := startSnapshotAPIFake(t, nil)
	net := &network.VMNetInfo{TAPDevice: "tap0"}
	for _, capable := range []bool{false, true} {
		m := resumeManager(t, capable)
		tracked, armed, _, err := m.restoreForResume(fc.socketPath, "/tmp/snap", "/tmp/mem", "", net, nil)
		if err != nil || !tracked {
			t.Fatalf("capable=%v: restore failed or untracked: %v", capable, err)
		}
		if (armed != "") != capable {
			t.Fatalf("capable=%v: armed session %q", capable, armed)
		}
	}
	bodies := fc.snapshotBodies()
	if len(bodies) != 2 || loadBodyHasSession(bodies[0]) || !loadBodyHasSession(bodies[1]) {
		t.Fatalf("session must appear only for the capable binary, got %v", bodies)
	}
}

// A rollback under a running daemon: the cached capability says yes, the
// binary says unknown field. The restore retries unguarded and records no
// session, and the capability clears so nothing else pays the retry.
func TestRestoreForResume_UnknownSessionFieldFallsBack(t *testing.T) {
	fc := startSnapshotAPIFake(t, func(_, body string) (int, string) {
		if loadBodyHasSession(body) {
			return http.StatusBadRequest, unknownFieldPayload("tracking_session_id")
		}
		return http.StatusNoContent, ""
	})
	m := resumeManager(t, true)
	tracked, armed, _, err := m.restoreForResume(fc.socketPath, "/tmp/snap", "/tmp/mem", "", &network.VMNetInfo{TAPDevice: "tap0"}, nil)
	if err != nil {
		t.Fatalf("the unguarded retry must succeed: %v", err)
	}
	if !tracked || armed != "" {
		t.Fatalf("tracking stays armed but no session may be recorded, got tracked=%v armed=%q", tracked, armed)
	}
	if bodies := fc.snapshotBodies(); len(bodies) != 2 || !loadBodyHasSession(bodies[0]) || loadBodyHasSession(bodies[1]) {
		t.Fatalf("want a guarded load then an unguarded retry, got %v", bodies)
	}
	if m.sessionArmingEnabled() {
		t.Fatal("the refusal must clear the capability")
	}
	// The record-bound path reports the same shape, so a caller persisting
	// the result stores exactly what was armed.
	var probe struct {
		Session string `json:"dirty_tracking_session_id,omitempty"`
	}
	b, _ := json.Marshal(toRecord(&VMInstance{ID: "vm-1", DirtyTrackingSessionID: armed}))
	_ = json.Unmarshal(b, &probe)
	if probe.Session != "" {
		t.Fatalf("an unarmed session must not be persisted, got %q", probe.Session)
	}
}

// The matcher covers both endpoints' field names and nothing else.
func TestIsUnknownSessionFieldErr(t *testing.T) {
	for _, field := range []string{"tracking_session_id", "expected_session_id", "expected_generation"} {
		err := &fakeErr{"[PUT /snapshot/load][400] loadSnapshotBadRequest " + unknownFieldPayload(field)}
		if !isUnknownSessionFieldErr(err) {
			t.Fatalf("must match the %s refusal: %v", field, err)
		}
	}
	if isUnknownSessionFieldErr(&fakeErr{"[PUT /snapshot/load][400] " + unknownFieldPayload("clock_realtime")}) {
		t.Fatal("the clock field has its own fallback and must not match")
	}
	if isUnknownSessionFieldErr(nil) {
		t.Fatal("nil must not match")
	}
}

type fakeErr struct{ s string }

func (e *fakeErr) Error() string { return e.s }
