package vm

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// withPSI sets the pressure eagerOverlayEnabled reads for the rest of the test.
func withPSI(t *testing.T, mem, io float64) {
	prev := eagerOverlayPSI
	eagerOverlayPSI = func() (float64, float64) { return mem, io }
	t.Cleanup(func() { eagerOverlayPSI = prev })
}

func TestEagerOverlayEnabled(t *testing.T) {
	m := &Manager{log: zerolog.Nop()}
	withPSI(t, 0, 0)
	if m.eagerOverlayEnabled() {
		t.Fatal("a binary that does not advertise the field must not get it")
	}
	m.eagerOverlayCapable.Store(true)
	if !m.eagerOverlayEnabled() {
		t.Fatal("a capable binary on an unpressured host should pre-copy")
	}
	withPSI(t, -1, -1)
	if !m.eagerOverlayEnabled() {
		t.Fatal("unreadable pressure must not block the pre-copy")
	}
	withPSI(t, eagerOverlayMaxPSI+1, 0)
	if m.eagerOverlayEnabled() {
		t.Fatal("a host under memory pressure should skip the pre-copy")
	}
	withPSI(t, 0, eagerOverlayMaxPSI+1)
	if m.eagerOverlayEnabled() {
		t.Fatal("a host under IO pressure should skip the pre-copy")
	}
}

// forkLoadBody runs a fork of a fresh saved snapshot of a paused source until
// Firecracker's load request, and returns that request's body. The fake API
// refuses the load so the restore stops there.
func forkLoadBody(t *testing.T, layered, capable bool) (body, mode string) {
	t.Helper()
	useTempFloor(t)
	withPSI(t, 0, 0)
	m := newSavedTestManager(t)
	// The API socket lives in the run dir, and t.TempDir is too long for one.
	runDir, err := os.MkdirTemp("", "eo")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(runDir) })
	m.cfg.RunDir = runDir
	m.restoreSem = make(chan struct{}, 1)
	m.netMgr = &fakeNetMgr{}
	sink := &phaseSink{}
	m.recorder = sink
	m.cfg.UffdEnabled, m.cfg.ResumeUffdEnabled = true, true
	m.eagerOverlayCapable.Store(capable)
	src, _ := seedPausedSource(t, m, layered)
	man, err := m.CreateSavedSnapshot(context.Background(), src.ID, uuid.NewString(), SavedSnapshotMemFS)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	m.launchFirecrackerHook = func(_ context.Context, _, socketPath, _, _, _ string, _ Supervision, _, _ bool) (int, Supervision, error) {
		ln, err := net.Listen("unix", socketPath)
		if err != nil {
			return 0, SupervisionUnit, err
		}
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/snapshot/load" {
				b, _ := io.ReadAll(r.Body)
				mu.Lock()
				body = string(b)
				mu.Unlock()
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"fault_message":"stop after the load request"}`))
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})}
		go srv.Serve(ln)
		t.Cleanup(func() { srv.Close() })
		return 0, SupervisionUnit, nil
	}
	_, rerr := m.restoreVMSnapshot(context.Background(), uuid.NewString(), "", "",
		VMConfig{VCPU: 1, MemoryMiB: 1024, SavedSnapshotID: man.SnapshotID}, nil, "", "", "", nil, 0, "")
	mu.Lock()
	defer mu.Unlock()
	if body == "" {
		t.Fatalf("the restore never sent a load request: %v", rerr)
	}
	return body, sink.modeOf("restore", "load_snapshot")
}

func TestForkRestoreAsksForEagerOverlayOnlyWhenLayeredAndCapable(t *testing.T) {
	b, mode := forkLoadBody(t, true, true)
	if !strings.Contains(b, `"eager_overlay":true`) || mode != "eager" {
		t.Fatalf("a layered fork on a capable binary must ask for the pre-copy under its own mode; mode=%q body=%s", mode, b)
	}
	for _, c := range []struct{ layered, capable bool }{{true, false}, {false, true}} {
		b, mode := forkLoadBody(t, c.layered, c.capable)
		if strings.Contains(b, "eager_overlay") || mode != "" {
			t.Fatalf("layered=%v capable=%v must not pre-copy; mode=%q body=%s", c.layered, c.capable, mode, b)
		}
	}
}

func TestRestoreWithEagerOverlayFallback_UnknownFieldRetriesWithout(t *testing.T) {
	m := &Manager{log: zerolog.Nop()}
	m.eagerOverlayCapable.Store(true)
	var sent []bool
	err := m.restoreWithEagerOverlayFallback(true, func(eager bool) error {
		sent = append(sent, eager)
		if eager {
			return errors.New("[PUT /snapshot/load][400] unknown field `eager_overlay`, expected one of `backend_path`")
		}
		return nil
	})
	if err != nil || len(sent) != 2 || !sent[0] || sent[1] {
		t.Fatalf("want one refused eager attempt then one without; sent=%v err=%v", sent, err)
	}
	if m.eagerOverlayCapable.Load() {
		t.Fatal("a refusal must clear the capability for later forks")
	}
	sent = nil
	_ = m.restoreWithEagerOverlayFallback(true, func(eager bool) error { sent = append(sent, eager); return nil })
	if len(sent) != 1 || sent[0] {
		t.Fatalf("once cleared, forks must not send the field; sent=%v", sent)
	}
}

func TestRestoreWithEagerOverlayFallback_OtherErrorsAreNotRetried(t *testing.T) {
	m := &Manager{log: zerolog.Nop()}
	m.eagerOverlayCapable.Store(true)
	calls := 0
	err := m.restoreWithEagerOverlayFallback(true, func(bool) error { calls++; return errors.New("load snapshot: connection refused") })
	if err == nil || calls != 1 || !m.eagerOverlayCapable.Load() {
		t.Fatalf("calls=%d err=%v capable=%v", calls, err, m.eagerOverlayCapable.Load())
	}
}

// False must be omitted, not sent: an older binary refuses the field even as false.
func TestEagerOverlaySerializesOnlyWhenOn(t *testing.T) {
	fc := startSnapshotAPIFake(t, nil)
	for _, eager := range []bool{true, false} {
		if err := RestoreSnapshotUffdInternalWithOverrides(
			fc.socketPath, "/tmp/snap", "/tmp/mem.diff", "/tmp/base", "", "", "eth0", "tap0", "",
			false, false, eager, "", nil,
		); err != nil {
			t.Fatal(err)
		}
	}
	bodies := fc.snapshotBodies()
	if len(bodies) != 2 || !strings.Contains(bodies[0], `"eager_overlay":true`) || strings.Contains(bodies[1], "eager_overlay") {
		t.Fatalf("bodies=%q", bodies)
	}
}
