package vm

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// A guest that reports it cannot correct its clock must fail the wait fast and
// typed, so the restore can be retried the unfrozen way instead of waiting out
// the budget with the customer's processes frozen.
func TestWaitForGuestWakeFailsFastOnUncorrectableClock(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(boxdPort))
	if err != nil {
		t.Skipf("port %d busy: %v", boxdPort, err)
	}
	calls := 0
	var sawPolicy bool
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/wake" || r.Method != http.MethodPost {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		var b struct {
			ClockFrozen bool `json:"clock_frozen"`
		}
		_ = jsonDecode(r, &b)
		sawPolicy = b.ClockFrozen
		calls++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"status":"clock","wall_clock":{"source":"unavailable","error":"open /dev/ptp0: no such file"}}`))
	}))
	srv.Listener = ln
	srv.Start()
	defer srv.Close()

	start := time.Now()
	err = waitForGuestWake(context.Background(), "127.0.0.1", 10*time.Second, true)
	if !errors.Is(err, ErrGuestClockUnready) {
		t.Fatalf("err = %v, want ErrGuestClockUnready", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("took %v; must not wait out the budget", time.Since(start))
	}
	if calls < clockUnreadyPolls {
		t.Errorf("gave up after %d polls, want at least %d", calls, clockUnreadyPolls)
	}
	if !sawPolicy {
		t.Error("the guest must be told the clock was frozen")
	}
}

func TestWaitForGuestWakeReadyIsNil(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(boxdPort))
	if err != nil {
		t.Skipf("port %d busy: %v", boxdPort, err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","wall_clock":{"source":"ptp"}}`))
	}))
	srv.Listener = ln
	srv.Start()
	defer srv.Close()
	if err := waitForGuestWake(context.Background(), "127.0.0.1", 2*time.Second, false); err != nil {
		t.Fatalf("want nil, got %v", err)
	}
}

func jsonDecode(r *http.Request, v any) error { return json.NewDecoder(r.Body).Decode(v) }

// A record that still owes a wake must get one on recovery — with the policy
// its restore used — never a health poll, which would take a stopped workload
// for a ready sandbox.
func TestVerifyBoxdReadyCompletesAPendingWake(t *testing.T) {
	origWake, origAdopt := boxdWakeGuest, adoptionBoxdReady
	t.Cleanup(func() { boxdWakeGuest, adoptionBoxdReady = origWake, origAdopt })
	m := &Manager{log: zerolog.Nop()}

	t.Run("pending_wake_is_sent_with_its_policy", func(t *testing.T) {
		var sawFrozen *bool
		boxdWakeGuest = func(_ context.Context, _ string, _ time.Duration, frozen bool) error {
			sawFrozen = &frozen
			return nil
		}
		adoptionBoxdReady = func(context.Context, *Manager, string) error {
			t.Fatal("a pending wake must not be verified by health")
			return nil
		}
		inst := &VMInstance{ID: "vm", WakePending: true, ClockFrozen: true}
		if err := m.verifyBoxdReady(context.Background(), "10.0.0.2", inst); err != nil {
			t.Fatalf("verify: %v", err)
		}
		if sawFrozen == nil || !*sawFrozen {
			t.Error("wake not sent, or sent without the frozen policy")
		}
		if inst.WakePending {
			t.Error("WakePending still set after a completed wake")
		}
	})

	t.Run("no_pending_wake_uses_health", func(t *testing.T) {
		boxdWakeGuest = func(context.Context, string, time.Duration, bool) error {
			t.Fatal("no wake owed; must not send one")
			return nil
		}
		called := false
		adoptionBoxdReady = func(context.Context, *Manager, string) error { called = true; return nil }
		if err := m.verifyBoxdReady(context.Background(), "10.0.0.2", &VMInstance{ID: "vm"}); err != nil || !called {
			t.Fatalf("err=%v called=%v; want health verification", err, called)
		}
	})

	t.Run("uncorrectable_clock_latches_the_host_and_fails", func(t *testing.T) {
		m := &Manager{log: zerolog.Nop(), cfg: ManagerConfig{GuestClockFreezeEnabled: true}}
		m.clockRealtimeCapable.Store(true)
		boxdWakeGuest = func(context.Context, string, time.Duration, bool) error { return ErrGuestClockUnready }
		inst := &VMInstance{ID: "vm", WakePending: true, ClockFrozen: true}
		if err := m.verifyBoxdReady(context.Background(), "10.0.0.2", inst); !errors.Is(err, ErrGuestClockUnready) {
			t.Fatalf("err = %v, want ErrGuestClockUnready", err)
		}
		if !inst.WakePending {
			t.Error("a failed wake must leave WakePending set")
		}
		if m.clockPolicyFor(true) != nil {
			t.Error("host not latched to unfrozen restores")
		}
	})
}

// The wake state must survive a daemon restart, or recovery cannot know it
// owes one.
func TestWakeStateSurvivesRecordRoundTrip(t *testing.T) {
	rec := toRecord(&VMInstance{ID: "vm", WakePending: true, ClockFrozen: true})
	if !rec.WakePending || !rec.ClockFrozen {
		t.Fatalf("toRecord dropped wake state: %+v", rec)
	}
	got := toInstance(rec)
	if !got.WakePending || !got.ClockFrozen {
		t.Errorf("toInstance dropped wake state: pending=%v frozen=%v", got.WakePending, got.ClockFrozen)
	}
}
