package vm

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// The policy must stay legacy — restore whatever the snapshot carries — unless
// both the operator asked for the behaviour and the guest was shown to correct
// its own wall clock. Freezing a guest that cannot leaves it on a stale clock.
func TestClockPolicyFor(t *testing.T) {
	cases := []struct {
		name     string
		enabled  bool
		corrects bool
		want     bool // true ⇒ expect a non-nil false (freeze)
	}{
		{name: "enabled_and_guest_corrects_freezes", enabled: true, corrects: true, want: true},
		{name: "flag_off_stays_legacy", enabled: false, corrects: true},
		{name: "guest_does_not_correct_stays_legacy", enabled: true, corrects: false},
		{name: "neither_stays_legacy"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := &Manager{cfg: ManagerConfig{GuestClockFreezeEnabled: tc.enabled}}
			// Capability is varied by TestClockPolicyForSeparatesGuestFromBinary;
			// hold it true here so this table isolates flag x guest property.
			m.clockRealtimeCapable.Store(true)
			got := m.clockPolicyFor(tc.corrects)
			if !tc.want {
				if got != nil {
					t.Fatalf("clockPolicyFor = %v, want nil (legacy)", *got)
				}
				return
			}
			if got == nil {
				t.Fatal("clockPolicyFor = nil, want a freeze request")
			}
			// Never true: advancing the guest clock by elapsed wall time is the
			// behaviour being fixed, so nothing may ask for it.
			if *got {
				t.Errorf("clockPolicyFor = true, want false")
			}
		})
	}
}

// The two facts the policy combines are independent, and an older binary must
// not erase the guest's. A capable host freezes; an incapable one restores the
// same marked guest the legacy way and leaves the marker for a later upgrade.
func TestClockPolicyForSeparatesGuestFromBinary(t *testing.T) {
	newManager := func(capable bool) *Manager {
		m := &Manager{cfg: ManagerConfig{GuestClockFreezeEnabled: true}}
		m.clockRealtimeCapable.Store(capable)
		return m
	}

	if got := newManager(true).clockPolicyFor(true); got == nil || *got {
		t.Errorf("capable host with a correcting guest: got %v, want a freeze request", got)
	}
	if got := newManager(false).clockPolicyFor(true); got != nil {
		t.Errorf("incapable host: got %v, want nil so the restore stays legacy", *got)
	}
	if got := newManager(true).clockPolicyFor(false); got != nil {
		t.Errorf("guest that does not correct: got %v, want nil", *got)
	}
}

// A pause must carry the marker forward, or every resume silently drops back to
// legacy — the slower half of the bug this exists to fix.
func TestGuestCorrectsWallClock(t *testing.T) {
	mark := func(t *testing.T, path string) string {
		t.Helper()
		if err := os.WriteFile(clockFreezeMarkerPath(path), nil, 0o644); err != nil {
			t.Fatalf("write marker: %v", err)
		}
		return path
	}

	t.Run("own_memory_file_marked", func(t *testing.T) {
		dir := t.TempDir()
		mem := mark(t, filepath.Join(dir, "mem.snap"))
		if !guestCorrectsWallClock(mem, "") {
			t.Error("want true when the VM's own image is marked")
		}
	})

	// First layered pass: the VM loaded straight off the template base, so the
	// base is what carries the marker.
	t.Run("layered_base_marked", func(t *testing.T) {
		dir := t.TempDir()
		base := mark(t, filepath.Join(dir, "template.snap"))
		if !guestCorrectsWallClock(filepath.Join(dir, "mem.diff"), base) {
			t.Error("want true when the layered base is marked")
		}
	})

	t.Run("neither_marked", func(t *testing.T) {
		dir := t.TempDir()
		if guestCorrectsWallClock(filepath.Join(dir, "mem.snap"), filepath.Join(dir, "base.snap")) {
			t.Error("want false when nothing is marked")
		}
	})

	// An empty base is the non-layered case, not a path to probe.
	t.Run("empty_base_is_not_marked", func(t *testing.T) {
		dir := t.TempDir()
		if guestCorrectsWallClock(filepath.Join(dir, "mem.snap"), "") {
			t.Error("want false for an unmarked VM with no base")
		}
	})
}

// The deploy replaces the Firecracker binary in place without restarting vmd, so
// a rollback can put an older binary under a running daemon and make the cached
// capability a lie. The first refusal must degrade to legacy rather than fail the
// restore, and must not leave every later restore paying for the discovery.
func TestRestoreWithClockFallback(t *testing.T) {
	unknownField := errors.New("load snapshot: [PUT /snapshot/load][400] Bad Request: " +
		"unknown field `clock_realtime`, expected one of `snapshot_path`, `mem_backend`")

	t.Run("rejection_retries_without_the_option_and_demotes", func(t *testing.T) {
		m := &Manager{log: zerolog.Nop()}
		m.clockRealtimeCapable.Store(true)

		var sent []*bool
		freeze := false
		used, err := m.restoreWithClockFallback(&freeze, func(clock *bool) error {
			sent = append(sent, clock)
			if clock != nil {
				return unknownField
			}
			return nil
		})
		if err != nil {
			t.Fatalf("restore should have succeeded on retry: %v", err)
		}
		if len(sent) != 2 {
			t.Fatalf("attempts = %d, want 2 (one with the option, one without)", len(sent))
		}
		if sent[0] == nil || sent[1] != nil {
			t.Errorf("want first attempt with the option and retry without; got %v, %v", sent[0], sent[1])
		}
		if m.clockRealtimeCapable.Load() {
			t.Error("capability must be cleared so later restores skip the doomed attempt")
		}
		// The restore that succeeded ran without the policy, and the log must say so.
		if used {
			t.Error("usedPolicy = true after falling back to legacy, want false")
		}
	})

	// An unrelated failure must not be swallowed by a retry.
	t.Run("other_errors_are_not_retried", func(t *testing.T) {
		m := &Manager{log: zerolog.Nop()}
		m.clockRealtimeCapable.Store(true)

		boom := errors.New("load snapshot: connection refused")
		calls := 0
		freeze := false
		used, err := m.restoreWithClockFallback(&freeze, func(*bool) error {
			calls++
			return boom
		})
		if used {
			t.Error("usedPolicy = true for a failed restore, want false")
		}
		if !errors.Is(err, boom) {
			t.Errorf("err = %v, want the original failure", err)
		}
		if calls != 1 {
			t.Errorf("calls = %d, want 1 (no retry)", calls)
		}
		if !m.clockRealtimeCapable.Load() {
			t.Error("an unrelated failure must not clear the capability")
		}
	})

	// Legacy restores never carried the option, so there is nothing to fall back to.
	t.Run("legacy_restore_is_not_retried", func(t *testing.T) {
		m := &Manager{log: zerolog.Nop()}
		m.clockRealtimeCapable.Store(true)
		calls := 0
		_, err := m.restoreWithClockFallback(nil, func(*bool) error {
			calls++
			return unknownField
		})
		if err == nil {
			t.Error("want the error surfaced, not retried away")
		}
		if calls != 1 {
			t.Errorf("calls = %d, want 1", calls)
		}
	})
}

// A successful restore that kept the policy must report it, or rollout
// verification cannot tell the feature working from the feature never engaging.
func TestRestoreWithClockFallbackReportsPolicyUsed(t *testing.T) {
	m := &Manager{log: zerolog.Nop()}
	m.clockRealtimeCapable.Store(true)
	freeze := false
	used, err := m.restoreWithClockFallback(&freeze, func(*bool) error { return nil })
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if !used {
		t.Error("usedPolicy = false, want true when the policy restore succeeded")
	}
}

// The guest property must survive a vmd restart. It is not derivable from the
// daemon's own state: a reattached VM that came back looking incapable would
// have its valid marker stripped by the next pause, permanently demoting every
// resume after that.
func TestCorrectsWallClockSurvivesRecordRoundTrip(t *testing.T) {
	for _, corrects := range []bool{true, false} {
		rec := toRecord(&VMInstance{ID: "vm", CorrectsWallClock: &corrects})
		if rec.CorrectsWallClock == nil || *rec.CorrectsWallClock != corrects {
			t.Fatalf("toRecord dropped the property: got %v, want %v", rec.CorrectsWallClock, corrects)
		}
		got := toInstance(rec).CorrectsWallClock
		if got == nil || *got != corrects {
			t.Errorf("toInstance dropped the property: got %v, want %v", got, corrects)
		}
	}
}

// Older records predate the field, and their guests were never shown to correct
// their clocks — decoding them as false is what keeps that safe.
func TestCorrectsWallClockAbsentFromOldRecordIsFalse(t *testing.T) {
	var rec VMRecord
	if err := json.Unmarshal([]byte(`{"id":"vm"}`), &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// Unresolved, not "no": a binary predating the field drops it on rewrite, so
	// reading that silence as false would strip a marker that is still valid.
	if rec.CorrectsWallClock != nil {
		t.Errorf("a record without the field must decode as unresolved, got %v", *rec.CorrectsWallClock)
	}
}

// Resume latency is a critical path, so the ordinary case must answer from the
// durable record rather than the filesystem. Each case seeds a marker that
// contradicts the record: if the record is used, the marker is irrelevant, which
// is what proves the lookup was skipped.
func TestResumeWallClockProperty(t *testing.T) {
	t.Run("same_image_trusts_the_record_over_the_disk", func(t *testing.T) {
		mem := filepath.Join(t.TempDir(), "mem.snap")
		if err := os.WriteFile(clockFreezeMarkerPath(mem), nil, 0o644); err != nil {
			t.Fatalf("seed marker: %v", err)
		}
		// Marker says yes, record says no. The record wins ⇒ no stat happened.
		if resumeWallClockProperty(mem, "", mem, boolPtr(false)) {
			t.Error("want the recorded value; a marker on disk means the record was not used")
		}
		// And the inverse: no marker on disk, record says yes.
		bare := filepath.Join(t.TempDir(), "mem.snap")
		if !resumeWallClockProperty(bare, "", bare, boolPtr(true)) {
			t.Error("want the recorded value even with no marker beside the image")
		}
	})

	// An override supplies an image this VM was never paused into, so the record
	// describes a different artifact and the marker is the only evidence.
	t.Run("override_image_reads_the_marker", func(t *testing.T) {
		dir := t.TempDir()
		override := filepath.Join(dir, "restored.snap")
		if err := os.WriteFile(clockFreezeMarkerPath(override), nil, 0o644); err != nil {
			t.Fatalf("seed marker: %v", err)
		}
		if !resumeWallClockProperty(override, "", filepath.Join(dir, "mem.snap"), boolPtr(false)) {
			t.Error("want the marker consulted when the image is not the paused one")
		}
	})

	t.Run("override_without_a_marker_stays_legacy", func(t *testing.T) {
		dir := t.TempDir()
		if resumeWallClockProperty(filepath.Join(dir, "restored.snap"), "", filepath.Join(dir, "mem.snap"), boolPtr(true)) {
			t.Error("a stale record must not carry over to a different image")
		}
	})
}

// A capability read once at startup goes stale in both directions, because the
// deploy swaps the binary in place without restarting vmd. The restore fallback
// only ever demotes, so promotion after an upgrade has to come from here — and
// the watch must stop when its context does.
func TestWatchFirecrackerCapability(t *testing.T) {
	fakeFC := func(t *testing.T, advertises bool) string {
		t.Helper()
		dir := t.TempDir()
		bin := filepath.Join(dir, "firecracker")
		body := "#!/bin/sh\necho 'Firecracker v1.15.0'\n"
		if advertises {
			body += "echo 'capability: " + clockRealtimeCap + "'\n"
		}
		if err := os.WriteFile(bin, []byte(body), 0o755); err != nil {
			t.Fatalf("write fake firecracker: %v", err)
		}
		return bin
	}

	waitFor := func(t *testing.T, m *Manager, want bool) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if m.clockRealtimeCapable.Load() == want {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatalf("capability never became %v", want)
	}

	t.Run("promotes_when_the_binary_advertises", func(t *testing.T) {
		m := &Manager{cfg: ManagerConfig{FirecrackerBin: fakeFC(t, true)}}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		m.WatchFirecrackerCapability(ctx, zerolog.Nop())
		waitFor(t, m, true)
	})

	t.Run("stays_false_for_an_older_binary", func(t *testing.T) {
		m := &Manager{cfg: ManagerConfig{FirecrackerBin: fakeFC(t, false)}}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		m.WatchFirecrackerCapability(ctx, zerolog.Nop())
		// Give the first probe room to run before concluding it stayed false.
		time.Sleep(200 * time.Millisecond)
		if m.clockRealtimeCapable.Load() {
			t.Error("capability true for a binary that does not advertise it")
		}
	})

	// No binary configured means nothing to probe, and no goroutine to leak.
	t.Run("no_binary_is_a_no_op", func(t *testing.T) {
		m := &Manager{}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		m.WatchFirecrackerCapability(ctx, zerolog.Nop())
		if m.clockRealtimeCapable.Load() {
			t.Error("capability true with no binary configured")
		}
	})
}

// A rollback to a binary without the record field, then an upgrade back, leaves
// the field absent. Reading that silence as "no" would ignore the marker still
// beside the image and delete it at the next pause — a permanent demotion.
func TestResumeWallClockPropertyUnresolvedRecordConsultsTheMarker(t *testing.T) {
	mem := filepath.Join(t.TempDir(), "mem.snap")
	if err := os.WriteFile(clockFreezeMarkerPath(mem), nil, 0o644); err != nil {
		t.Fatalf("seed marker: %v", err)
	}
	// Same image, but the record lost the answer.
	if !resumeWallClockProperty(mem, "", mem, nil) {
		t.Error("an unresolved record must fall back to the marker, not read as false")
	}

	bare := filepath.Join(t.TempDir(), "mem.snap")
	if resumeWallClockProperty(bare, "", bare, nil) {
		t.Error("unresolved with no marker must still be false")
	}
}

// The builder writes the marker and vmd reads it, so the two spellings must
// never drift apart.
func TestWallClockMarkerPathMatchesInternal(t *testing.T) {
	if got, want := WallClockMarkerPath("/x/mem.snap"), clockFreezeMarkerPath("/x/mem.snap"); got != want {
		t.Fatalf("exported %q != internal %q", got, want)
	}
}

// A freeze the guest could not complete must demote the pause to an unfrozen
// image — never leave a marked image whose workload was running on the stale
// clock — and must be bounded, since it sits on the pause path.
func TestFreezeGuestForPause(t *testing.T) {
	orig := boxdFreezeGuest
	t.Cleanup(func() { boxdFreezeGuest = orig })
	m := &Manager{log: zerolog.Nop()}

	t.Run("frozen_keeps_the_marker", func(t *testing.T) {
		boxdFreezeGuest = func(context.Context, string) error { return nil }
		corrects, frozen := m.freezeGuestForPause(context.Background(), "10.0.0.2", zerolog.Nop())
		if !corrects || !frozen {
			t.Fatalf("got corrects=%v frozen=%v, want both true", corrects, frozen)
		}
	})

	t.Run("refused_demotes_to_unfrozen", func(t *testing.T) {
		boxdFreezeGuest = func(context.Context, string) error { return errors.New("504: budget") }
		corrects, frozen := m.freezeGuestForPause(context.Background(), "10.0.0.2", zerolog.Nop())
		if corrects || frozen {
			t.Fatalf("got corrects=%v frozen=%v, want both false", corrects, frozen)
		}
	})

	t.Run("call_is_bounded_by_the_budget", func(t *testing.T) {
		var seen time.Duration
		boxdFreezeGuest = func(ctx context.Context, _ string) error {
			dl, ok := ctx.Deadline()
			if !ok {
				t.Fatal("freeze must carry a deadline; it sits on the pause path")
			}
			seen = time.Until(dl)
			return nil
		}
		m.freezeGuestForPause(context.Background(), "10.0.0.2", zerolog.Nop())
		if seen <= 0 || seen > guestFreezeBudget {
			t.Errorf("deadline %v from now, want within (0, %v]", seen, guestFreezeBudget)
		}
	})
}
