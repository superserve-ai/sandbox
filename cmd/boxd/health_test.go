package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func wake(clock *wallClock, fz *freezer, clockFrozen bool) (int, map[string]any) {
	rec := httptest.NewRecorder()
	body := `{"clock_frozen":false}`
	if clockFrozen {
		body = `{"clock_frozen":true}`
	}
	handleWake(clock, fz)(rec, httptest.NewRequest(http.MethodPost, "/wake", strings.NewReader(body)))
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func health(clock *wallClock, fz *freezer, query string) (int, map[string]any) {
	rec := httptest.NewRecorder()
	handleHealth(clock, fz)(rec, httptest.NewRequest(http.MethodGet, "/health"+query, nil))
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// The restore contract: /wake with clock_frozen corrects the clock, then
// releases the workload, and 200 means both happened.
func TestWakeFrozenRestoreCorrectsThenThaws(t *testing.T) {
	cg := newFake()
	fz := newFreezer(cg, testDir)
	_ = fz.freeze(bg())
	src := &fakeSource{host: base.Add(48 * time.Hour)}
	code, body := wake(clockUnder(src, base), fz, true)
	if code != 200 || body["status"] != "ok" {
		t.Fatalf("code %d body %v, want 200 ok", code, body)
	}
	if src.setTo == nil {
		t.Error("clock not corrected before release")
	}
	if fz.isFrozen() {
		t.Error("workload still frozen after a ready wake")
	}
}

// Frozen restore, no host time: not ready, and the workload stays stopped —
// serving would mean a stale clock. The supervisor retries unfrozen.
func TestWakeFrozenRestoreWithoutHostTimeStaysFrozen(t *testing.T) {
	cg := newFake()
	fz := newFreezer(cg, testDir)
	_ = fz.freeze(bg())
	code, body := wake(clockUnder(&fakeSource{hostErr: errors.New("no ptp")}, base), fz, true)
	if code != 503 || body["status"] != "clock" {
		t.Fatalf("code %d body %v, want 503 clock", code, body)
	}
	if !fz.isFrozen() {
		t.Error("workload released under a stale clock")
	}
}

// The unfrozen retry of that same image: the clock already moved with the
// host, so nothing needs correcting, and the workload is released.
func TestWakeUnfrozenRestoreReleasesEvenWithoutHostTime(t *testing.T) {
	cg := newFake()
	fz := newFreezer(cg, testDir)
	_ = fz.freeze(bg())
	code, _ := wake(clockUnder(&fakeSource{hostErr: errors.New("no ptp")}, base), fz, false)
	if code != 200 || fz.isFrozen() {
		t.Fatalf("code %d frozen %v, want 200 and released", code, fz.isFrozen())
	}
}

func TestWakeUnreadyWhenThawCannotBeConfirmed(t *testing.T) {
	cg := newFake()
	fz := newFreezer(cg, testDir)
	_ = fz.freeze(bg())
	cg.stuckThaw = true
	code, body := wake(clockUnder(&fakeSource{host: base}, base), fz, true)
	if code != 503 || body["status"] != "thaw" {
		t.Fatalf("code %d body %v, want 503 thaw", code, body)
	}
}

// A guest that was never frozen — fresh boot — wakes ready with nothing to do.
func TestWakeIsIdempotentAndHarmlessWhenNotFrozen(t *testing.T) {
	fz := newFreezer(newFake(), testDir)
	clock := clockUnder(&fakeSource{host: base}, base)
	for i := 0; i < 3; i++ {
		if code, _ := wake(clock, fz, false); code != 200 {
			t.Fatalf("wake %d: code %d, want 200", i, code)
		}
	}
}

// /health reports; it never corrects the clock or releases the workload.
func TestHealthNeverMutates(t *testing.T) {
	cg := newFake()
	fz := newFreezer(cg, testDir)
	_ = fz.freeze(bg())
	src := &fakeSource{host: base.Add(time.Hour)}
	code, body := health(clockUnder(src, base), fz, "")
	if code != 503 || body["status"] != "frozen" {
		t.Fatalf("code %d body %v, want 503 frozen — a stopped workload is not ready", code, body)
	}
	if src.setTo != nil {
		t.Error("health stepped the clock")
	}
	if !fz.isFrozen() {
		t.Error("health released the workload")
	}
}

func TestHealthVerifySettime(t *testing.T) {
	fz := newFreezer(newFake(), testDir)
	_, body := health(clockUnder(&fakeSource{host: base}, base), fz, "?verify=settime")
	wc, _ := body["wall_clock"].(map[string]any)
	if wc["settime_ok"] != true {
		t.Errorf("settime_ok missing: %v", body)
	}
	_, body = health(clockUnder(&fakeSource{host: base, setErr: errors.New("EPERM")}, base), fz, "?verify=settime")
	wc, _ = body["wall_clock"].(map[string]any)
	if wc["settime_ok"] == true {
		t.Errorf("settime_ok reported despite EPERM: %v", body)
	}
}
