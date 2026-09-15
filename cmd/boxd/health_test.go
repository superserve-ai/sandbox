package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func wake(clock *wallClock, fz *freezer, clockFrozen bool) (int, map[string]any) {
	return wakeWith(clock, fz, clockFrozen, "t1")
}

func wakeWith(clock *wallClock, fz *freezer, clockFrozen bool, token string) (int, map[string]any) {
	rec := httptest.NewRecorder()
	body := fmt.Sprintf(`{"clock_frozen":%v,"token":%q}`, clockFrozen, token)
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
	_ = fz.freeze(bg(), "t1")
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
	_ = fz.freeze(bg(), "t1")
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
	_ = fz.freeze(bg(), "t1")
	code, _ := wake(clockUnder(&fakeSource{hostErr: errors.New("no ptp")}, base), fz, false)
	if code != 200 || fz.isFrozen() {
		t.Fatalf("code %d frozen %v, want 200 and released", code, fz.isFrozen())
	}
}

func TestWakeUnreadyWhenThawCannotBeConfirmed(t *testing.T) {
	cg := newFake()
	fz := newFreezer(cg, testDir)
	_ = fz.freeze(bg(), "t1")
	cg.stuckThaw = true
	code, body := wake(clockUnder(&fakeSource{host: base}, base), fz, true)
	if code != 503 || body["status"] != "thaw" {
		t.Fatalf("code %d body %v, want 503 thaw", code, body)
	}
}

// A wake repeated with its own token after success is answered the same way;
// any other token names no freeze this guest holds and changes nothing.
func TestWakeIsIdempotentForItsTokenOnly(t *testing.T) {
	fz := newFreezer(newFake(), testDir)
	_ = fz.freeze(bg(), "t1")
	src := &fakeSource{host: base}
	clock := clockUnder(src, base)
	if code, body := wakeWith(clock, fz, false, "t2"); code != 409 || body["status"] != "token" || !fz.isFrozen() {
		t.Fatalf("wrong token: code %d body %v frozen %v, want 409 token and still frozen", code, body, fz.isFrozen())
	}
	for i := 0; i < 3; i++ {
		if code, _ := wakeWith(clock, fz, false, "t1"); code != 200 {
			t.Fatalf("wake %d: code %d, want 200", i, code)
		}
	}
	if code, _ := wakeWith(clock, fz, false, "t2"); code != 409 {
		t.Fatalf("stale token after release: code %d, want 409", code)
	}
	if code, _ := wakeWith(clock, newFreezer(newFake(), testDir), false, "t1"); code != 409 {
		t.Fatalf("never frozen: code %d, want 409", code)
	}
	// A retry after its answer was lost is answered as done even when the
	// host clock cannot be read now: the effect was not lost.
	src.hostErr = errors.New("no ptp")
	if code, body := wakeWith(clock, fz, true, "t1"); code != 200 || body["status"] != "ok" {
		t.Fatalf("retry with the clock unreadable: code %d body %v, want 200 ok", code, body)
	}
	// The next freeze needs a new token; a delayed wake for the old one is
	// refused against it and changes nothing.
	src.hostErr = nil
	_ = fz.freeze(bg(), "t3")
	if code, _ := wakeWith(clock, fz, true, "t1"); code != 409 || !fz.isFrozen() {
		t.Fatalf("stale wake against a new freeze: code %d frozen %v, want 409 and still frozen", code, fz.isFrozen())
	}
	if code, _ := wakeWith(clock, fz, false, "t3"); code != 200 || fz.isFrozen() {
		t.Fatalf("wake of the new freeze: code %d frozen %v, want 200 and released", code, fz.isFrozen())
	}
}

// /health reports; it never corrects the clock or releases the workload.
func TestHealthNeverMutates(t *testing.T) {
	cg := newFake()
	fz := newFreezer(cg, testDir)
	_ = fz.freeze(bg(), "t1")
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

func verifyClock(clock *wallClock, fz *freezer) (int, map[string]any) {
	rec := httptest.NewRecorder()
	handleVerifyClock(clock, fz)(rec, httptest.NewRequest(http.MethodPost, "/verify-clock", nil))
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// Verification is its own route: it proves the clock can be set, only where a
// freezer exists, and health never does it.
func TestVerifyClockIsItsOwnRoute(t *testing.T) {
	fz := newFreezer(newFake(), testDir)
	src := &fakeSource{host: base}
	code, body := verifyClock(clockUnder(src, base), fz)
	wc, _ := body["wall_clock"].(map[string]any)
	if code != 200 || wc["settime_ok"] != true {
		t.Errorf("code %d body %v, want proven", code, body)
	}
	// Not proven is a failure in the status code too, not only in the body.
	denied := &fakeSource{host: base, setErr: errors.New("EPERM")}
	code, body = verifyClock(clockUnder(denied, base), fz)
	wc, _ = body["wall_clock"].(map[string]any)
	if code != http.StatusServiceUnavailable || body["status"] != "clock" || wc["settime_ok"] == true {
		t.Errorf("EPERM: code %d body %v, want 503 clock and not proven", code, body)
	}
	unreadable := &fakeSource{hostErr: errors.New("no ptp")}
	if code, body := verifyClock(clockUnder(unreadable, base), fz); code != http.StatusServiceUnavailable || body["status"] != "clock" {
		t.Errorf("no host time: code %d body %v, want 503 clock", code, body)
	}
	// Health with a verify query does nothing of the kind.
	probe := &fakeSource{host: base}
	if _, body := health(clockUnder(probe, base), fz, "?verify=settime"); probe.setTo != nil {
		t.Errorf("health set the clock: %v", body)
	}
	// No freezer: the route does not exist for this image.
	missing := newFake()
	missing.missing = true
	if code, _ := verifyClock(clockUnder(&fakeSource{host: base}, base), newFreezer(missing, testDir)); code != http.StatusNotFound {
		t.Errorf("without a freezer: code %d, want 404", code)
	}
}

// Without a freezer, health is the answer it has always been: the legacy
// body, no lock, no clock, no larger encoding.
func TestHealthWithoutFreezerIsLegacy(t *testing.T) {
	missing := newFake()
	missing.missing = true
	fz := newFreezer(missing, testDir)
	rec := httptest.NewRecorder()
	handleHealth(clockUnder(&fakeSource{hostErr: errors.New("no ptp")}, base), fz)(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != 200 || rec.Body.String() != `{"status":"ok"}` {
		t.Fatalf("code %d body %q, want the legacy body exactly", rec.Code, rec.Body.String())
	}
}

// A wake that does not say whether the clock was frozen releases nothing.
func TestWakeWithoutClockFrozenIsRefused(t *testing.T) {
	for _, body := range []string{"", "{}", "not json", `{"clock_frozen":"yes","token":"t1"}`, `{"token":"t1"}`, `{"clock_frozen":true}`} {
		cg := newFake()
		fz := newFreezer(cg, testDir)
		_ = fz.freeze(bg(), "t1")
		src := &fakeSource{host: base.Add(48 * time.Hour)}
		rec := httptest.NewRecorder()
		handleWake(clockUnder(src, base), fz)(rec, httptest.NewRequest(http.MethodPost, "/wake", strings.NewReader(body)))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %q: code %d, want 400", body, rec.Code)
		}
		if !fz.isFrozen() || src.setTo != nil {
			t.Errorf("body %q: frozen=%v clockSet=%v; a refused wake must change nothing", body, fz.isFrozen(), src.setTo != nil)
		}
	}
}
