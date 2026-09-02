package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func healthWith(clock *wallClock, fz *freezer, query string) (int, map[string]any) {
	rec := httptest.NewRecorder()
	handleHealth(clock, fz)(rec, httptest.NewRequest(http.MethodGet, "/health"+query, nil))
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

// The contract vmd relies on: 200 means clock right and workload running.
func TestHealthReadyMeansCorrectedAndThawed(t *testing.T) {
	cg := newFake()
	fz := newFreezer(cg, testDir)
	_ = fz.freeze(bg())
	src := &fakeSource{host: base.Add(time.Hour)}
	code, body := healthWith(clockUnder(src, base), fz, "")
	if code != 200 || body["status"] != "ok" {
		t.Fatalf("code %d body %v, want 200 ok", code, body)
	}
	if fz.isFrozen() {
		t.Error("ready reported with the workload still frozen")
	}
	if src.setTo == nil {
		t.Error("ready reported without correcting the clock")
	}
}

func TestHealthUnreadyWhenThawCannotBeConfirmed(t *testing.T) {
	cg := newFake()
	fz := newFreezer(cg, testDir)
	_ = fz.freeze(bg())
	cg.stuckThaw = true
	code, body := healthWith(clockUnder(&fakeSource{host: base}, base), fz, "")
	if code != 503 || body["status"] != "thaw" {
		t.Fatalf("code %d body %v, want 503 thaw", code, body)
	}
}

// Frozen workload and no host time: the image was prepared for a frozen
// restore, so an uncorrectable clock is not ready.
func TestHealthFrozenWithoutHostTimeIsNotReady(t *testing.T) {
	cg := newFake()
	fz := newFreezer(cg, testDir)
	_ = fz.freeze(bg())
	code, body := healthWith(clockUnder(&fakeSource{hostErr: errors.New("no ptp")}, base), fz, "")
	if code != 503 || body["status"] != "clock" {
		t.Fatalf("code %d body %v, want 503 clock", code, body)
	}
	if !fz.isFrozen() {
		t.Error("workload thawed under a stale clock")
	}
}

// A fresh boot with no host time is fine: nothing was frozen, nothing to fix.
// Template builds on images without the device depend on this.
func TestHealthFreshBootWithoutHostTimeIsReady(t *testing.T) {
	fz := newFreezer(newFake(), testDir)
	code, _ := healthWith(clockUnder(&fakeSource{hostErr: errors.New("no ptp")}, base), fz, "")
	if code != 200 {
		t.Fatalf("code %d, want 200", code)
	}
}

func TestHealthVerifySettime(t *testing.T) {
	fz := newFreezer(newFake(), testDir)
	_, body := healthWith(clockUnder(&fakeSource{host: base}, base), fz, "?verify=settime")
	wc, _ := body["wall_clock"].(map[string]any)
	if wc["settime_ok"] != true {
		t.Errorf("settime_ok missing: %v", body)
	}
	_, body = healthWith(clockUnder(&fakeSource{host: base, setErr: errors.New("EPERM")}, base), fz, "?verify=settime")
	wc, _ = body["wall_clock"].(map[string]any)
	if wc["settime_ok"] == true {
		t.Errorf("settime_ok reported despite EPERM: %v", body)
	}
}

func bg() context.Context { return context.Background() }
