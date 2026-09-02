package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// boxdWallClockProven decides whether an image is marked as able to correct
// its own wall clock. A marker on a guest that cannot would let it be restored
// onto a stale clock, so every path that is not positive evidence must read as
// "not proven".
func TestBoxdWallClockProven(t *testing.T) {
	serve := func(t *testing.T, status int, body string) (ip string, done func()) {
		t.Helper()
		// boxdPort is fixed, so bind the loopback on exactly that port.
		ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(boxdPort))
		if err != nil {
			t.Skipf("port %d busy: %v", boxdPort, err)
		}
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/health" || r.URL.Query().Get("verify") != "settime" {
				t.Errorf("unexpected request %s: the build must ask the clock to be proven settable", r.URL.RequestURI())
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			w.Write([]byte(body))
		}))
		srv.Listener = ln
		srv.Start()
		return "127.0.0.1", srv.Close
	}

	cases := []struct {
		name   string
		status int
		body   string
		want   bool
		reason string // substring expected in the reason when not proven
	}{
		{"ptp_and_settable_is_proven", 200, `{"status":"ok","wall_clock":{"source":"ptp","settime_ok":true}}`, true, ""},
		{"ptp_with_prior_correction_is_proven", 200, `{"status":"ok","wall_clock":{"source":"ptp","corrected_ms":86400000,"settime_ok":true}}`, true, ""},
		{"ptp_but_not_settable_is_not", 200, `{"status":"ok","wall_clock":{"source":"ptp","error":"settime: EPERM"}}`, false, "EPERM"},
		{"unavailable_source_is_not", 200, `{"status":"ok","wall_clock":{"source":"unavailable","error":"open /dev/ptp0: no such file"}}`, false, "ptp0"},
		{"not_ready_is_not", 503, `{"status":"clock","wall_clock":{"source":"ptp","error":"set: EPERM"}}`, false, "503"},
		{"missing_field_is_not", 200, `{"status":"ok"}`, false, "source"},
		{"malformed_is_not", 200, `not json`, false, "decode"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip, done := serve(t, tc.status, tc.body)
			defer done()
			got, why := boxdWallClockProven(context.Background(), ip)
			if got != tc.want {
				t.Fatalf("proven = %v (%q), want %v", got, why, tc.want)
			}
			if !tc.want && !strings.Contains(why, tc.reason) {
				t.Errorf("reason %q, want it to mention %q", why, tc.reason)
			}
		})
	}

	// No agent at all is the most likely failure in practice and must not
	// resolve to "proven" by accident.
	t.Run("unreachable_is_not", func(t *testing.T) {
		got, why := boxdWallClockProven(context.Background(), "127.0.0.1")
		if got {
			t.Fatal("unreachable agent must not prove anything")
		}
		if !strings.Contains(why, "/health") {
			t.Errorf("reason %q should say it was the health probe that failed", why)
		}
	})
}

// A freeze that did not complete must never let the image be marked: the
// helper's error is what demotes the template to the unfrozen path.
func TestBoxdFreezeWorkload(t *testing.T) {
	serve := func(t *testing.T, status int) func() {
		t.Helper()
		ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(boxdPort))
		if err != nil {
			t.Skipf("port %d busy: %v", boxdPort, err)
		}
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.URL.Path != "/freeze" {
				t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			}
			w.WriteHeader(status)
			w.Write([]byte("workload did not freeze within budget"))
		}))
		srv.Listener = ln
		srv.Start()
		return srv.Close
	}

	t.Run("frozen_is_ok", func(t *testing.T) {
		defer serve(t, 200)()
		if err := boxdFreezeWorkload(context.Background(), "127.0.0.1"); err != nil {
			t.Fatalf("want nil, got %v", err)
		}
	})
	t.Run("budget_exhausted_is_an_error_with_the_reason", func(t *testing.T) {
		defer serve(t, 504)()
		err := boxdFreezeWorkload(context.Background(), "127.0.0.1")
		if err == nil || !strings.Contains(err.Error(), "504") || !strings.Contains(err.Error(), "budget") {
			t.Fatalf("err = %v, want the status and the agent's reason", err)
		}
	})
	t.Run("unreachable_is_an_error", func(t *testing.T) {
		if err := boxdFreezeWorkload(context.Background(), "127.0.0.1"); err == nil {
			t.Fatal("no agent must not read as frozen")
		}
	})
}
