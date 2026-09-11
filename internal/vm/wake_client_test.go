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
	err = waitForGuestWake(context.Background(), "127.0.0.1", 10*time.Second, true, "tok")
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

// The verdict needs consecutive answers of one kind: an answer of another
// kind, or another status, in between starts the count over, so a guest
// that was recovering is not parked on failures that were not consecutive.
func TestWaitForGuestWakeVerdictNeedsAConsecutiveStreak(t *testing.T) {
	for _, tc := range []struct {
		name    string
		answers []int // 0: clock, 1: thaw, 2: HTTP 500
		want    error
		calls   int
	}{
		{"a_thaw_answer_breaks_a_clock_streak", []int{0, 0, 1, 0, 0, 0}, ErrGuestClockUnready, 6},
		{"another_status_breaks_the_streak", []int{1, 1, 2, 1, 1, 1}, ErrGuestThawFailed, 6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(boxdPort))
			if err != nil {
				t.Skipf("port %d busy: %v", boxdPort, err)
			}
			calls := 0
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				i := calls
				calls++
				if i >= len(tc.answers) {
					i = len(tc.answers) - 1
				}
				w.Header().Set("Content-Type", "application/json")
				switch tc.answers[i] {
				case 0:
					w.WriteHeader(http.StatusServiceUnavailable)
					w.Write([]byte(`{"status":"clock","wall_clock":{"error":"no ptp"}}`))
				case 1:
					w.WriteHeader(http.StatusServiceUnavailable)
					w.Write([]byte(`{"status":"thaw","wall_clock":{"error":"cgroup busy"}}`))
				default:
					w.WriteHeader(http.StatusInternalServerError)
				}
			}))
			srv.Listener = ln
			srv.Start()
			defer srv.Close()
			err = waitForGuestWake(context.Background(), "127.0.0.1", 10*time.Second, true, "tok")
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if calls != tc.calls {
				t.Fatalf("verdict after %d answers, want %d: the streak must restart at the interruption", calls, tc.calls)
			}
		})
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
	if err := waitForGuestWake(context.Background(), "127.0.0.1", 2*time.Second, false, "tok"); err != nil {
		t.Fatalf("want nil, got %v", err)
	}
}
func jsonDecode(r *http.Request, v any) error { return json.NewDecoder(r.Body).Decode(v) }

// A short freeze budget still reaches the guest as a positive budget: the
// reserve for the reply scales down with it instead of consuming it whole.
func TestFreezeRequestKeepsAPositiveGuestBudget(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(boxdPort))
	if err != nil {
		t.Skipf("port %d busy: %v", boxdPort, err)
	}
	var seen int64 = -1
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			BudgetMs int64  `json:"budget_ms"`
			Token    string `json:"token"`
		}
		_ = jsonDecode(r, &b)
		seen = b.BudgetMs
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"version":1,"capability":"wake","token":"` + b.Token + `"}`))
	}))
	srv.Listener = ln
	srv.Start()
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	echo, err := postBoxdFreeze(ctx, "127.0.0.1", "tok")
	if err != nil || echo.Token != "tok" {
		t.Fatalf("echo=%+v err=%v; want the freeze sent and echoed under a 100ms budget", echo, err)
	}
	if seen <= 0 || seen >= 100 {
		t.Fatalf("guest budget %dms, want positive and below the caller's 100ms", seen)
	}
}

// The wait's bound holds even when a guest accepts the connection and never
// answers: each request is cut off by the wait's deadline, not only by the
// per-request client timeout.
func TestWaitForGuestWakeHonoursAShortTimeoutAgainstAHungGuest(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(boxdPort))
	if err != nil {
		t.Skipf("port %d busy: %v", boxdPort, err)
	}
	release := make(chan struct{})
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release // never answers within the test's budget
	}))
	srv.Listener = ln
	srv.Start()
	defer func() { close(release); srv.Close() }()

	start := time.Now()
	err = waitForGuestWake(context.Background(), "127.0.0.1", 300*time.Millisecond, false, "tok")
	took := time.Since(start)
	if err == nil {
		t.Fatal("want an error from a guest that never answers")
	}
	if took > time.Second {
		t.Fatalf("took %v against a 300ms bound; a hung request must not carry the wait past it", took)
	}
}
