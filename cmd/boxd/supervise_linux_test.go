//go:build linux

package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/superserve-ai/sandbox/internal/start"
)

// These tests spawn real child processes via /bin/sh, so they are gated to
// linux (where the cmd/boxd package compiles and CI runs). They exercise the
// pieces the pure-logic tests can't: real launch, stdout/stderr capture, the
// restart loop honouring policy, the "already supervising" 409 guard with a
// live child, and graceful Stop via SIGTERM.

// captureLogs redirects supervisorLogf into an in-memory buffer for the
// duration of a test and returns an accessor + restore func.
func captureLogs(t *testing.T) (lines func() []string, restore func()) {
	t.Helper()
	var mu sync.Mutex
	var buf []string
	orig := supervisorLogf
	supervisorLogf = func(format string, args ...any) {
		mu.Lock()
		buf = append(buf, fmt.Sprintf(format, args...))
		mu.Unlock()
	}
	return func() []string {
			mu.Lock()
			defer mu.Unlock()
			out := make([]string, len(buf))
			copy(out, buf)
			return out
		}, func() {
			supervisorLogf = orig
		}
}

func TestSuperviseRunOnceCapturesOutput(t *testing.T) {
	lines, restore := captureLogs(t)
	defer restore()

	sup := newSupervisor(os.Environ())
	spec := &start.Spec{
		Argv:    []string{"/bin/sh", "-c", "echo out-line; echo err-line 1>&2; exit 0"},
		Restart: start.RestartNo,
	}
	if err := sup.Start(spec); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Wait for the supervise loop to finish (RestartNo + clean exit → stops).
	waitFor(t, func() bool { return !sup.IsSupervising() }, 5*time.Second)
	sup.Stop()

	got := lines()
	if !anyContains(got, "out-line") {
		t.Fatalf("stdout line not captured in logs: %v", got)
	}
	if !anyContains(got, "err-line") {
		t.Fatalf("stderr line not captured in logs: %v", got)
	}
}

func TestSuperviseRestartNoStopsAfterExit(t *testing.T) {
	_, restore := captureLogs(t)
	defer restore()

	sup := newSupervisor(os.Environ())
	// Append to a counter file each run so we can assert it ran exactly once.
	dir := t.TempDir()
	counter := dir + "/runs"
	spec := &start.Spec{
		Argv:    []string{"/bin/sh", "-c", "echo x >> " + counter + "; exit 1"},
		Restart: start.RestartNo, // exit 1 but policy=no → no restart
	}
	if err := sup.Start(spec); err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitFor(t, func() bool { return !sup.IsSupervising() }, 5*time.Second)
	sup.Stop()

	data, _ := os.ReadFile(counter)
	if n := strings.Count(string(data), "\n"); n != 1 {
		t.Fatalf("RestartNo ran %d times, want 1", n)
	}
}

func TestSuperviseRestartOnFailureRetries(t *testing.T) {
	_, restore := captureLogs(t)
	defer restore()

	dir := t.TempDir()
	counter := dir + "/runs"
	sup := newSupervisor(os.Environ())
	// Fails every run; on-failure must keep retrying. Backoff base is 500ms,
	// so within ~2s we should see at least 2 runs, then we stop it.
	spec := &start.Spec{
		Argv:    []string{"/bin/sh", "-c", "echo x >> " + counter + "; exit 7"},
		Restart: start.RestartOnFailure,
	}
	if err := sup.Start(spec); err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitFor(t, func() bool {
		data, _ := os.ReadFile(counter)
		return strings.Count(string(data), "\n") >= 2
	}, 5*time.Second)
	sup.Stop()

	// After Stop, no further restarts.
	data, _ := os.ReadFile(counter)
	before := strings.Count(string(data), "\n")
	time.Sleep(800 * time.Millisecond)
	data, _ = os.ReadFile(counter)
	if after := strings.Count(string(data), "\n"); after != before {
		t.Fatalf("supervisor restarted after Stop: %d → %d", before, after)
	}
}

func TestSuperviseAlreadySupervisingGuard(t *testing.T) {
	_, restore := captureLogs(t)
	defer restore()

	sup := newSupervisor(os.Environ())
	t.Cleanup(sup.Stop)

	spec := &start.Spec{Argv: []string{"/bin/sh", "-c", "sleep 30"}, Restart: start.RestartNo}
	if err := sup.Start(spec); err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitFor(t, func() bool { return sup.IsSupervising() }, 2*time.Second)

	if err := sup.Start(spec); err != errAlreadySupervising {
		t.Fatalf("second Start err=%v, want errAlreadySupervising", err)
	}
}

func TestSuperviseStopIsGraceful(t *testing.T) {
	_, restore := captureLogs(t)
	defer restore()

	sup := newSupervisor(os.Environ())
	// Long sleep; Stop must terminate it promptly via SIGTERM on the group.
	spec := &start.Spec{Argv: []string{"/bin/sh", "-c", "sleep 60"}, Restart: start.RestartAlways}
	if err := sup.Start(spec); err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitFor(t, func() bool { return sup.IsSupervising() }, 2*time.Second)

	stopBegan := time.Now()
	sup.Stop()
	if elapsed := time.Since(stopBegan); elapsed > childStopGrace+2*time.Second {
		t.Fatalf("Stop took %s, longer than grace window", elapsed)
	}
	if sup.IsSupervising() {
		t.Fatal("still supervising after Stop")
	}
}

// --- helpers ---

func waitFor(t *testing.T, cond func() bool, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !cond() {
		t.Fatalf("condition not met within %s", timeout)
	}
}

func anyContains(lines []string, sub string) bool {
	for _, l := range lines {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}
