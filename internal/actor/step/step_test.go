package step

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// shortSockDir returns a short-path temp dir for unix sockets (t.TempDir() can
// exceed the ~104-char sun_path limit on macOS).
func shortSockDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "actorstep")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

func TestLogRecordRecallAndReplay(t *testing.T) {
	dir := t.TempDir()

	l1, err := OpenLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, found := l1.Recall("plan"); found {
		t.Fatal("empty log should not find a step")
	}
	if _, err := l1.Record("plan", json.RawMessage(`{"goal":"x"}`)); err != nil {
		t.Fatal(err)
	}
	// Idempotent re-record returns the original value.
	v, err := l1.Record("plan", json.RawMessage(`{"goal":"DIFFERENT"}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(v) != `{"goal":"x"}` {
		t.Errorf("re-record must keep original value, got %s", v)
	}
	_ = l1.Close()

	// Simulate a crash + restart: a fresh Log over the same dir replays.
	l2, err := OpenLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	got, found := l2.Recall("plan")
	if !found || string(got) != `{"goal":"x"}` {
		t.Fatalf("replay should recall the step: found=%v val=%s", found, got)
	}
}

func TestLogToleratesTruncatedTail(t *testing.T) {
	dir := t.TempDir()
	l, _ := OpenLog(dir)
	_, _ = l.Record("a", json.RawMessage(`1`))
	_, _ = l.Record("b", json.RawMessage(`2`))
	_ = l.Close()

	// Corrupt the journal with a half-written trailing line (a crash mid-append).
	jp := filepath.Join(dir, JournalName)
	data, _ := os.ReadFile(jp)
	partial := []byte(`{"seq":3,"step":"c","val`)
	_ = os.WriteFile(jp, append(data, partial...), 0o644)

	l2, err := OpenLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	if _, ok := l2.Recall("a"); !ok {
		t.Error("committed step a should survive a truncated tail")
	}
	if _, ok := l2.Recall("b"); !ok {
		t.Error("committed step b should survive a truncated tail")
	}
	if _, ok := l2.Recall("c"); ok {
		t.Error("partially-written step c must NOT be recalled")
	}
}

func TestServerClientStep(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(shortSockDir(t), "step.sock")

	log, _ := OpenLog(dir)
	srv, err := Listen(sock, log)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve()
	defer srv.Close()

	c, err := Dial(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	runs := 0
	work := func() (int, error) { runs++; return 42, nil }

	// First call runs the work and records it.
	v, err := Step(c, "compute", work)
	if err != nil || v != 42 {
		t.Fatalf("step: v=%d err=%v", v, err)
	}
	// Second call in the SAME run recalls — fn must not run again.
	v, err = Step(c, "compute", work)
	if err != nil || v != 42 {
		t.Fatalf("step replay: v=%d err=%v", v, err)
	}
	if runs != 1 {
		t.Fatalf("fn should run exactly once within a run, ran %d times", runs)
	}
}

// TestCrashReplaySkipsCompletedSteps is the headline durability proof: a
// workflow runs steps A and B, then the process "crashes" before C. On replay
// (fresh log/server/client over the same /state dir), A and B are recalled
// without re-running their fns, and only C executes — so external effects are
// not repeated and the harness resumes from the exact interruption point.
func TestCrashReplaySkipsCompletedSteps(t *testing.T) {
	dir := t.TempDir()
	sockDir := shortSockDir(t)

	var aRuns, bRuns, cRuns int

	// --- First process: completes A and B, then "crashes" before C. ---
	func() {
		log, _ := OpenLog(dir)
		srv, err := Listen(filepath.Join(sockDir, "s1.sock"), log)
		if err != nil {
			t.Fatal(err)
		}
		go srv.Serve()
		defer srv.Close()
		defer log.Close()
		c, _ := Dial(srv.Addr())
		defer c.Close()

		if _, err := Step(c, "A", func() (string, error) { aRuns++; return "a-result", nil }); err != nil {
			t.Fatal(err)
		}
		if _, err := Step(c, "B", func() (int, error) { bRuns++; return 7, nil }); err != nil {
			t.Fatal(err)
		}
		// crash here — C never runs
	}()

	// --- Second process (replay): same /state dir, fresh everything. ---
	func() {
		log, _ := OpenLog(dir)
		srv, err := Listen(filepath.Join(sockDir, "s2.sock"), log)
		if err != nil {
			t.Fatal(err)
		}
		go srv.Serve()
		defer srv.Close()
		defer log.Close()
		c, _ := Dial(srv.Addr())
		defer c.Close()

		a, _ := Step(c, "A", func() (string, error) { aRuns++; return "RECOMPUTED", nil })
		b, _ := Step(c, "B", func() (int, error) { bRuns++; return 999, nil })
		cv, _ := Step(c, "C", func() (bool, error) { cRuns++; return true, nil })

		if a != "a-result" {
			t.Errorf("A should be recalled as a-result, got %q", a)
		}
		if b != 7 {
			t.Errorf("B should be recalled as 7, got %d", b)
		}
		if !cv {
			t.Errorf("C should run and return true")
		}
	}()

	if aRuns != 1 {
		t.Errorf("A must run exactly once across the crash, ran %d", aRuns)
	}
	if bRuns != 1 {
		t.Errorf("B must run exactly once across the crash, ran %d", bRuns)
	}
	if cRuns != 1 {
		t.Errorf("C must run exactly once (only after replay), ran %d", cRuns)
	}
}

func TestErroredStepNotMemoized(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(shortSockDir(t), "e.sock")
	log, _ := OpenLog(dir)
	srv, _ := Listen(sock, log)
	go srv.Serve()
	defer srv.Close()
	c, _ := Dial(sock)
	defer c.Close()

	calls := 0
	flaky := func() (int, error) {
		calls++
		if calls == 1 {
			return 0, os.ErrDeadlineExceeded
		}
		return 5, nil
	}
	if _, err := Step(c, "flaky", flaky); err == nil {
		t.Fatal("first attempt should error")
	}
	// A failed step is NOT memoized, so a retry re-runs and can succeed.
	v, err := Step(c, "flaky", flaky)
	if err != nil || v != 5 {
		t.Fatalf("retry should succeed: v=%d err=%v", v, err)
	}
	if calls != 2 {
		t.Errorf("flaky should have run twice (fail then succeed), ran %d", calls)
	}
}
