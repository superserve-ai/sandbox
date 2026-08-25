package vm

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestParseUffdCounters(t *testing.T) {
	// Real userfaultfd fdinfo shape.
	fdinfo := "pos:\t0\nflags:\t02000002\nmnt_id:\t15\nino:\t1234\npending:\t3\ntotal:\t4271\nAPI:\taa\nioctls:\t3f\n"
	pending, total := parseUffdCounters(fdinfo)
	if pending != 3 || total != 4271 {
		t.Fatalf("pending=%d total=%d, want 3/4271", pending, total)
	}

	// Absent counters must read as -1, never 0 — "not reported" and "zero
	// unresolved faults" are opposite diagnoses.
	pending, total = parseUffdCounters("pos:\t0\nflags:\t02000002\n")
	if pending != -1 || total != -1 {
		t.Fatalf("absent counters gave %d/%d, want -1/-1", pending, total)
	}
	if p, tt := parseUffdCounters(""); p != -1 || tt != -1 {
		t.Fatalf("empty fdinfo gave %d/%d, want -1/-1", p, tt)
	}
}

func TestCaptureProcStateSelf(t *testing.T) {
	// The live process always has a task dir; stacks may be unreadable
	// (non-root, no CONFIG_STACKTRACE) and that must degrade, not fail.
	st := captureProcState(os.Getpid())
	if st.CaptureError != "" {
		t.Fatalf("self capture errored: %s", st.CaptureError)
	}
	if len(st.Threads) == 0 {
		t.Fatal("no threads captured for the running process")
	}
	if len(st.Threads) > maxStallThreads {
		t.Fatalf("thread cap exceeded: %d", len(st.Threads))
	}
	for _, th := range st.Threads {
		if th.TID == "" {
			t.Fatal("thread captured without a tid")
		}
		if len(th.Stack) > maxStackFramesKept {
			t.Fatalf("stack cap exceeded: %d frames", len(th.Stack))
		}
	}
	// The dump is for humans and must always name the pid.
	if !strings.Contains(st.dump(), "pid: "+strconv.Itoa(os.Getpid())) {
		t.Fatal("dump missing pid header")
	}
}

func TestCaptureProcStateDeadProcess(t *testing.T) {
	// PID 0 never has a /proc entry: a process that died before capture must
	// report the gap rather than panic or fabricate an empty-but-clean state.
	st := captureProcState(0)
	if st.CaptureError == "" {
		t.Fatal("dead process must set CaptureError")
	}
	if len(st.Threads) != 0 {
		t.Fatalf("dead process yielded %d threads", len(st.Threads))
	}
}

func TestReadProcFileCaps(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "big")
	if err := os.WriteFile(p, []byte(strings.Repeat("x", stallProcFileMaxLen*2)), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := len(readProcFile(p)); got != stallProcFileMaxLen {
		t.Fatalf("read %d bytes, want cap %d", got, stallProcFileMaxLen)
	}
	if readProcFile(filepath.Join(dir, "missing")) != "" {
		t.Fatal("missing file must read as empty, not error")
	}
}

func TestThreadSummaryShapesTheVerdict(t *testing.T) {
	st := &procStallState{
		Threads: []procThread{
			{TID: "1", Comm: "fc_vcpu0", Wchan: "userfaultfd_msg_wait", Stack: []string{"[<0>] handle_userfault+0x1a0"}},
			{TID: "2", Comm: "fc_uffd", Wchan: "0", Stack: nil},
		},
	}
	got := st.threadSummary()
	if !strings.Contains(got, "fc_vcpu0@userfaultfd_msg_wait:[<0>] handle_userfault+0x1a0") {
		t.Fatalf("vcpu wait site missing from summary: %q", got)
	}
	// An unavailable wchan renders as "-" so the field never reads as a real
	// wait site named "0".
	if !strings.Contains(got, "fc_uffd@-:") {
		t.Fatalf("empty wchan not normalized: %q", got)
	}
}
