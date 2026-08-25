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

func TestResolveFCPIDFallsBackToTheRecord(t *testing.T) {
	// Direct spawn returns a real pid at launch; unit supervision returns 0
	// and systemd's MainPID lands on the record asynchronously. Capture must
	// find the process in BOTH shapes or the default path yields no evidence.
	m := &Manager{vms: map[string]*VMInstance{
		"unit-vm": {PID: 4242},
		"no-pid":  {PID: 0},
	}}
	if got := m.resolveFCPID("unit-vm", 99); got != 99 {
		t.Fatalf("launch pid ignored: got %d, want 99", got)
	}
	if got := m.resolveFCPID("unit-vm", 0); got != 4242 {
		t.Fatalf("record pid not used for unit supervision: got %d, want 4242", got)
	}
	if got := m.resolveFCPID("no-pid", 0); got != 0 {
		t.Fatalf("unknown pid must stay 0 (capture skipped), got %d", got)
	}
	if got := m.resolveFCPID("missing", 0); got != 0 {
		t.Fatalf("untracked vm must yield 0, got %d", got)
	}
}

func TestPublishLaunchPIDNeverErasesAResolvedPID(t *testing.T) {
	// Unit supervision returns 0 from the launch while an async resolver
	// publishes the real MainPID. Whichever lands second, the record must end
	// up with the real PID.
	inst := &VMInstance{}
	publishLaunchPID(inst, 0, SupervisionUnit) // launch returns first
	if inst.PID != 0 {
		t.Fatalf("PID = %d, want 0 before resolution", inst.PID)
	}
	inst.PID = 777 // resolver publishes MainPID
	publishLaunchPID(inst, 0, SupervisionUnit)
	if inst.PID != 777 {
		t.Fatalf("late zero erased the resolved PID: got %d, want 777", inst.PID)
	}
	// Direct spawn supplies a real PID at launch and must still win.
	publishLaunchPID(inst, 1234, SupervisionUnit)
	if inst.PID != 1234 {
		t.Fatalf("launch PID not recorded: got %d, want 1234", inst.PID)
	}
	if inst.Supervision != SupervisionUnit {
		t.Fatalf("supervision not recorded: %v", inst.Supervision)
	}
}

func TestLaunchGenerationFencesAStaleResolver(t *testing.T) {
	// A tap-busy retry reuses the instance. Attempt 1's resolver may already
	// hold a MainPID and be descheduled, so clearing the field is not enough:
	// its late write must be dropped, or capture inspects the stopped unit.
	inst := &VMInstance{PID: 555}
	gen1 := currentLaunchGen(inst)

	gen2 := beginLaunchAttempt(inst) // retry starts
	if inst.PID != 0 {
		t.Fatalf("stale PID survived the retry: %d", inst.PID)
	}
	if gen2 == gen1 {
		t.Fatal("a new attempt must open a new generation")
	}
	if publishResolvedPID(inst, gen1, 555) {
		t.Fatal("attempt 1's resolver published into attempt 2's record")
	}
	if inst.PID != 0 {
		t.Fatalf("stale resolver wrote %d", inst.PID)
	}

	// Attempt 2's own resolver is accepted.
	if !publishResolvedPID(inst, gen2, 909) {
		t.Fatal("current attempt's resolver was rejected")
	}
	if inst.PID != 909 {
		t.Fatalf("PID = %d, want 909", inst.PID)
	}
	// A resolver that found nothing never clobbers a known PID.
	if publishResolvedPID(inst, gen2, 0) || inst.PID != 909 {
		t.Fatalf("zero resolution disturbed the record: %d", inst.PID)
	}
}

func TestThreadSummaryPrioritizesTheDiagnosis(t *testing.T) {
	// A 32-vCPU VM has more threads than the summary renders, so ranking —
	// not directory order — must decide what survives truncation.
	var threads []procThread
	for i := 0; i < 40; i++ {
		threads = append(threads, procThread{TID: strconv.Itoa(i), Comm: "fc_vcpu" + strconv.Itoa(i)})
	}
	threads = append(threads,
		procThread{TID: "98", Comm: "fc_vcpu31", Wchan: "handle_userfault"},
		procThread{TID: "99", Comm: "uffd-internal", Stack: []string{"[<0>] poll_schedule_timeout"}},
	)
	got := st(threads).threadSummary()
	if !strings.Contains(got, "uffd-internal") {
		t.Fatalf("uffd handler dropped by truncation: %q", got)
	}
	if !strings.Contains(got, "handle_userfault") {
		t.Fatalf("blocked thread dropped by truncation: %q", got)
	}
	if n := strings.Count(got, "|") + 1; n > maxSummaryThreads {
		t.Fatalf("summary rendered %d threads, cap is %d", n, maxSummaryThreads)
	}
}

func st(threads []procThread) *procStallState { return &procStallState{Threads: threads} }

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

// The launch-path helpers run on every restore attempt, so their cost is a
// hot-path cost. Benchmarked to keep that claim honest rather than assumed.
func BenchmarkLaunchPIDHelpers(b *testing.B) {
	m := &Manager{vms: map[string]*VMInstance{"vm": {}}}
	inst := m.vms["vm"]
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gen := beginLaunchAttempt(inst)
		_ = m.launchGenFor("vm")
		publishLaunchPID(inst, 4242, SupervisionUnit)
		publishResolvedPID(inst, gen, 4242)
	}
}

// captureProcState is the one piece that must run synchronously before
// teardown (the process is about to be killed), so it sits inside the
// readiness-timeout verdict reserve. Benchmarked against the current process
// to keep that budget claim measured rather than asserted.
func BenchmarkCaptureProcState(b *testing.B) {
	pid := os.Getpid()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = captureProcState(pid)
	}
}
