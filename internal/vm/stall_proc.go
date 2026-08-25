package vm

// stall_proc.go — the kernel's view of a Firecracker process that stalled
// during restore. When a guest never becomes ready, the console says only
// that it produced no output; what the process was actually blocked on lives
// in procfs, and dies with the process at teardown. These reads answer the
// question the console cannot: which thread is waiting, and on what.
//
// The uffd fdinfo counters are the discriminator. `pending` counts faults the
// kernel has queued but the handler has not read; `total` counts every
// unresolved fault including ones already read:
//
//	pending > 0, handler mid-copy   → the handler is blocked and not reading
//	pending = 0, total > 0, idle    → a fault was read and then never resolved
//	total = 0                       → the guest is not waiting on memory at all
//
// Everything here is best-effort: a dead process, a hardened kernel, or a
// missing CONFIG_STACKTRACE yields empty fields, never an error path.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/superserve-ai/sandbox/internal/sentrylog"
)

// Bounds so a pathological process cannot turn forensics into a memory or log
// problem. Firecracker runs a handful of threads (api, vmm, vcpus, uffd).
const (
	// Above any supported VM shape: the largest configuration runs 32 vCPU
	// threads plus the api, vmm, uffd handler and watchdog. A cap that cut
	// into that range would drop threads by directory order — including,
	// possibly, the blocked vCPU or the handler this capture exists to find.
	maxStallThreads = 96
	// Threads rendered into the single-line summary; the dump file keeps all
	// of them. Ordered by diagnostic value first, so the cap never hides the
	// interesting ones.
	maxSummaryThreads   = 10
	maxStackFramesKept  = 12
	maxStallFdScan      = 256
	stallProcFileMaxLen = 8 << 10
)

// stallCaptureBudget bounds how long the RESTORE PATH waits for the capture.
//
// The bound is enforced by waiting on a worker rather than by checking a
// clock between reads: os.ReadFile cannot be interrupted, so a single stuck
// procfs read would otherwise blow any pre-check budget and hold the verdict
// reserve — the exact thing this reserve exists to protect. On expiry the
// restore proceeds to teardown and the worker is abandoned; it either
// finishes and logs on its own, or dies with the read. An incomplete capture
// is worth strictly less than a delayed verdict is harmful.
const stallCaptureBudget = 250 * time.Millisecond

// procThread is one thread's kernel-side state at stall time.
type procThread struct {
	TID   string
	Comm  string
	Wchan string
	Stack []string
}

// procStallState is a Firecracker process's kernel state, captured while it
// is still alive. Empty fields mean "unavailable", never "known absent".
type procStallState struct {
	PID          int
	Truncated    bool
	Threads      []procThread
	UffdPending  int64
	UffdTotal    int64
	UffdFdinfo   string
	UffdFound    bool
	CaptureError string
}

// readProcFileBy reads a procfs file only if the budget has not expired.
// This limits how much WORK the capture attempts once it is already over
// time; it cannot bound elapsed time, because an os.ReadFile already in
// flight has no cancellation path. Elapsed time is bounded by the caller
// waiting on captureProcStateBounded. ok=false means the budget stopped this
// read from starting.
func readProcFileBy(path string, deadline time.Time) (string, bool) {
	if !time.Now().Before(deadline) {
		return "", false
	}
	return readProcFile(path), true
}

// readProcFile reads a small procfs file, capped. procfs reads are served
// from kernel memory — no disk I/O, no blocking on the stalled guest.
func readProcFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	if len(b) > stallProcFileMaxLen {
		b = b[:stallProcFileMaxLen]
	}
	return strings.TrimRight(string(b), "\n")
}

// captureProcStateBounded runs the capture on a worker and returns whatever
// it produced within stallCaptureBudget. A nil result means the worker did
// not finish in time: the caller must proceed with teardown regardless, since
// procfs reads offer no cancellation and waiting further would spend the
// verdict reserve on evidence rather than on returning the answer.
//
// The abandoned worker is harmless — it holds no locks and writes only to its
// own state — and if it does complete it still logs, so a slow capture
// degrades to a late one rather than a lost one.
func captureProcStateBounded(pid int, vmID string) (*procStallState, bool) {
	done := make(chan *procStallState, 1) // buffered: an abandoned worker must never block
	go func() {
		defer sentrylog.Recover("stall-proc-capture")
		done <- captureProcState(pid, vmID)
	}()
	select {
	case st := <-done:
		return st, true
	case <-time.After(stallCaptureBudget):
		return nil, false
	}
}

// captureProcState reads the per-thread kernel state and userfaultfd counters
// of a live Firecracker process. MUST be called before teardown: once the
// process is killed, every answer here is gone. Callers on the verdict path
// use captureProcStateBounded — the internal deadline below limits how much
// work is attempted, but only the caller's wait bounds elapsed time.
func captureProcState(pid int, vmID string) *procStallState {
	// -1, not the zero value: `total: 0` is the affirmative verdict "the
	// guest is not waiting on memory at all — look elsewhere", so a counter
	// we never managed to read must never render as that. Unreadable
	// /proc/<pid>/fd, a capped scan, or a File-backend VM all land here.
	st := &procStallState{PID: pid, UffdPending: -1, UffdTotal: -1}
	deadline := time.Now().Add(stallCaptureBudget)
	base := filepath.Join("/proc", strconv.Itoa(pid))
	if _, err := os.Stat(base); err != nil {
		st.CaptureError = "process gone before capture"
		return st
	}
	// A PID is only a name for a process while that process lives. If
	// Firecracker exited during the readiness wait, the kernel is free to
	// hand this number to anything, and capturing it would attribute a
	// stranger's threads and stacks to this VM — worse than no evidence.
	// Firecracker's command line carries the VM id, so the check is exact
	// rather than a guess at "looks like a VMM".
	// pidIsVMFirecracker, not a substring test: a short VM id can appear in
	// an unrelated process's argv, and this must match the firecracker
	// binary plus the exact `--id <vmID>` token.
	if !pidIsVMFirecracker(pid, vmID) {
		st.CaptureError = "pid is no longer this VM's firecracker (exited, or recycled by another process)"
		return st
	}

	entries, err := os.ReadDir(filepath.Join(base, "task"))
	if err != nil {
		st.CaptureError = "task dir unreadable: " + err.Error()
	}
	for i, e := range entries {
		if i >= maxStallThreads || time.Now().After(deadline) {
			// Report what was gathered rather than spend the teardown
			// reserve; the flag keeps a partial capture from reading as a
			// complete one.
			st.Truncated = true
			break
		}
		tdir := filepath.Join(base, "task", e.Name())
		comm, ok := readProcFileBy(filepath.Join(tdir, "comm"), deadline)
		if !ok {
			st.Truncated = true
			break
		}
		wchan, _ := readProcFileBy(filepath.Join(tdir, "wchan"), deadline)
		t := procThread{TID: e.Name(), Comm: comm, Wchan: wchan}
		// The kernel stack is the direct answer to "blocked on what" — a
		// userfaultfd wait, a page-cache read, a poll. Root-only and
		// kernel-config dependent, hence best-effort.
		raw, _ := readProcFileBy(filepath.Join(tdir, "stack"), deadline)
		if raw != "" {
			frames := strings.Split(raw, "\n")
			if len(frames) > maxStackFramesKept {
				frames = frames[:maxStackFramesKept]
			}
			for _, f := range frames {
				t.Stack = append(t.Stack, strings.TrimSpace(f))
			}
		}
		st.Threads = append(st.Threads, t)
	}

	// The fd scan is the other multi-read step and must respect the same
	// bound; the counters are the most valuable single signal, so it runs
	// last and is skipped rather than allowed to overrun.
	if fd, ok := findUffdFD(base, deadline); ok {
		st.UffdFound = true
		st.UffdFdinfo, _ = readProcFileBy(filepath.Join(base, "fdinfo", fd), deadline)
		st.UffdPending, st.UffdTotal = parseUffdCounters(st.UffdFdinfo)
	} else if !time.Now().Before(deadline) {
		st.Truncated = true
	}
	return st
}

// findUffdFD locates the userfaultfd descriptor by its anon-inode link target.
func findUffdFD(procBase string, deadline time.Time) (string, bool) {
	entries, err := os.ReadDir(filepath.Join(procBase, "fd"))
	if err != nil {
		return "", false
	}
	for i, e := range entries {
		if i >= maxStallFdScan || !time.Now().Before(deadline) {
			break
		}
		target, err := os.Readlink(filepath.Join(procBase, "fd", e.Name()))
		if err == nil && strings.Contains(target, "userfaultfd") {
			return e.Name(), true
		}
	}
	return "", false
}

// parseUffdCounters pulls the two unresolved-fault counters out of fdinfo.
// Absent fields read as -1 so "not reported" is distinguishable from zero.
func parseUffdCounters(fdinfo string) (pending, total int64) {
	pending, total = -1, -1
	for _, line := range strings.Split(fdinfo, "\n") {
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(val), 10, 64)
		if err != nil {
			continue
		}
		switch strings.TrimSpace(key) {
		case "pending":
			pending = n
		case "total":
			total = n
		}
	}
	return pending, total
}

// threadSummary renders one compact "comm@wchan:top-frame" token per thread —
// enough to read the verdict off the log line without opening the dump.
func (s *procStallState) threadSummary() string {
	// Rank before truncating: the uffd handler and any thread parked in the
	// kernel are the diagnosis; idle api/vmm threads are filler. Ordering is
	// stable within a rank so repeated captures read consistently.
	ranked := make([]procThread, len(s.Threads))
	copy(ranked, s.Threads)
	sort.SliceStable(ranked, func(i, j int) bool {
		return threadRank(ranked[i]) < threadRank(ranked[j])
	})
	if len(ranked) > maxSummaryThreads {
		ranked = ranked[:maxSummaryThreads]
	}
	parts := make([]string, 0, len(ranked))
	for _, t := range ranked {
		top := ""
		if len(t.Stack) > 0 {
			top = t.Stack[0]
		}
		wchan := t.Wchan
		if wchan == "" || wchan == "0" {
			wchan = "-"
		}
		parts = append(parts, fmt.Sprintf("%s@%s:%s", t.Comm, wchan, top))
	}
	return strings.Join(parts, " | ")
}

// threadRank orders threads by how likely they are to carry the answer:
// the uffd handler first, then anything blocked in the kernel, then the rest.
func threadRank(t procThread) int {
	name := strings.ToLower(t.Comm)
	switch {
	case strings.Contains(name, "uffd"):
		return 0
	case t.Wchan != "" && t.Wchan != "0":
		return 1
	case len(t.Stack) > 0:
		return 2
	default:
		return 3
	}
}

// dump renders the full capture for the quarantine file. Kernel stacks and
// thread names only — no guest memory, no tenant data.
func (s *procStallState) dump() string {
	var b strings.Builder
	fmt.Fprintf(&b, "pid: %d\n", s.PID)
	if s.CaptureError != "" {
		fmt.Fprintf(&b, "capture_error: %s\n", s.CaptureError)
	}
	fmt.Fprintf(&b, "truncated: %v\n", s.Truncated)
	fmt.Fprintf(&b, "uffd_found: %v pending: %d total: %d\n\n", s.UffdFound, s.UffdPending, s.UffdTotal)
	if s.UffdFdinfo != "" {
		fmt.Fprintf(&b, "--- uffd fdinfo ---\n%s\n\n", s.UffdFdinfo)
	}
	for _, t := range s.Threads {
		fmt.Fprintf(&b, "--- tid %s (%s) wchan=%s ---\n", t.TID, t.Comm, t.Wchan)
		for _, f := range t.Stack {
			fmt.Fprintf(&b, "  %s\n", f)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// logStallProcState emits the kernel-side verdict for a stalled guest and
// writes the full capture beside the quarantined console. The log line alone
// is meant to be sufficient: the uffd counters plus each thread's wait site
// separate "handler blocked and not reading" from "fault read and dropped"
// from "not waiting on memory at all".
func (m *Manager) logStallProcState(vmID string, waited time.Duration, st *procStallState, dir string, failedAt time.Time) {
	preserved := ""
	if m.forensicsOK {
		path := filepath.Join(dir, fmt.Sprintf("%d-%s.procstate.txt", failedAt.Unix(), vmID))
		if err := os.WriteFile(path, []byte(st.dump()), 0o600); err == nil {
			preserved = path
		}
	}
	m.log.Warn().Str("vm_id", vmID).
		Int("fc_pid", st.PID).
		Int64("wait_boxd_ms", waited.Milliseconds()).
		Bool("uffd_found", st.UffdFound).
		Int64("uffd_pending", st.UffdPending).
		Int64("uffd_total", st.UffdTotal).
		Int("threads", len(st.Threads)).
		Bool("truncated", st.Truncated).
		Str("thread_state", st.threadSummary()).
		Str("procstate_preserved", preserved).
		Str("capture_error", st.CaptureError).
		Msg("guest not ready — firecracker kernel state at stall")
}

// resolveFCPID returns the Firecracker PID to inspect at stall time.
//
// The launch return value is authoritative only for direct spawn: a
// unit-supervised launch reports 0 and systemd's MainPID reaches the
// instance record asynchronously, so the record is the fallback rather than
// the exception. Both reads are in-memory — no systemd round trip on the
// verdict path. A zero result means the PID is genuinely unknown and proc
// capture is skipped rather than aimed at PID 0.
func (m *Manager) resolveFCPID(vmID string, launchPID int) int {
	if launchPID > 0 {
		return launchPID
	}
	inst := m.trackedInstance(vmID)
	if inst == nil {
		return 0
	}
	inst.mu.RLock()
	defer inst.mu.RUnlock()
	return inst.PID
}

// publishLaunchPID records what the launch learned about the Firecracker
// process without ever un-learning what is already known.
//
// A unit-supervised launch returns 0 and resolves systemd's MainPID on its
// own goroutine, so the resolver can publish the real PID before the
// launching goroutine gets here. Assigning the returned zero unconditionally
// would erase it — leaving the record permanently PID-less for a VM that has
// one, which costs the stall capture its subject and misleads anything else
// reading the field. Zero means "not known yet", never "known to be none".
// beginLaunchAttempt clears the previous attempt's PID and opens a new
// generation, returning it for this attempt's resolver to carry.
//
// Clearing alone is not enough: the prior attempt's resolver may already hold
// a MainPID and simply not have written it yet, so it would repopulate the
// record with a stopped unit's PID moments after the clear. The generation is
// what makes that write droppable. Must run before the launch spawns its own
// resolver.
func beginLaunchAttempt(inst *VMInstance) uint64 {
	inst.mu.Lock()
	defer inst.mu.Unlock()
	inst.PID = 0
	inst.launchGen++
	return inst.launchGen
}

// publishResolvedPID records an asynchronously resolved MainPID, but only if
// the attempt that started the resolver is still the current one.
func publishResolvedPID(inst *VMInstance, gen uint64, pid int) bool {
	if pid <= 0 {
		return false
	}
	inst.mu.Lock()
	defer inst.mu.Unlock()
	if inst.launchGen != gen {
		return false // a later attempt owns this record now
	}
	inst.PID = pid
	return true
}

// currentLaunchGen reads the generation a launch should hand its resolver.
func currentLaunchGen(inst *VMInstance) uint64 {
	inst.mu.RLock()
	defer inst.mu.RUnlock()
	return inst.launchGen
}

func publishLaunchPID(inst *VMInstance, pid int, supervision Supervision) {
	inst.mu.Lock()
	defer inst.mu.Unlock()
	if pid > 0 {
		inst.PID = pid
	}
	inst.Supervision = supervision
}

// launchGenFor returns the tracked instance's current launch generation, or 0
// when the record is gone (a resolver carrying 0 can never match a real
// attempt, so its write is dropped — the safe direction).
func (m *Manager) launchGenFor(vmID string) uint64 {
	inst := m.trackedInstance(vmID)
	if inst == nil {
		return 0
	}
	return currentLaunchGen(inst)
}
