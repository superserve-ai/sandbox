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
	"strconv"
	"strings"
	"time"
)

// Bounds so a pathological process cannot turn forensics into a memory or log
// problem. Firecracker runs a handful of threads (api, vmm, vcpus, uffd).
const (
	maxStallThreads     = 24
	maxStackFramesKept  = 12
	maxStallFdScan      = 256
	stallProcFileMaxLen = 8 << 10
)

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
	Threads      []procThread
	UffdPending  int64
	UffdTotal    int64
	UffdFdinfo   string
	UffdFound    bool
	CaptureError string
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

// captureProcState reads the per-thread kernel state and userfaultfd counters
// of a live Firecracker process. MUST be called before teardown: once the
// process is killed, every answer here is gone.
func captureProcState(pid int) *procStallState {
	st := &procStallState{PID: pid}
	base := filepath.Join("/proc", strconv.Itoa(pid))
	if _, err := os.Stat(base); err != nil {
		st.CaptureError = "process gone before capture"
		return st
	}

	entries, err := os.ReadDir(filepath.Join(base, "task"))
	if err != nil {
		st.CaptureError = "task dir unreadable: " + err.Error()
	}
	for i, e := range entries {
		if i >= maxStallThreads {
			break
		}
		tdir := filepath.Join(base, "task", e.Name())
		t := procThread{
			TID:   e.Name(),
			Comm:  readProcFile(filepath.Join(tdir, "comm")),
			Wchan: readProcFile(filepath.Join(tdir, "wchan")),
		}
		// The kernel stack is the direct answer to "blocked on what" — a
		// userfaultfd wait, a page-cache read, a poll. Root-only and
		// kernel-config dependent, hence best-effort.
		if raw := readProcFile(filepath.Join(tdir, "stack")); raw != "" {
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

	if fd, ok := findUffdFD(base); ok {
		st.UffdFound = true
		st.UffdFdinfo = readProcFile(filepath.Join(base, "fdinfo", fd))
		st.UffdPending, st.UffdTotal = parseUffdCounters(st.UffdFdinfo)
	}
	return st
}

// findUffdFD locates the userfaultfd descriptor by its anon-inode link target.
func findUffdFD(procBase string) (string, bool) {
	entries, err := os.ReadDir(filepath.Join(procBase, "fd"))
	if err != nil {
		return "", false
	}
	for i, e := range entries {
		if i >= maxStallFdScan {
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
	parts := make([]string, 0, len(s.Threads))
	for _, t := range s.Threads {
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

// dump renders the full capture for the quarantine file. Kernel stacks and
// thread names only — no guest memory, no tenant data.
func (s *procStallState) dump() string {
	var b strings.Builder
	fmt.Fprintf(&b, "pid: %d\n", s.PID)
	if s.CaptureError != "" {
		fmt.Fprintf(&b, "capture_error: %s\n", s.CaptureError)
	}
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
func publishLaunchPID(inst *VMInstance, pid int, supervision Supervision) {
	inst.mu.Lock()
	defer inst.mu.Unlock()
	if pid > 0 {
		inst.PID = pid
	}
	inst.Supervision = supervision
}
