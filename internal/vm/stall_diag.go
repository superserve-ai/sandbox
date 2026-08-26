package vm

// stall_diag.go — diagnostics gathered WHILE a guest is still stuck, rather
// than at the moment it is killed.
//
// The teardown capture (stall_proc.go) answered where the stall is not: with
// the memory handler idle and zero unresolved faults, the guest itself is the
// thing that is stuck — one vCPU spinning in guest mode, another halted
// waiting for an interrupt. Answering *why* needs signals that only exist
// while the VM runs, and that take longer to collect than a teardown path can
// afford.
//
// The timing is the whole idea. A healthy guest answers in tens of
// milliseconds, so by a few seconds the outcome is already decided — yet vmd
// then sits idle until the readiness deadline. Firing diagnostics into that
// dead time costs the request nothing (it is not on the reply path at all)
// and buys the better part of half a minute to work with, which is what makes
// the slower, more decisive probes possible:
//
//   - KVM counters sampled twice: whether the spinning vCPU is exiting at all,
//     and whether the halted one is being woken. A flat exit count means a
//     tight guest loop; a flat halt_wakeup means nothing is arriving.
//   - guest instruction pointers: which code the guest is actually looping in.
//   - thread stacks re-read over time: whether the state is frozen or moving.
//
// Everything here is read-only with respect to the VM. Nothing interferes
// with a guest that might still recover.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/superserve-ai/sandbox/internal/sentrylog"
)

const (
	// stallDiagAfter is how long a readiness wait must run before the guest
	// is treated as stuck. Healthy restores finish about three orders of
	// magnitude faster, and nothing has ever been observed recovering between
	// a couple of seconds and the deadline, so this only ever fires on a
	// guest that is already lost.
	stallDiagAfter = 5 * time.Second

	// stallDiagSettle separates the two counter samples. Long enough that a
	// slow-moving counter still shows movement, short enough to leave the
	// rest of the window for the profile.
	stallDiagSettle = 2 * time.Second

	// stallDiagPerfWindow is how long the guest is profiled for instruction
	// pointers. It runs inside the readiness window with room to spare.
	stallDiagPerfWindow = 3 * time.Second

	// stallDiagBudget caps the whole battery so it can never outlive the
	// readiness window and collide with teardown.
	stallDiagBudget = 20 * time.Second
)

// stallDiagSem bounds concurrent diagnostic batteries. These are heavier than
// the teardown capture — a profiler subprocess and several seconds of
// sampling — so a burst of stalls must not turn diagnosis into load on a host
// that is already unwell. Saturated attempts are skipped, not queued.
var stallDiagSem = make(chan struct{}, 2)

// armEarlyStallDiagnostics schedules the battery to run if the guest is still
// unready after stallDiagAfter. The returned func cancels it and is safe to
// call on every path — on a healthy restore it stops a timer that never fired,
// which is the entire cost of this feature on the happy path.
func (m *Manager) armEarlyStallDiagnostics(vmID string, launchPID int) func() {
	timer := time.AfterFunc(stallDiagAfter, func() {
		defer sentrylog.Recover("stall-diag-arm")
		select {
		case stallDiagSem <- struct{}{}:
		default:
			m.log.Warn().Str("vm_id", vmID).
				Msg("guest slow to become ready — diagnostics skipped (concurrent batteries saturated)")
			return
		}
		defer func() { <-stallDiagSem }()
		m.runStallDiagnostics(vmID, m.resolveFCPID(vmID, launchPID))
	})
	return func() { timer.Stop() }
}

// runStallDiagnostics collects the live-VM evidence and logs it. Best-effort
// throughout: a probe that fails contributes an empty field rather than
// aborting the rest, because a partial answer still narrows the question.
func (m *Manager) runStallDiagnostics(vmID string, pid int) {
	if pid <= 0 || !pidIsVMFirecracker(pid, vmID) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), stallDiagBudget)
	defer cancel()
	started := time.Now()

	before, kvmDir := readKVMCounters(pid)
	select {
	case <-time.After(stallDiagSettle):
	case <-ctx.Done():
		return
	}
	after, _ := readKVMCounters(pid)
	deltas := counterDeltas(before, after)

	guestIPs := sampleGuestIPs(ctx, pid)
	threads := captureProcState(pid, vmID)

	ev := m.log.Warn().Str("vm_id", vmID).
		Int("fc_pid", pid).
		Dur("stuck_for", time.Since(started)+stallDiagAfter).
		Str("kvm_dir", kvmDir).
		Str("kvm_deltas", formatDeltas(deltas)).
		Str("guest_ips", strings.Join(guestIPs, ",")).
		Bool("uffd_found", threads.UffdFound).
		Int64("uffd_pending", threads.UffdPending).
		Int64("uffd_total", threads.UffdTotal).
		Str("thread_state", threads.threadSummary())
	ev.Msg("guest still not ready — live diagnostics")

	m.writeStallDiagDump(vmID, pid, deltas, guestIPs, threads)
}

// writeStallDiagDump preserves the full battery next to the other forensics
// so a later reader has the raw numbers, not just the summary line.
func (m *Manager) writeStallDiagDump(vmID string, pid int, deltas map[string]int64, guestIPs []string, threads *procStallState) {
	if !m.forensicsOK {
		return
	}
	dir := filepath.Join(m.cfg.RunDir, stallForensicsDirName)
	path := filepath.Join(dir, fmt.Sprintf("%d-%s.livediag.txt", time.Now().Unix(), vmID))
	var b strings.Builder
	fmt.Fprintf(&b, "vm: %s\npid: %d\n\n--- kvm counter deltas over %s ---\n", vmID, pid, stallDiagSettle)
	for _, k := range sortedKeys(deltas) {
		fmt.Fprintf(&b, "  %-32s %d\n", k, deltas[k])
	}
	fmt.Fprintf(&b, "\n--- guest instruction pointers ---\n")
	for _, ip := range guestIPs {
		fmt.Fprintf(&b, "  %s\n", ip)
	}
	fmt.Fprintf(&b, "\n--- threads ---\n%s", threads.dump())
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err == nil {
		pruneOldest(dir, stallForensicsKeep)
	}
}

// readKVMCounters reads every per-VM and per-vCPU counter KVM exposes for
// this process. Names are prefixed by their vcpu directory so a spinning and
// a halted vCPU stay distinguishable — which is the entire point.
func readKVMCounters(pid int) (map[string]int64, string) {
	out := map[string]int64{}
	base, err := kvmDebugDirFor(pid)
	if err != nil {
		return out, ""
	}
	readInto := func(dir, prefix string) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				continue
			}
			if n, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64); err == nil {
				out[prefix+e.Name()] = n
			}
		}
	}
	readInto(base, "vm/")
	if entries, err := os.ReadDir(base); err == nil {
		for _, e := range entries {
			if e.IsDir() && strings.HasPrefix(e.Name(), "vcpu") {
				readInto(filepath.Join(base, e.Name()), e.Name()+"/")
			}
		}
	}
	return out, base
}

// kvmDebugDirFor finds the debugfs directory KVM created for this process.
// The name is "<pid>-<instance>", so the pid alone is not a complete key.
func kvmDebugDirFor(pid int) (string, error) {
	root := "/sys/kernel/debug/kvm"
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", err
	}
	want := strconv.Itoa(pid) + "-"
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), want) {
			return filepath.Join(root, e.Name()), nil
		}
	}
	return "", os.ErrNotExist
}

// counterDeltas keeps only counters that MOVED. A stalled VM's interesting
// signal is what is still ticking (or conspicuously not), and dropping the
// hundreds of static counters is what makes the result readable.
func counterDeltas(before, after map[string]int64) map[string]int64 {
	deltas := map[string]int64{}
	for k, a := range after {
		if b, ok := before[k]; ok && a != b {
			deltas[k] = a - b
		}
	}
	return deltas
}

func sortedKeys(m map[string]int64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func formatDeltas(deltas map[string]int64) string {
	if len(deltas) == 0 {
		return "none-moved"
	}
	parts := make([]string, 0, len(deltas))
	for _, k := range sortedKeys(deltas) {
		parts = append(parts, fmt.Sprintf("%s=%+d", k, deltas[k]))
	}
	return strings.Join(parts, " ")
}

// guestIPPattern matches the instruction pointers perf reports for samples
// taken while the CPU was in guest mode.
var guestIPPattern = regexp.MustCompile(`(?m)^\s*([0-9a-f]{6,16})\s`)

// sampleGuestIPs profiles the stalled process and returns the distinct guest
// instruction pointers seen, most frequent first.
//
// Addresses rather than symbols on purpose: the shipped guest kernel is
// stripped, so resolution happens offline against a kallsyms dump from a live
// guest of the same image. Recording raw pointers keeps the host path simple
// and the evidence durable.
func sampleGuestIPs(ctx context.Context, pid int) []string {
	tmp, err := os.MkdirTemp("", "stalldiag")
	if err != nil {
		return nil
	}
	defer os.RemoveAll(tmp)
	data := filepath.Join(tmp, "perf.data")

	rec := exec.CommandContext(ctx, "perf", "record", "-e", "cpu-clock", "-F", "97",
		"--pid", strconv.Itoa(pid), "-o", data, "--", "sleep",
		strconv.Itoa(int(stallDiagPerfWindow/time.Second)))
	if err := rec.Run(); err != nil {
		return nil
	}
	script := exec.CommandContext(ctx, "perf", "script", "-i", data, "-F", "ip")
	out, err := script.Output()
	if err != nil {
		return nil
	}

	counts := map[string]int{}
	for _, m := range guestIPPattern.FindAllStringSubmatch(string(out), -1) {
		counts[m[1]]++
	}
	ips := make([]string, 0, len(counts))
	for ip := range counts {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool {
		if counts[ips[i]] != counts[ips[j]] {
			return counts[ips[i]] > counts[ips[j]]
		}
		return ips[i] < ips[j]
	})
	if len(ips) > 12 {
		ips = ips[:12]
	}
	for i, ip := range ips {
		ips[i] = fmt.Sprintf("%s:%d", ip, counts[ip])
	}
	return ips
}
