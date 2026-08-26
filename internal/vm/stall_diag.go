package vm

// stall_diag.go — diagnostics gathered while a guest is still stuck, rather
// than at teardown (stall_proc.go).
//
// A healthy guest answers in tens of milliseconds, so once a readiness wait
// has run for seconds the outcome is already decided and vmd is simply idle
// until the deadline. Running the probes in that dead window keeps them off
// the reply path entirely and leaves time for ones a teardown path could not
// afford. Everything here is read-only with respect to the VM: nothing
// interferes with a guest that might still recover.

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
	// Healthy restores finish three orders of magnitude faster than this, and
	// no restore has been observed recovering between a couple of seconds and
	// the deadline, so this only fires on a guest that is already lost.
	stallDiagAfter = 5 * time.Second

	stallDiagSettle     = 2 * time.Second
	stallDiagPerfWindow = 3 * time.Second

	// Caps the battery so it can never outlive the readiness window and
	// collide with teardown.
	stallDiagBudget = 20 * time.Second
)

// stallDiagSem bounds concurrent batteries: these run a profiler subprocess
// for seconds, so a burst of stalls must not turn diagnosis into load on a
// host that is already unwell. Saturated attempts are skipped, not queued.
var stallDiagSem = make(chan struct{}, 2)

// armEarlyStallDiagnostics schedules the battery for a guest still unready
// after stallDiagAfter. The returned cancel is safe on every path; on a
// healthy restore it stops a timer that never fired, which is this feature's
// entire cost there.
func (m *Manager) armEarlyStallDiagnostics(vmID string, launchPID int) func() {
	// Cancellation runs through a context, not the timer: Stop cannot recall
	// a callback that already fired, so a restore that becomes ready just
	// after the threshold would otherwise be profiled and logged as stalled —
	// a false specimen in the very data this exists to produce.
	ctx, cancel := context.WithCancel(context.Background())
	timer := time.AfterFunc(stallDiagAfter, func() {
		defer sentrylog.Recover("stall-diag-arm")
		if ctx.Err() != nil {
			return
		}
		select {
		case stallDiagSem <- struct{}{}:
		default:
			m.log.Warn().Str("vm_id", vmID).
				Msg("guest slow to become ready — diagnostics skipped (concurrent batteries saturated)")
			return
		}
		defer func() { <-stallDiagSem }()
		m.runStallDiagnostics(ctx, vmID, m.resolveFCPID(vmID, launchPID))
	})
	return func() {
		timer.Stop()
		cancel()
	}
}

// runStallDiagnostics collects the live-VM evidence and logs it. A probe that
// fails contributes an empty field rather than aborting the rest.
func (m *Manager) runStallDiagnostics(parent context.Context, vmID string, pid int) {
	if pid <= 0 || !pidIsVMFirecracker(pid, vmID) {
		return
	}
	ctx, cancel := context.WithTimeout(parent, stallDiagBudget)
	defer cancel()
	deadline, _ := ctx.Deadline()
	started := time.Now()

	before, kvmDir := readKVMCounters(pid, deadline)
	select {
	case <-time.After(stallDiagSettle):
	case <-ctx.Done():
		return
	}
	after, _ := readKVMCounters(pid, deadline)
	deltas := counterDeltas(before, after)

	guestIPs := sampleGuestIPs(ctx, pid)
	threads, _ := captureProcStateBounded(pid, vmID, nil)
	if threads == nil {
		threads = &procStallState{PID: pid, UffdPending: -1, UffdTotal: -1}
	}

	// The guest may have come up while the battery ran; publishing then would
	// record a healthy restore as a stall.
	if ctx.Err() != nil {
		return
	}

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

// writeStallDiagDump preserves the raw numbers next to the other forensics.
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
// this process. Names carry their vcpu directory as a prefix, since telling
// the spinning vCPU from the halted one is the entire point.
func readKVMCounters(pid int, deadline time.Time) (map[string]int64, string) {
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
			raw, ok := readProcFileBy(filepath.Join(dir, e.Name()), deadline)
			if !ok {
				return // out of budget; report what was gathered
			}
			if n, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64); err == nil {
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

// kvmDebugDirFor finds KVM's debugfs directory for this process. The name is
// "<pid>-<instance>", so matching must include the separator.
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

// alwaysReportCounters are reported even when they did not move. A zero here
// is a finding, not noise: an exit count that stays flat while a vCPU burns
// CPU says the guest is looping without ever leaving guest mode, and a halt
// wakeup that never increments says nothing is being delivered to the halted
// one. Omitting them would make "did not move" indistinguishable from "not
// available".
var alwaysReportCounters = map[string]bool{
	"exits":                true,
	"halt_exits":           true,
	"halt_wakeup":          true,
	"halt_successful_poll": true,
	"halt_attempted_poll":  true,
	"irq_injections":       true,
	"irq_window_exits":     true,
	"nmi_injections":       true,
	"mmio_exits":           true,
	"signal_exits":         true,
	"insn_emulation":       true,
	"request_irq_exits":    true,
	"guest_mode":           true,
}

// counterDeltas reports counters that moved, plus the allowlist above whether
// they moved or not. Dropping the hundreds of remaining static counters is
// what keeps the result readable.
func counterDeltas(before, after map[string]int64) map[string]int64 {
	deltas := map[string]int64{}
	for k, a := range after {
		b, ok := before[k]
		if !ok {
			continue
		}
		name := k
		if i := strings.LastIndex(k, "/"); i >= 0 {
			name = k[i+1:]
		}
		if a != b || alwaysReportCounters[name] {
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

// guestSampleLine matches a perf script line of the form "<ip> <dso>", where
// the dso identifies which address space the sample came from.
var guestSampleLine = regexp.MustCompile(`(?m)^\s*([0-9a-f]{6,16})\s+(\S.*)$`)

// guestDSO reports whether a perf dso field denotes guest address space.
// perf labels guest samples with a guest-specific dso; anything else is a
// host address inside Firecracker or the kernel.
func guestDSO(dso string) bool {
	return strings.Contains(strings.ToLower(dso), "guest")
}

// sampleGuestIPs profiles the stalled VM and returns distinct GUEST
// instruction pointers, most frequent first.
//
// Two things make this trustworthy rather than merely plausible. It records
// through `perf kvm --guest`, which is the interface built for guest
// profiling — plain `perf record` on the pid samples the host side and would
// hand back Firecracker and KVM addresses. And it keeps only samples perf
// attributes to guest address space, so an address is either provably from
// the guest or absent: reporting a host address as a guest RIP would send a
// reader to resolve it against guest symbols and arrive at confident
// nonsense, which is worse than reporting nothing.
//
// Addresses rather than symbols because the shipped guest kernel is stripped;
// resolution happens offline against a kallsyms dump from a live guest of the
// same image.
func sampleGuestIPs(ctx context.Context, pid int) []string {
	tmp, err := os.MkdirTemp("", "stalldiag")
	if err != nil {
		return nil
	}
	defer os.RemoveAll(tmp)
	data := filepath.Join(tmp, "perf.data")

	rec := exec.CommandContext(ctx, "perf", "kvm", "--guest", "record",
		"-p", strconv.Itoa(pid), "-o", data, "--", "sleep",
		strconv.Itoa(int(stallDiagPerfWindow/time.Second)))
	if err := rec.Run(); err != nil {
		return nil
	}
	script := exec.CommandContext(ctx, "perf", "script", "-i", data, "-F", "ip,dso")
	out, err := script.Output()
	if err != nil {
		return nil
	}

	counts := map[string]int{}
	for _, m := range guestSampleLine.FindAllStringSubmatch(string(out), -1) {
		if guestDSO(m[2]) {
			counts[m[1]]++
		}
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
