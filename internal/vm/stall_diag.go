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
	"sync/atomic"
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

	// kvm_entry fires per VM entry — a few thousand per second on a spinning
	// vCPU — so the size cap bounds the recording even if a guest exits far
	// more often than any observed stall.
	stallDiagPerfMaxSize = "32M"

	// Caps the battery so it can never outlive the readiness window and
	// collide with teardown.
	stallDiagBudget = 20 * time.Second
)

// stallDiagSem bounds concurrent batteries: these run a profiler subprocess
// for seconds, so a burst of stalls must not turn diagnosis into load on a
// host that is already unwell. Saturated attempts are skipped, not queued.
var stallDiagSem = make(chan struct{}, 2)

// A host-wide stall can leave hundreds of restores unready at once, and one
// warning per skipped restore would itself become load on a struggling host.
// Skips are counted and reported as one aggregate warning per interval.
var (
	stallDiagSkips    atomic.Int64
	stallDiagLastWarn atomic.Int64
)

const stallDiagWarnEvery = 30 * time.Second

// claimSkipWarn records one saturated skip and reports whether this caller
// should emit the aggregate warning, returning the skips it covers.
func claimSkipWarn(now time.Time) (int64, bool) {
	stallDiagSkips.Add(1)
	last := stallDiagLastWarn.Load()
	if now.UnixNano()-last < int64(stallDiagWarnEvery) ||
		!stallDiagLastWarn.CompareAndSwap(last, now.UnixNano()) {
		return 0, false
	}
	return stallDiagSkips.Swap(0), true
}

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
	// settled decides, exactly once, whether this restore is published as a
	// stall. Checking the context before writing is not enough: readiness can
	// complete in the window between that check and the write, and the
	// callback would still record a healthy restore as stalled. Whichever of
	// the two arrives first claims the outcome.
	var settled atomic.Bool
	timer := time.AfterFunc(stallDiagAfter, func() {
		defer sentrylog.Recover("stall-diag-arm")
		if ctx.Err() != nil {
			return
		}
		select {
		case stallDiagSem <- struct{}{}:
		default:
			// vm_id is a sample, not the full set; skipped carries the count.
			if n, ok := claimSkipWarn(time.Now()); ok {
				m.log.Warn().Int64("skipped", n).Str("vm_id", vmID).
					Msg("guests slow to become ready — diagnostics skipped (concurrent batteries saturated)")
			}
			return
		}
		defer func() { <-stallDiagSem }()
		m.runStallDiagnostics(ctx, &settled, vmID, m.resolveFCPID(vmID, launchPID))
	})
	return func() {
		timer.Stop()
		// Claim the outcome before cancelling, so a battery about to publish
		// loses the race rather than winning it.
		settled.CompareAndSwap(false, true)
		cancel()
	}
}

// runStallDiagnostics collects the live-VM evidence and logs it. A probe that
// fails contributes an empty field rather than aborting the rest.
func (m *Manager) runStallDiagnostics(parent context.Context, settled *atomic.Bool, vmID string, pid int) {
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
	// Re-check identity after the settle, before anything reads or profiles
	// again. The process may have exited during those seconds and the kernel
	// is free to hand its number to another Firecracker — whose counters and
	// guest addresses would then be recorded under this VM's id. Abandoning
	// the battery is the right trade: no evidence beats wrong evidence.
	if ctx.Err() != nil || !pidIsVMFirecracker(pid, vmID) {
		return
	}
	after, _ := readKVMCounters(pid, deadline)
	deltas := counterDeltas(before, after)

	var guestIPs []string
	if ctx.Err() == nil {
		guestIPs = sampleGuestIPs(ctx, pid)
	}

	// Only after profiling, and only if still wanted: this capture takes a
	// slot in the semaphore the teardown path shares, so starting one for a
	// battery that is already cancelled can make a genuine timeout skip its
	// own capture as saturated.
	threads := &procStallState{PID: pid, UffdPending: -1, UffdTotal: -1}
	if ctx.Err() == nil {
		if st, _ := captureProcStateBounded(pid, vmID, nil); st != nil {
			threads = st
		}
	}

	// The guest may have come up while the battery ran. Claiming the outcome
	// is what makes the decision final: if readiness already claimed it, this
	// restore was healthy and must not be recorded as a stall.
	if settled != nil && !settled.CompareAndSwap(false, true) {
		return
	}

	ev := m.log.Warn().Str("vm_id", vmID).
		Int("fc_pid", pid).
		Dur("stuck_for", time.Since(started)+stallDiagAfter).
		Str("kvm_dir", kvmDir).
		Str("kvm_deltas", formatDeltas(deltas)).
		Str("kvm_gauges", formatGauges(latestGauges(after))).
		Str("guest_ips", strings.Join(guestIPs, ",")).
		Bool("uffd_found", threads.UffdFound).
		Int64("uffd_pending", threads.UffdPending).
		Int64("uffd_total", threads.UffdTotal).
		Str("thread_state", threads.threadSummary())
	ev.Msg("guest still not ready — live diagnostics")

	m.writeStallDiagDump(vmID, pid, deltas, latestGauges(after), guestIPs, threads)
}

// writeStallDiagDump preserves the raw numbers next to the other forensics.
func (m *Manager) writeStallDiagDump(vmID string, pid int, deltas, gauges map[string]int64, guestIPs []string, threads *procStallState) {
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
	fmt.Fprintf(&b, "\n--- kvm gauges (current values) ---\n")
	for _, k := range sortedKeys(gauges) {
		fmt.Fprintf(&b, "  %-32s %d\n", k, gauges[k])
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

// readKVMCounters reads the allowlisted counters KVM exposes for this
// process; see kvmReadable for why the set is explicit.
//
// The useful counters (exits, halt_wakeup, irq_injections, ...) live at the
// VM level and are aggregated across vCPUs; the per-vCPU directories carry
// only a handful of values. That is still enough: a flat VM-wide exit count
// while a vCPU burns CPU proves a loop that never leaves guest mode, and the
// per-vCPU guest_mode and pid entries say which vCPU is executing and map it
// to the thread stacks captured alongside. Names keep their directory as a
// prefix so the two levels stay distinguishable.
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
			if e.IsDir() || !kvmReadable(e.Name()) {
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

// kvmGauges hold a current value rather than a running total, so a delta of
// zero says "unchanged", not "idle" — guest_mode 1→1 and 0→0 are opposite
// findings that subtract to the same number. They are reported as values.
var kvmGauges = map[string]bool{
	"guest_mode":             true,
	"pid":                    true,
	"tsc-offset":             true,
	"tsc-scaling-ratio":      true,
	"lapic_timer_advance_ns": true,
}

// alwaysReportCounters are reported even when they did not move. A zero here
// is a finding, not noise: an exit count that stays flat while a vCPU burns
// CPU says the guest is looping without ever leaving guest mode, and a halt
// wakeup that never increments says nothing is reaching the halted one.
// Omitting them would make "did not move" indistinguishable from "not
// available". The tlb-flush and notify entries speak to whether one vCPU is
// waiting on another to acknowledge an interrupt.
var alwaysReportCounters = map[string]bool{
	"exits":                     true,
	"halt_exits":                true,
	"halt_wakeup":               true,
	"halt_successful_poll":      true,
	"halt_attempted_poll":       true,
	"irq_injections":            true,
	"irq_window_exits":          true,
	"nmi_injections":            true,
	"request_irq_exits":         true,
	"mmio_exits":                true,
	"signal_exits":              true,
	"insn_emulation":            true,
	"remote_tlb_flush":          true,
	"remote_tlb_flush_requests": true,
	"notify_window_exits":       true,
}

// kvmExtraCounters are plain counters reported only when they move.
var kvmExtraCounters = map[string]bool{
	"irq_exits":           true,
	"io_exits":            true,
	"tlb_flush":           true,
	"req_event":           true,
	"blocking":            true,
	"host_state_reload":   true,
	"hypercalls":          true,
	"nmi_window_exits":    true,
	"halt_poll_invalid":   true,
	"insn_emulation_fail": true,
	"preemption_reported": true,
	"preemption_other":    true,
	"nx_lpage_splits":     true,
	"pf_taken":            true,
	"pf_fixed":            true,
	"pf_fast":             true,
	"pf_guest":            true,
	"pf_spurious":         true,
	"pf_emulate":          true,
}

// kvmReadable gates which debugfs entries are OPENED at all.
//
// Not every entry there is a cheap integer. Reading mmu_rmaps_stat takes
// slots_lock and the MMU *write* lock and walks each memslot's reverse maps —
// work proportional to guest memory, performed while blocking the guest's own
// fault handling. Parsing the result and discarding it would be far too late:
// the cost is paid at open. The *_hist entries are likewise not single
// integers. A battery only ever runs against a VM that is already unwell, so
// entries are named explicitly rather than discovered.
func kvmReadable(name string) bool {
	return alwaysReportCounters[name] || kvmGauges[name] || kvmExtraCounters[name]
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
		name := baseName(k)
		if kvmGauges[name] {
			continue // reported as a value; see latestGauges
		}
		if a != b || alwaysReportCounters[name] {
			deltas[k] = a - b
		}
	}
	return deltas
}

// latestGauges returns the current value of each gauge — which vCPU is in
// guest mode, the thread each vCPU runs on, and the clock offsets.
func latestGauges(sample map[string]int64) map[string]int64 {
	out := map[string]int64{}
	for k, v := range sample {
		if kvmGauges[baseName(k)] {
			out[k] = v
		}
	}
	return out
}

func baseName(key string) string {
	if i := strings.LastIndex(key, "/"); i >= 0 {
		return key[i+1:]
	}
	return key
}

func sortedKeys(m map[string]int64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// formatGauges renders current values (no sign), unlike deltas.
func formatGauges(g map[string]int64) string {
	if len(g) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(g))
	for _, k := range sortedKeys(g) {
		parts = append(parts, fmt.Sprintf("%s=%d", k, g[k]))
	}
	return strings.Join(parts, " ")
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

// perfUsable caches whether perf can actually profile. Distributions ship a
// wrapper at the usual path that only prints an "install linux-tools-<kernel>"
// notice, so presence on PATH proves nothing and a stall must not spend a
// subprocess discovering that every time.
var perfUsable atomic.Pointer[bool]

// perfIsUsable derives its probe from the battery's context so cancellation
// reaches the subprocess instead of leaving it to run out its own clock.
func perfIsUsable(parent context.Context) bool {
	if cached := perfUsable.Load(); cached != nil {
		return *cached
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "perf", "--version").CombinedOutput()
	if err != nil {
		// Could not run it at all — cancelled, a fork failure, or a timeout
		// under the very host pressure that accompanies a stall. That says
		// nothing durable about perf, so it is not cached: caching it would
		// silently disable guest profiling for the rest of this process's life.
		return false
	}
	// A command that ran gives a deterministic answer: the distribution stub
	// prints an "install linux-tools-<kernel>" notice instead of profiling.
	// Only the positive verdict is cached — perf can be installed out-of-band
	// under a running daemon, and re-probing a stub costs one cheap
	// subprocess per stall.
	ok := !strings.Contains(string(out), "linux-tools")
	if ok {
		perfUsable.Store(&ok)
	}
	return ok
}

// kvmEntryLine matches one perf-script kvm:kvm_entry event, capturing which
// vCPU entered guest mode and the guest RIP it entered at. The comma between
// the fields is optional: the tracepoint's print format differs across kernel
// versions ("vcpu 0 rip 0x..." vs "vcpu 0, rip 0x...").
var kvmEntryLine = regexp.MustCompile(`kvm_entry:\s+vcpu (\d+),?\s+rip 0x([0-9a-f]+)`)

// sampleGuestIPs records where the guest is executing and returns distinct
// per-vCPU guest instruction pointers, most frequent first, each rendered as
// "v<cpu>:<rip>:<count>".
//
// It reads the kvm:kvm_entry tracepoint rather than sampling with the PMU:
// KVM logs the guest RIP on every VM entry, entirely host-side, so this works
// where guest PMU sampling is not virtualized and `perf kvm --guest record`
// returns zero samples. A stalled vCPU still enters thousands of times a
// second — the host timer tick alone forces exits — so the address it spins
// at clusters sharply, and the halted vCPU's wake/halt cycle shows up as a
// separate, sparser cluster under its own vcpu id.
//
// Addresses rather than symbols because the shipped guest kernel is stripped;
// resolution happens offline against a kallsyms dump from a live guest of the
// same image.
func sampleGuestIPs(ctx context.Context, pid int) []string {
	if !perfIsUsable(ctx) {
		return nil
	}
	tmp, err := os.MkdirTemp("", "stalldiag")
	if err != nil {
		return nil
	}
	defer os.RemoveAll(tmp)
	data := filepath.Join(tmp, "perf.data")
	rec := exec.CommandContext(ctx, "perf", "record", "-e", "kvm:kvm_entry",
		"--max-size", stallDiagPerfMaxSize,
		"-p", strconv.Itoa(pid), "-o", data, "--", "sleep",
		strconv.Itoa(int(stallDiagPerfWindow/time.Second)))
	if err := rec.Run(); err != nil {
		return nil
	}
	script := exec.CommandContext(ctx, "perf", "script", "-i", data)
	out, err := script.Output()
	if err != nil {
		return nil
	}

	counts := map[string]int{}
	for _, m := range kvmEntryLine.FindAllStringSubmatch(string(out), -1) {
		counts["v"+m[1]+":"+m[2]]++
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
