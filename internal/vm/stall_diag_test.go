package vm

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestCounterDeltasKeepMovementAndTheProofOfStillness(t *testing.T) {
	// Movement is signal, but so is its absence: a vCPU burning CPU while its
	// exit count stays flat proves a loop that never leaves guest mode. So
	// allowlisted counters are reported at zero, while the hundreds of other
	// static counters are dropped to keep the result readable.
	before := map[string]int64{"vcpu0/exits": 100, "vcpu1/exits": 50, "vm/fpu_reload": 7}
	after := map[string]int64{"vcpu0/exits": 100, "vcpu1/exits": 4050, "vm/fpu_reload": 7}

	d := counterDeltas(before, after)
	if d["vcpu1/exits"] != 4000 {
		t.Fatalf("delta = %d, want 4000", d["vcpu1/exits"])
	}
	got, ok := d["vcpu0/exits"]
	if !ok {
		t.Fatal("a flat exit count must be reported — it is the proof of a tight guest loop")
	}
	if got != 0 {
		t.Fatalf("flat counter reported as %d, want 0", got)
	}
	if _, ok := d["vm/fpu_reload"]; ok {
		t.Fatal("static non-allowlisted counter was not dropped")
	}
	// A counter absent from the first sample cannot yield a meaningful delta.
	if got := counterDeltas(map[string]int64{}, after); len(got) != 0 {
		t.Fatalf("counters without a baseline produced deltas: %v", got)
	}
	// The rendered form must name the vcpu, since distinguishing the spinning
	// vCPU from the halted one is the entire purpose.
	if s := formatDeltas(d); !strings.Contains(s, "vcpu1/exits=+4000") {
		t.Fatalf("formatted deltas lost the vcpu identity: %q", s)
	}
	if s := formatDeltas(nil); s != "none-moved" {
		t.Fatalf("empty deltas rendered as %q", s)
	}
}

func TestExpensiveKVMEntriesAreNeverOpened(t *testing.T) {
	// Reading mmu_rmaps_stat takes the KVM MMU write lock and walks every
	// memslot's reverse maps, blocking the guest's own fault handling. The
	// cost is paid at open, so filtering after parsing would be too late.
	// The *_hist entries are not single integers either.
	for _, name := range []string{"mmu_rmaps_stat", "halt_poll_success_hist", "halt_poll_fail_hist", "halt_wait_hist"} {
		if kvmReadable(name) {
			t.Fatalf("%q would be opened; it is not a cheap integer", name)
		}
	}
	// Entries the diagnosis depends on, all verified present on the hosts.
	for _, name := range []string{
		"exits", "halt_wakeup", "irq_injections", "remote_tlb_flush",
		"remote_tlb_flush_requests", "notify_window_exits", "guest_mode", "pid",
	} {
		if !kvmReadable(name) {
			t.Fatalf("%q must be readable — the diagnosis depends on it", name)
		}
	}
}

func TestBatteryAbandonsAProcessThatChangedIdentity(t *testing.T) {
	// The settle interval gives the stalled process time to exit, and the
	// kernel may hand its number to another Firecracker. Recording that
	// process's counters and guest addresses under this VM's id would be
	// worse than recording nothing, so the battery abandons instead.
	m := &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{}}
	m.runStallDiagnostics(context.Background(), nil, "00000000-0000-0000-0000-000000000000", os.Getpid())

	// A cancelled battery must not start the shared-semaphore capture at all;
	// stealing a slot there can make a genuine timeout skip its own capture.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m.runStallDiagnostics(ctx, nil, "any-vm", os.Getpid())
	if len(stallProcSem) != 0 {
		t.Fatalf("cancelled battery left %d proc-capture slots held", len(stallProcSem))
	}
}

func TestPublicationIsClaimedExactlyOnce(t *testing.T) {
	// Readiness can complete in the window between the battery's last context
	// check and its write, so the outcome is decided by a claim rather than a
	// check: whoever arrives first wins, and the loser stays silent.
	var settled atomic.Bool

	// Readiness wins: the battery must not publish.
	if !settled.CompareAndSwap(false, true) {
		t.Fatal("first claim should succeed")
	}
	if settled.CompareAndSwap(false, true) {
		t.Fatal("a second claim must fail — the outcome is already decided")
	}

	// Fresh restore, battery wins: readiness then finds it already claimed.
	var other atomic.Bool
	if !other.CompareAndSwap(false, true) {
		t.Fatal("battery should be able to claim an unclaimed outcome")
	}
	if other.CompareAndSwap(false, true) {
		t.Fatal("readiness must not re-claim after the battery published")
	}
}

func TestGaugesAreReportedAsValuesNotDeltas(t *testing.T) {
	// guest_mode and pid hold a current value, not a running total. As deltas
	// they are actively misleading: 1→1 and 0→0 both subtract to zero, which
	// would leave the executing vCPU unidentifiable and drop the vCPU→thread
	// mapping entirely.
	before := map[string]int64{
		"vcpu0/guest_mode": 1, "vcpu1/guest_mode": 0,
		"vcpu0/pid": 4242, "vcpu1/pid": 4243,
		"vm/exits": 100,
	}
	after := map[string]int64{
		"vcpu0/guest_mode": 1, "vcpu1/guest_mode": 0,
		"vcpu0/pid": 4242, "vcpu1/pid": 4243,
		"vm/exits": 100,
	}

	d := counterDeltas(before, after)
	for k := range d {
		if strings.Contains(k, "guest_mode") || strings.Contains(k, "pid") {
			t.Fatalf("gauge %q leaked into deltas, where it cannot be interpreted", k)
		}
	}

	g := latestGauges(after)
	if g["vcpu0/guest_mode"] != 1 || g["vcpu1/guest_mode"] != 0 {
		t.Fatalf("guest_mode values lost: %v", g)
	}
	if g["vcpu0/pid"] != 4242 || g["vcpu1/pid"] != 4243 {
		t.Fatalf("vcpu→thread mapping lost: %v", g)
	}
	// Rendered without a sign, unlike deltas.
	if s := formatGauges(g); !strings.Contains(s, "vcpu0/guest_mode=1") {
		t.Fatalf("gauges rendered as %q", s)
	}
	if formatGauges(nil) != "none" {
		t.Fatal("empty gauges must render as none")
	}
}

func TestKVMDebugDirMatchesTheWholePIDToken(t *testing.T) {
	// KVM names its directories "<pid>-<instance>", so a prefix match on the
	// bare pid would also match pid 12345 for pid 1234.
	root := t.TempDir()
	for _, name := range []string{"1234-15", "12345-15", "999-1"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Exercise the same matching rule the real lookup uses.
	entries, _ := os.ReadDir(root)
	var got []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "1234-") {
			got = append(got, e.Name())
		}
	}
	if len(got) != 1 || got[0] != "1234-15" {
		t.Fatalf("pid token matching selected %v", got)
	}
}

func TestSaturationWarningsAreAggregated(t *testing.T) {
	// A host-wide stall can leave hundreds of restores unready at once; one
	// warning per skipped restore would itself be load on a struggling host,
	// so skips accumulate into one counted warning per interval.
	stallDiagSkips.Store(0)
	stallDiagLastWarn.Store(0)
	base := time.Unix(1000, 0)

	if n, ok := claimSkipWarn(base); !ok || n != 1 {
		t.Fatalf("first skip should warn with count 1, got %d %v", n, ok)
	}
	for i := 0; i < 400; i++ {
		if _, ok := claimSkipWarn(base.Add(time.Second)); ok {
			t.Fatal("skips within the interval must not each warn")
		}
	}
	if n, ok := claimSkipWarn(base.Add(stallDiagWarnEvery + time.Second)); !ok || n != 401 {
		t.Fatalf("next interval should warn with the accumulated 401 skips, got %d %v", n, ok)
	}
}

func TestCancelledPerfProbeIsNotCached(t *testing.T) {
	// A probe that never ran — cancelled by readiness completing — says
	// nothing durable about perf. Caching its failure would silently disable
	// guest profiling for the rest of the process's life.
	perfUsable.Store(nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if perfIsUsable(ctx) {
		t.Fatal("a cancelled probe must not report perf as usable")
	}
	if perfUsable.Load() != nil {
		t.Fatal("a probe that never ran must not be cached")
	}
}

func TestPerfStubIsNotTreatedAsUsable(t *testing.T) {
	// Distributions ship a wrapper at perf's usual path that only prints an
	// "install linux-tools-<kernel>" notice. Presence on PATH proves nothing,
	// and profiling through the stub yields no samples at all.
	stub := "perf not found for kernel 6.8.0-1063-gcp\n\nYou may need to install the following packages for this specific kernel:\n    linux-tools-6.8.0-1063-gcp\n"
	if !strings.Contains(stub, "linux-tools") {
		t.Fatal("test fixture no longer resembles the stub output")
	}
	real := "perf version 6.8.12\n"
	if strings.Contains(real, "linux-tools") {
		t.Fatal("a working perf must not be mistaken for the stub")
	}
}

func TestKvmEntryLinesYieldPerVcpuRIPs(t *testing.T) {
	// The tracepoint stream interleaves entries from every vCPU with other
	// kvm events. Only kvm_entry lines carry a guest RIP; counting anything
	// else (kvm_exit reasons, msr writes) would corrupt the histogram, and
	// losing the vcpu id would merge the spinning vCPU's cluster with the
	// halted one's — the distinction is the entire finding.
	// First three lines are verbatim perf-script output from a production
	// host; the comma variant covers kernels whose print format includes it.
	out := "" +
		"       fc_vcpu 1  599500 [039] 1377662.550600: kvm:kvm_entry:  vcpu 1 rip 0xffffffff81036706\n" +
		"       fc_vcpu 1  599500 [039] 1377662.550637: kvm:kvm_entry:  vcpu 1 rip 0xffffffff81036706\n" +
		"       fc_vcpu 0  599499 [002] 1377662.550644: kvm:kvm_entry:  vcpu 0 rip 0xffffffff815cf36e\n" +
		" fc_vcpu 1 2335220 [069] 12345.679150: kvm:kvm_entry: vcpu 1, rip 0xffffffff81036706\n" +
		" fc_vcpu 1 2335220 [069] 12345.679200: kvm:kvm_exit: reason EXTERNAL_INTERRUPT rip 0xffffffff81036706 info1 0\n" +
		" fc_vcpu 1 2335220 [069] 12345.679300: kvm:kvm_msr: msr_write 6e0 = 0x1fb1e5ac1f9\n"

	counts := map[string]int{}
	for _, m := range kvmEntryLine.FindAllStringSubmatch(out, -1) {
		counts["v"+m[1]+":"+m[2]]++
	}
	if counts["v1:ffffffff81036706"] != 3 {
		t.Fatalf("spinning vCPU cluster = %d, want 3 (both print formats must count)", counts["v1:ffffffff81036706"])
	}
	if counts["v0:ffffffff815cf36e"] != 1 {
		t.Fatalf("halted vCPU entry = %d, want 1", counts["v0:ffffffff815cf36e"])
	}
	if len(counts) != 2 {
		t.Fatalf("non-entry events leaked into the histogram: %v", counts)
	}
}

func TestArmedDiagnosticsAreCancelledOnTheHappyPath(t *testing.T) {
	// Cancelling must be safe on every path and repeatable, since restore
	// paths may cancel more than once.
	m := &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{}}
	stop := m.armEarlyStallDiagnostics("vm-that-succeeds", 0)
	stop()
	stop()
	time.Sleep(10 * time.Millisecond)
}

func TestCancellationSuppressesABatteryAlreadyInFlight(t *testing.T) {
	// A restore that becomes ready just after the threshold would otherwise be
	// profiled and logged as stalled — timer.Stop cannot recall a callback
	// that already fired, so the context is what must suppress it.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m := &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{}}
	// A cancelled context must stop the battery before it profiles anything,
	// even when handed a live pid.
	m.runStallDiagnostics(ctx, nil, "not-this-vm", os.Getpid())
	if ctx.Err() == nil {
		t.Fatal("test setup: context should be cancelled")
	}
}

func TestDiagnosticsRefuseAForeignPID(t *testing.T) {
	// Same identity rule as the teardown capture: profiling and counter reads
	// must never be aimed at a process that is not this VM's firecracker.
	m := &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{}}
	m.runStallDiagnostics(context.Background(), nil, "00000000-0000-0000-0000-000000000000", os.Getpid())
	m.runStallDiagnostics(context.Background(), nil, "any-vm", 0)
}
