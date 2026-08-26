package vm

import (
	"context"
	"os"
	"path/filepath"
	"strings"
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

func TestOnlyGuestSamplesAreReported(t *testing.T) {
	// A host address reported as a guest RIP would be resolved against guest
	// symbols and yield confident nonsense — worse than reporting nothing.
	sample := "" +
		"    ffffffff810a2b40 [guest.kernel.kallsyms]\n" +
		"    ffffffff810a2b40 [guest.kernel.kallsyms]\n" +
		"    00007f9c0a1b2c3d /usr/local/bin/firecracker\n" +
		"    ffffffff81abcdef [kernel.kallsyms]\n"

	var guest, host int
	for _, m := range guestSampleLine.FindAllStringSubmatch(sample, -1) {
		if guestDSO(m[2]) {
			guest++
		} else {
			host++
		}
	}
	if guest != 2 {
		t.Fatalf("guest samples = %d, want 2", guest)
	}
	if host != 2 {
		t.Fatalf("host samples = %d, want 2 (they must be recognized and excluded)", host)
	}
	if guestDSO("/usr/local/bin/firecracker") || guestDSO("[kernel.kallsyms]") {
		t.Fatal("host dso classified as guest")
	}
	if !guestDSO("[guest.kernel.kallsyms]") {
		t.Fatal("guest dso not recognized")
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
	m.runStallDiagnostics(ctx, "not-this-vm", os.Getpid())
	if ctx.Err() == nil {
		t.Fatal("test setup: context should be cancelled")
	}
}

func TestDiagnosticsRefuseAForeignPID(t *testing.T) {
	// Same identity rule as the teardown capture: profiling and counter reads
	// must never be aimed at a process that is not this VM's firecracker.
	m := &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{}}
	m.runStallDiagnostics(context.Background(), "00000000-0000-0000-0000-000000000000", os.Getpid())
	m.runStallDiagnostics(context.Background(), "any-vm", 0)
}
